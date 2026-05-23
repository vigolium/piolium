/**
 * Balanced mode orchestrator (`/piolium-balanced`).
 *
 * Pipeline (from command-defs/balanced.md):
 *
 *   L1 Intel
 *   → L2 KB / Threat Model
 *   → [L3 SAST + L4 Lite Probe]   (parallel)
 *   → L5 Single Review Chamber + FP check
 *   → L6 PoC
 *   → L6b Finding Finalisation
 *   → L6c Final Report
 *
 * Differences from the full deep pipeline (deliberate, MVP-grade):
 *   - The chamber phase is a single agent run (chamber-synthesizer) doing
 *     inline Ideator + Devil's-Advocate work. We don't yet implement the
 *     orchestrator-managed multi-round debate; the synthesizer's prompt is
 *     long enough to cover both. A future milestone can bolt on a real
 *     debate driver.
 *   - The probe team is two-step: probe-strategist → evidence-harvester.
 *     Reasoner agents are folded into the harvester's prompt for now.
 *   - Per-finding PoC and finalisation phases iterate over `findings/`
 *     directories sequentially under the global cap.
 */

import { existsSync, mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { AgentRuntimeModel } from "../agent-runner.ts";
import { type AgentDefinition, loadAgents } from "../agents.ts";
import {
	type AuditRunState,
	applyPhaseStatus,
	initAudit,
	latestAudit,
	markAuditStatus,
	readAuditState,
} from "../audit-state.ts";
import { runCandidateScanAsync } from "../candidate-scan.ts";
import { consolidateDrafts, findingsDraftDir, listFindingDirs } from "../findings.ts";
import { runReconAsync } from "../recon.ts";
import { Scheduler } from "../scheduler.ts";
import { cleanupConfirmArtifacts } from "./confirm.ts";
import { type PhaseUiHooks, runAgentPhase } from "./phase-runner.ts";

export type BalancedUiHooks = PhaseUiHooks;

export interface RunBalancedOptions {
	cwd: string;
	signal?: AbortSignal;
	ui?: BalancedUiHooks;
	forceFresh?: boolean;
	agentRuntime?: AgentRuntimeModel;
}

export interface RunBalancedResult {
	auditId: string;
	status: "complete" | "failed";
	phases: Record<string, "complete" | "failed" | "skipped">;
}

export const BALANCED_ATTACK_SURFACE_DIR = "piolium/attack-surface";
export const BALANCED_KB_REPORT = `${BALANCED_ATTACK_SURFACE_DIR}/knowledge-base-report.md`;
export const BALANCED_ADVISORY_SUMMARY = `${BALANCED_ATTACK_SURFACE_DIR}/advisory-summary.md`;
export const BALANCED_SAST_REPORT = `${BALANCED_ATTACK_SURFACE_DIR}/source-sink-flows-all-severities.md`;
export const BALANCED_ATTACK_SURFACE_INVENTORY = `${BALANCED_ATTACK_SURFACE_DIR}/manual-attack-surface-inventory.md`;
export const BALANCED_PROBE_SUMMARY = `${BALANCED_ATTACK_SURFACE_DIR}/balanced-probe-summary.md`;
export const BALANCED_CHAMBER_SUMMARY = `${BALANCED_ATTACK_SURFACE_DIR}/balanced-chamber-summary.md`;
export const BALANCED_VERIFICATION_SUMMARY = `${BALANCED_ATTACK_SURFACE_DIR}/balanced-verification-summary.md`;
export const BALANCED_CLEANUP_SUMMARY = `${BALANCED_ATTACK_SURFACE_DIR}/balanced-cleanup-summary.json`;
export const BALANCED_CONSOLIDATION_MANIFEST = `${BALANCED_ATTACK_SURFACE_DIR}/balanced-consolidation-manifest.json`;
const BALANCED_TRANSIENT_PATHS = [
	"piolium/tmp",
	"piolium/probe-workspace",
	"piolium/chamber-workspace",
	"piolium/adversarial-reviews",
	"piolium/bypass-analysis",
	"piolium/codeql-artifacts",
	"piolium/codeql-queries",
	"piolium/semgrep-rules",
	"piolium/agentic-actions-res",
	"piolium/confirm-workspace",
	"piolium/codeql-res",
	"piolium/semgrep-res",
	"piolium/real-env-evidence",
	"piolium/raw",
	"piolium/file-records",
	"piolium/findings-draft",
	"piolium/attack-surface/raw",
	"piolium/attack-pattern-registry.json",
	"piolium/authz-coverage-gaps.md",
	"piolium/merged-results.sarif",
];
const FINAL_REPORT = "piolium/final-audit-report.md";

function exists(cwd: string, rel: string): boolean {
	return existsSync(join(cwd, rel));
}

function gateL1(cwd: string) {
	return () => exists(cwd, BALANCED_ADVISORY_SUMMARY);
}
function gateL2(cwd: string) {
	return () => exists(cwd, BALANCED_KB_REPORT);
}
function gateL3(cwd: string) {
	return () =>
		exists(cwd, BALANCED_SAST_REPORT) || hasDraftPrefix(cwd, "p4-") || hasDraftPrefix(cwd, "q2-");
}
function gateL4(cwd: string) {
	return () => exists(cwd, BALANCED_ATTACK_SURFACE_INVENTORY) && exists(cwd, BALANCED_PROBE_SUMMARY);
}
function gateL5(cwd: string) {
	return () =>
		exists(cwd, BALANCED_CHAMBER_SUMMARY) || hasDraftPrefix(cwd, "p8-") || hasDraftPrefix(cwd, "b5-");
}
function gateL6(cwd: string) {
	return () => listFindingDirs(cwd).some((d) => d.hasPoc) || listFindingDirs(cwd).length === 0;
}
function gateL6b(cwd: string) {
	const dirs = listFindingDirs(cwd);
	return () => dirs.length === 0 || dirs.every((d) => d.hasReport);
}
function gateL6c(cwd: string) {
	return () => exists(cwd, FINAL_REPORT);
}
function gateL7(cwd: string) {
	return () => exists(cwd, BALANCED_VERIFICATION_SUMMARY);
}

function hasDraftPrefix(cwd: string, prefix: string): boolean {
	const dir = findingsDraftDir(cwd);
	if (!existsSync(dir)) return false;
	return readdirSync(dir).some((f) => f.startsWith(prefix) && f.endsWith(".md"));
}

function pickResume(cwd: string, force: boolean): AuditRunState | undefined {
	if (force) return undefined;
	const state = readAuditState(cwd).state;
	const audit = state ? latestAudit(state) : undefined;
	if (!audit) return undefined;
	if (audit.mode !== "balanced") return undefined;
	if (audit.status === "complete") return undefined;
	return audit;
}

function buildL1Task(): string {
	return [
		"You are running Phase L1 (Intel) of /piolium-balanced.",
		"",
		"Goal: gather published security advisories (CVE/GHSA/OSV) and high-level dependency intelligence relevant to this repository.",
		"",
		`Required artifact: write \`${BALANCED_ADVISORY_SUMMARY}\` with sections:`,
		"  ## Repository Identity",
		"  ## Recent Advisories (last 24 months)",
		"  ## Dependency Intelligence",
		"  ## Architecture Hints",
		"  ## Coverage Gaps",
		"",
		"Skip Phase 2 (commit archaeology) — that's a deep-only phase.",
		"Stop after writing the file. Do not promote drafts or move to L2.",
	].join("\n");
}

function buildL2Task(): string {
	return [
		"You are running Phase L2 (Knowledge Base / Threat Model) of /piolium-balanced.",
		"",
		`Required artifact: \`${BALANCED_KB_REPORT}\`. Sections:`,
		"  ## Project Type & Components",
		"  ## Trust Boundaries",
		"  ## Data-Flow Slices (DFD)",
		"  ## Control-Flow Slices (CFD)",
		"  ## Framework Contracts and Hidden Control Channels",
		"  ## Domain Attack Modes (apply security-threat-model and other relevant skills)",
		"  ## Coverage Gaps",
		"",
		"Framework-contract coverage must inventory middleware/proxy/runtime/header assumptions that can affect auth, routing, tenant selection, debug/admin/preview behavior, method/path override, or cache keys.",
		"",
		`Read \`${BALANCED_ADVISORY_SUMMARY}\` if present. Use the security-threat-model skill if available.`,
		"Stop after writing the report. Do not start L3.",
	].join("\n");
}

function buildL3Task(): string {
	return [
		"You are running Phase L3 (SAST) of /piolium-balanced.",
		"",
		"Goal: run the cheapest available static analysis pass. Required artifacts:",
		`  - \`${BALANCED_SAST_REPORT}\` summary`,
		"  - draft findings under `piolium/findings-draft/p4-NNN-<slug>.md`",
		"",
		"Read `piolium/attack-surface/candidates-summary.md` and `piolium/attack-surface/candidates.jsonl` first. Prioritize precise/high-score candidate files, then validate normally.",
		"Prioritize `hidden-control-channel` candidates when they sit near auth, middleware, proxy, routing, tenant, debug/admin, preview, or cache behavior.",
		"If CodeQL/Semgrep are on PATH and skills exist, use them via the codeql/semgrep skills.",
		"If neither is available, fall back to grep+read patterns aimed at: command injection, path traversal, SSRF, broken authn/z, hardcoded secrets, weak crypto.",
		"Cap drafts at 20. Quality over quantity.",
		"Each draft frontmatter MUST include: id (p4-NNN), phase (L3), slug, severity (critical|high|medium|low|info).",
	].join("\n");
}

function buildL4Task(): string {
	return [
		"You are running Phase L4 (Lite Probe Team) of /piolium-balanced.",
		"",
		"This is a SINGLE-TEAM, SINGLE-PASS probe — not the deep multi-team probe.",
		"",
		"Steps you must complete in order, all in one session:",
		`  1. Read \`${BALANCED_KB_REPORT}\`. If absent, fail with a clear note.`,
		"  2. Read `piolium/attack-surface/candidates-summary.md` and pick one or two highest-impact attack-surface slices.",
		`  3. Write \`${BALANCED_ATTACK_SURFACE_INVENTORY}\` with entry points, public routes/URLs, attacker sources, sinks, hidden control channels, middleware/proxy assumptions, and key files.`,
		"  4. Generate hypotheses (act as both backward and contradiction reasoner inline).",
		"  5. Verify hypotheses with `read`/`grep`/`bash` — file:line evidence required.",
		"  6. Write verified hypotheses as drafts to `piolium/findings-draft/l4-NNN-<slug>.md`.",
		`  7. Write \`${BALANCED_PROBE_SUMMARY}\` summarising the probe execution and coverage.`,
		"Transient scratch, if needed: `piolium/tmp/piolium/balanced-probe/`.",
		"",
		"Cap drafts at 10. Each draft frontmatter MUST include id (l4-NNN), phase (L4), slug, severity.",
	].join("\n");
}

function buildL5Task(): string {
	return [
		"You are running Phase L5 (Single Review Chamber + FP Check) of /piolium-balanced.",
		"",
		"There is no separate Ideator / Tracer / Advocate run in balanced mode — you do all of those roles inline.",
		"",
		"Inputs:",
		`  - \`${BALANCED_KB_REPORT}\``,
		`  - \`${BALANCED_ATTACK_SURFACE_INVENTORY}\``,
		`  - \`${BALANCED_SAST_REPORT}\``,
		"  - `piolium/attack-surface/candidates-summary.md`",
		"  - `piolium/findings-draft/p4-*.md` (SAST drafts)",
		"  - `piolium/findings-draft/l4-*.md` (Probe drafts)",
		"",
		"Steps:",
		"  1. Read all draft findings.",
		"  2. For each draft: act as Ideator (challenge it), Devil's-Advocate (try to reject it), and Synthesizer (final verdict).",
		"  3. Do not delete weak drafts. Mark rejected drafts with frontmatter `status: rejected-fp` and `rejection_reason: <short reason>`.",
		"  4. For surviving drafts, copy them to `piolium/findings-draft/p8-NNN-<slug>.md` with frontmatter `status: valid` and severity normalised to one of: critical, high, medium, low, info.",
		`  5. Write the durable chamber summary to \`${BALANCED_CHAMBER_SUMMARY}\`.`,
		"Transient scratch, if needed: `piolium/tmp/piolium/balanced-chamber/`.",
		"",
		"Cap surviving drafts at 12.",
	].join("\n");
}

function buildL6Task(findingDir: string, slug: string): string {
	return [
		"You are running Phase L6 (PoC) for a single finding in /piolium-balanced.",
		"",
		`Finding directory: ${findingDir}`,
		`Slug: ${slug}`,
		"",
		"Steps:",
		"  1. Read `draft.md` in the finding directory.",
		"  2. Build a minimal proof-of-concept demonstrating exploitability.",
		"  3. Write the PoC to `<finding-dir>/poc.{py|sh|js|rb|go}` (pick the most natural language).",
		"  4. Write evidence (commands run, observed output) to `<finding-dir>/evidence/`.",
		"  5. If exploitation requires a runtime that's unavailable, write a 'theoretical PoC' note explaining the chain.",
		"",
		"Stop after the PoC + evidence are written.",
	].join("\n");
}

function buildL6bTask(findingDir: string): string {
	return [
		"You are running Phase L6b (Finding Finalisation / vuln-report) for a single finding.",
		"",
		`Finding directory: ${findingDir}`,
		"",
		"Steps:",
		"  1. Read `draft.md`, `poc.*`, and `evidence/` contents.",
		"  2. Use the `vuln-report` skill if available; otherwise produce a GitHub-advisory-style report.",
		"  3. Write the final report to `<finding-dir>/report.md` — must be > 500 bytes, include Summary, Details, Root Cause, PoC, Impact, Remediation sections.",
		"",
		"Do not modify draft.md.",
	].join("\n");
}

function buildL6cTask(): string {
	return [
		"You are running Phase L6c (Final Report Assembly) of /piolium-balanced.",
		"",
		"Steps:",
		"  1. List every directory under `piolium/findings/`. Each MUST have a `report.md` of >500 bytes — if any are missing, fail with a clear error and DO NOT write the final report.",
		"  2. Compose `piolium/final-audit-report.md` with:",
		"     - Executive Summary",
		"     - Findings by Severity (with links to per-finding report.md)",
		`     - Attack Surface Summary linking \`${BALANCED_ATTACK_SURFACE_DIR}/\` artifacts`,
		"     - Coverage Gaps",
		"     - Methodology Notes",
		"  3. Reference findings by their <id>-<slug> directory name.",
		"",
		"Stop after writing the final report.",
	].join("\n");
}

async function runL3PlusL4Parallel(
	cwd: string,
	audit: AuditRunState,
	staticAnalyzer: AgentDefinition | undefined,
	probeStrategist: AgentDefinition | undefined,
	signal: AbortSignal | undefined,
	ui: BalancedUiHooks | undefined,
	agentRuntime?: AgentRuntimeModel,
): Promise<{ failed: boolean }> {
	const scheduler = new Scheduler({ maxConcurrent: 3, ...(signal ? { signal } : {}) });
	const settled = await Promise.allSettled([
		scheduler.enqueue({
			id: "L3",
			run: (sig) =>
				runAgentPhase({
					cwd,
					audit,
					phaseName: "L3",
					statusKey: "piolium-balanced",
					statusLabel: "● L3 SAST",
					agent: staticAnalyzer,
					missingAgentMessage: "static-analyzer agent missing",
					task: buildL3Task(),
					gate: gateL3(cwd),
					mode: "balanced",
					ui,
					agentRuntime,
					...(sig ? { signal: sig } : {}),
				}),
		}),
		scheduler.enqueue({
			id: "L4",
			run: (sig) =>
				runAgentPhase({
					cwd,
					audit,
					phaseName: "L4",
					statusKey: "piolium-balanced",
					statusLabel: "● L4 lite probe",
					agent: probeStrategist,
					missingAgentMessage: "probe-strategist agent missing",
					task: buildL4Task(),
					gate: gateL4(cwd),
					mode: "balanced",
					ui,
					agentRuntime,
					...(sig ? { signal: sig } : {}),
				}),
		}),
	]);
	scheduler.dispose();
	return { failed: settled.some((s) => s.status === "rejected") };
}

async function runPerFindingPhase(
	cwd: string,
	audit: AuditRunState,
	phaseName: "L6" | "L6b",
	agent: AgentDefinition | undefined,
	taskBuilder: (dir: string, slug: string) => string,
	ui: BalancedUiHooks | undefined,
	signal: AbortSignal | undefined,
	agentRuntime?: AgentRuntimeModel,
): Promise<{ failed: boolean }> {
	if (!agent) {
		await applyPhaseStatus(cwd, audit, phaseName, {
			status: "failed",
			error: `agent missing for ${phaseName}`,
		});
		throw new Error(`agent missing for ${phaseName}`);
	}
	await applyPhaseStatus(cwd, audit, phaseName, { status: "in_progress" });
	const dirs = listFindingDirs(cwd);
	if (dirs.length === 0) {
		await applyPhaseStatus(cwd, audit, phaseName, { status: "skipped" });
		return { failed: false };
	}
	const scheduler = new Scheduler({ maxConcurrent: 3, ...(signal ? { signal } : {}) });
	const results = await Promise.allSettled(
		dirs.map((d) =>
			scheduler.enqueue({
				id: `${phaseName}:${d.id}`,
				run: (sig) =>
					runAgentPhase({
						cwd,
						audit,
						// Use a per-finding sub-phase name so we don't collide with
						// the main phase status. We only update the main phase
						// at the end.
						phaseName: `${phaseName}:${d.id}`,
						statusKey: "piolium-balanced",
						statusLabel: `● ${phaseName} ${d.id}`,
						agent,
						missingAgentMessage: `agent missing for ${phaseName}`,
						task: taskBuilder(d.path, d.slug),
						gate: () =>
							phaseName === "L6"
								? readdirSync(d.path).some((f) => f.startsWith("poc.")) ||
									existsSync(join(d.path, "poc.theoretical.md"))
								: existsSync(join(d.path, "report.md")),
						mode: "balanced",
						ui,
						agentRuntime,
						...(sig ? { signal: sig } : {}),
					}),
			}),
		),
	);
	scheduler.dispose();
	const failed = results.some((r) => r.status === "rejected");
	await applyPhaseStatus(cwd, audit, phaseName, {
		status: failed ? "failed" : "complete",
		...(failed ? { error: `Some per-finding ${phaseName} runs failed.` } : {}),
	});
	return { failed };
}

export interface BalancedCleanupResult {
	summaryPath: string;
	removed: string[];
	missing: string[];
	retained: string[];
}

export function cleanupBalancedTransientArtifacts(cwd: string): BalancedCleanupResult {
	mkdirSync(join(cwd, BALANCED_ATTACK_SURFACE_DIR), { recursive: true });
	const removed: string[] = [];
	const missing: string[] = [];
	for (const rel of BALANCED_TRANSIENT_PATHS) {
		const abs = join(cwd, rel);
		if (!existsSync(abs)) {
			missing.push(rel);
			continue;
		}
		rmSync(abs, { recursive: true, force: true });
		removed.push(rel);
	}
	const result: BalancedCleanupResult = {
		summaryPath: BALANCED_CLEANUP_SUMMARY,
		removed,
		missing,
		retained: [
			"piolium/attack-surface/",
			"piolium/findings/",
			"piolium/final-audit-report.md",
			"piolium/audit-state.json",
		],
	};
	writeFileSync(join(cwd, BALANCED_CLEANUP_SUMMARY), `${JSON.stringify(result, null, "\t")}\n`);
	return result;
}

async function runBalancedVerificationCleanup(
	cwd: string,
	audit: AuditRunState,
	ui: BalancedUiHooks | undefined,
	signal: AbortSignal | undefined,
): Promise<{ failed: boolean }> {
	if (audit.phases.L7?.status === "complete" && gateL7(cwd)()) return { failed: false };
	if (signal?.aborted) throw signal.reason ?? new Error("Aborted");
	ui?.setStatus?.("piolium-balanced", "● L7 verify-cleanup");
	await applyPhaseStatus(cwd, audit, "L7", { status: "in_progress" });
	try {
		mkdirSync(join(cwd, BALANCED_ATTACK_SURFACE_DIR), { recursive: true });
		const dirs = listFindingDirs(cwd);
		const missingReports = dirs.filter((d) => !d.hasReport).map((d) => `${d.id}-${d.slug}`);
		const missingPocs = dirs.filter((d) => !d.hasPoc).map((d) => `${d.id}-${d.slug}`);
		const missingEvidence = dirs.filter((d) => !d.hasEvidence).map((d) => `${d.id}-${d.slug}`);
		const artifacts = [BALANCED_VERIFICATION_SUMMARY];

		if (dirs.length > 0) {
			const confirmCleanup = cleanupConfirmArtifacts(cwd);
			if (confirmCleanup.formatIssues.length > 0) {
				ui?.notify?.(
					`L7 verification completed with ${confirmCleanup.formatIssues.length} final-folder format warning(s).`,
					"warning",
				);
			}
		}
		const cleanup = cleanupBalancedTransientArtifacts(cwd);
		artifacts.push(cleanup.summaryPath);

		writeFileSync(
			join(cwd, BALANCED_VERIFICATION_SUMMARY),
			[
				"# Balanced Verification & Cleanup",
				"",
				`Generated: ${new Date().toISOString()}`,
				"",
				"## Verification",
				"",
				"- Scope: lightweight package verification; live target confirmation remains `/piolium-confirm`.",
				`- Final finding directories: ${dirs.length}`,
				`- Missing report.md: ${missingReports.length > 0 ? missingReports.join(", ") : "none"}`,
				`- Missing PoC artifact: ${missingPocs.length > 0 ? missingPocs.join(", ") : "none"}`,
				`- Missing evidence directory: ${missingEvidence.length > 0 ? missingEvidence.join(", ") : "none"}`,
				"",
				"## Cleanup",
				"",
				`- Removed: ${cleanup.removed.length > 0 ? cleanup.removed.map((p) => `\`${p}\``).join(", ") : "(none)"}`,
				`- Missing: ${cleanup.missing.length > 0 ? cleanup.missing.map((p) => `\`${p}\``).join(", ") : "(none)"}`,
				`- Cleanup summary: \`${cleanup.summaryPath}\``,
				"",
			].join("\n"),
		);
		await applyPhaseStatus(cwd, audit, "L7", {
			status: "complete",
			artifacts,
		});
		return { failed: false };
	} catch (err) {
		await applyPhaseStatus(cwd, audit, "L7", {
			status: "failed",
			error: err instanceof Error ? err.message : String(err),
		});
		return { failed: true };
	} finally {
		ui?.setStatus?.("piolium-balanced", undefined);
	}
}

export async function runBalancedAudit(opts: RunBalancedOptions): Promise<RunBalancedResult> {
	const { cwd, signal, ui } = opts;
	ui?.setStatus?.("piolium-balanced", "● preparing recon");
	const recon = await runReconAsync(cwd, { signal });
	mkdirSync(join(cwd, BALANCED_ATTACK_SURFACE_DIR), { recursive: true });
	ui?.setStatus?.("piolium-balanced", "● scanning candidate files");
	const candidateScan = await runCandidateScanAsync(cwd, { signal });
	ui?.notify?.(
		`Candidate scan: ${candidateScan.candidateCount} match(es) across ${candidateScan.candidateFiles} file(s).`,
		"info",
	);
	let audit = pickResume(cwd, opts.forceFresh ?? false);
	if (!audit) {
		audit = await initAudit(cwd, {
			mode: "balanced",
			...(recon.commit ? { commit: recon.commit } : { commit: null }),
			...(recon.branch ? { branch: recon.branch } : { branch: "nogit" }),
			...(recon.repository ? { repository: recon.repository } : {}),
			history_available: recon.historyAvailable,
			agent_sdk: "pi",
		});
	}

	const { agents } = loadAgents({ cwd });
	const advisoryHunter = agents.get("advisory-hunter");
	const kbBuilder = agents.get("knowledge-base-builder");
	const staticAnalyzer = agents.get("static-analyzer");
	const probeStrategist = agents.get("probe-strategist");
	const chamberSynthesizer = agents.get("chamber-synthesizer");
	const pocBuilder = agents.get("poc-builder");
	const findingReporter = agents.get("finding-reporter");
	const reportAssembler = agents.get("report-assembler");

	let failed = false;

	try {
		// L1
		await runAgentPhase({
			cwd,
			audit,
			phaseName: "L1",
			statusKey: "piolium-balanced",
			statusLabel: "● L1 advisory hunter",
			agent: advisoryHunter,
			missingAgentMessage: "advisory-hunter agent missing",
			task: buildL1Task(),
			gate: gateL1(cwd),
			mode: "balanced",
			ui,
			agentRuntime: opts.agentRuntime,
			...(signal ? { signal } : {}),
		});

		// L2
		await runAgentPhase({
			cwd,
			audit,
			phaseName: "L2",
			statusKey: "piolium-balanced",
			statusLabel: "● L2 knowledge base",
			agent: kbBuilder,
			missingAgentMessage: "knowledge-base-builder agent missing",
			task: buildL2Task(),
			gate: gateL2(cwd),
			mode: "balanced",
			ui,
			agentRuntime: opts.agentRuntime,
			...(signal ? { signal } : {}),
		});

		// L3 + L4 in parallel
		const par = await runL3PlusL4Parallel(
			cwd,
			audit,
			staticAnalyzer,
			probeStrategist,
			signal,
			ui,
			opts.agentRuntime,
		);
		if (par.failed) failed = true;

		// L5 chamber + FP check
		if (!failed) {
			await runAgentPhase({
				cwd,
				audit,
				phaseName: "L5",
				statusKey: "piolium-balanced",
				statusLabel: "● L5 review chamber",
				agent: chamberSynthesizer,
				missingAgentMessage: "chamber-synthesizer agent missing",
				task: buildL5Task(),
				gate: gateL5(cwd),
				mode: "balanced",
				ui,
				agentRuntime: opts.agentRuntime,
				...(signal ? { signal } : {}),
			});

			// Consolidate chamber-survived drafts (p8-*) into severity-prefixed
			// findings/<C|H|M><N>-<slug>/ directories. Drafts at low/info
			// severity are dropped. The manifest is the hand-off to L6 PoC
			// builders.
			const consolidation = consolidateDrafts(cwd, ["p8-"]);
			const manifest = {
				generated_at: new Date().toISOString(),
				source_prefixes: ["p8-"],
				promoted: consolidation.promoted.map((entry) => ({
					id: entry.id,
					slug: entry.slug,
					severity: entry.severity,
					original_id: entry.originalId,
					...(entry.phase ? { phase: entry.phase } : {}),
					source_path: entry.sourcePath,
					finding_dir: entry.findingDir,
				})),
				dropped: consolidation.dropped.map((entry) => ({
					original_id: entry.originalId,
					severity: entry.severity,
					source_path: entry.sourcePath,
					reason: "below severity threshold (low/info)",
				})),
			};
			writeFileSync(
				join(cwd, BALANCED_CONSOLIDATION_MANIFEST),
				`${JSON.stringify(manifest, null, "\t")}\n`,
			);
			ui?.notify?.(
				`L5 promoted ${consolidation.promoted.length} finding(s); dropped ${consolidation.dropped.length} low/info draft(s).`,
				"info",
			);
		}

		// L6 — per-finding PoC
		if (!failed) {
			const r = await runPerFindingPhase(
				cwd,
				audit,
				"L6",
				pocBuilder,
				buildL6Task,
				ui,
				signal,
				opts.agentRuntime,
			);
			if (r.failed) failed = true;
		}

		// L6b — per-finding finalisation (vuln-report)
		if (!failed) {
			const r = await runPerFindingPhase(
				cwd,
				audit,
				"L6b",
				findingReporter,
				(dir) => buildL6bTask(dir),
				ui,
				signal,
				opts.agentRuntime,
			);
			if (r.failed) failed = true;
		}

		// L6c — final report assembly
		if (!failed) {
			await runAgentPhase({
				cwd,
				audit,
				phaseName: "L6c",
				statusKey: "piolium-balanced",
				statusLabel: "● L6c final report",
				agent: reportAssembler,
				missingAgentMessage: "report-assembler agent missing",
				task: buildL6cTask(),
				gate: gateL6c(cwd),
				mode: "balanced",
				ui,
				agentRuntime: opts.agentRuntime,
				...(signal ? { signal } : {}),
			});
		}
		if (!failed) {
			const r = await runBalancedVerificationCleanup(cwd, audit, ui, signal);
			if (r.failed) failed = true;
		}
	} catch {
		failed = true;
	}

	await markAuditStatus(cwd, audit.audit_id, failed ? "failed" : "complete");
	const fresh =
		readAuditState(cwd).state?.audits.find((a) => a.audit_id === audit.audit_id) ?? audit;
	const phases: Record<string, "complete" | "failed" | "skipped"> = {};
	for (const [name, p] of Object.entries(fresh.phases)) {
		if (p.status === "complete" || p.status === "failed" || p.status === "skipped") {
			phases[name] = p.status;
		}
	}
	ui?.notify?.(
		failed ? "Balanced audit failed." : "Balanced audit complete.",
		failed ? "error" : "info",
	);
	return { auditId: audit.audit_id, status: failed ? "failed" : "complete", phases };
}
