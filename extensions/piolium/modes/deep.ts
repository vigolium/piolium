/**
 * Deep mode orchestrator (`/piolium-deep`).
 *
 * Pipeline (from command-defs/deep.md):
 *
 *   01 Intelligence & Dependency Risk (P1)
 *   → 02 Patch History & Bypass Review (P2, skipped when no git)
 *   → 03 Architecture & Threat Model (P3)
 *   → 04 Static Analysis & Triage (P4)
 *   → [05 Authorization & Access Control (P5)
 *      + 06 State Machine & Concurrency (P6)
 *      + 07 Spec, Framework & Parser Gaps (P7)]  (parallel, cap 3)
 *   → 08 Manual Attack Surface Probe (P8)
 *   → 09 Cross-Service Data Flow (P9)
 *   → 10 Adversarial Review Chamber (P10)
 *   → 11 False-Positive Verification (P11)
 *   → 12 Variant Search (P12)
 *   → 13 Proof-of-Concept Construction (P13)
 *   → 14 Finding Report Drafting (P14)
 *   → 15 Final Report Assembly (P15)
 *   → 16 Finding Verification (P16)
 *   → 17 Cleanup (P17)
 *
 * MVP simplifications (deliberate):
 *   - P5 deep probe runs as a single probe-strategist+evidence-harvester
 *     pair instead of N teams. Multi-team planning is deferred.
 *   - P10 chamber phase is one synthesizer-driven session per cluster, with
 *     orchestrator-managed rounds replaced by inline self-debate.
 *   - P13/P14 iterate findings sequentially under the global cap.
 *
 * No-git mode: P2 transitions to `skipped` and the audit notes
 * `history_available: false`. Phases that depend on history (commit
 * archaeology) are bypassed.
 *
 * Single-phase mode: pass `only: ["P5"]` to rerun a specific phase. Its
 * prerequisites must already be `complete` (otherwise the run errors out).
 */

import { existsSync, mkdirSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
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
import { listFindingDirs, promoteDraftsByPrefix } from "../findings.ts";
import { runReconAsync } from "../recon.ts";
import { readPositiveIntEnv } from "../retry.ts";
import { Scheduler } from "../scheduler.ts";
import {
	CONFIRM_AGENT_PHASES,
	CONFIRM_REPORT,
	buildConfirmTask,
	cleanupConfirmArtifacts,
	confirmGateFor,
	ensureConfirmWorkdir,
	findingDirsWithReports,
	renameFalsePositiveFindings,
} from "./confirm.ts";
import { type PhaseUiHooks, runAgentPhase } from "./phase-runner.ts";

export type DeepUiHooks = PhaseUiHooks;

export interface RunDeepOptions {
	cwd: string;
	signal?: AbortSignal;
	ui?: DeepUiHooks;
	forceFresh?: boolean;
	agentRuntime?: AgentRuntimeModel;
	/** Restrict execution to a subset of phase ids (e.g. ["P5"]). */
	only?: string[];
}

export interface RunDeepResult {
	auditId: string;
	status: "complete" | "failed";
	phases: Record<string, "complete" | "failed" | "skipped">;
}

const ATTACK_SURFACE_DIR = "piolium/attack-surface";
const KB_REPORT = `${ATTACK_SURFACE_DIR}/knowledge-base-report.md`;
const ADVISORY_SUMMARY = `${ATTACK_SURFACE_DIR}/advisory-summary.md`;
const PATCH_BYPASS_SUMMARY = `${ATTACK_SURFACE_DIR}/patch-bypass-summary.md`;
const ATTACK_SURFACE_ARCHITECTURE = `${ATTACK_SURFACE_DIR}/architecture-entrypoints.md`;
const SAST_REPORT = `${ATTACK_SURFACE_DIR}/source-sink-flows-all-severities.md`;
const AUTHZ_MATRIX = `${ATTACK_SURFACE_DIR}/public-routes-authz-matrix.md`;
const STATE_CONCURRENCY = `${ATTACK_SURFACE_DIR}/state-concurrency-summary.md`;
const SPEC_GAP = `${ATTACK_SURFACE_DIR}/spec-gap-summary.md`;
const MANUAL_ATTACK_SURFACE = `${ATTACK_SURFACE_DIR}/manual-attack-surface-inventory.md`;
const PROBE_SUMMARY = `${ATTACK_SURFACE_DIR}/deep-probe-summary.md`;
const CROSS_SERVICE = `${ATTACK_SURFACE_DIR}/cross-service-edges.json`;
const CROSS_SERVICE_REPORT = `${ATTACK_SURFACE_DIR}/cross-service-edges.md`;
const CHAMBER_INDEX = "piolium/chamber-workspace/index.md";
const VARIANT_SUMMARY = `${ATTACK_SURFACE_DIR}/variant-summary.md`;
const FINAL_REPORT = "piolium/final-audit-report.md";
const DEEP_CLEANUP_SUMMARY = `${ATTACK_SURFACE_DIR}/deep-cleanup-summary.json`;
const DEEP_TRANSIENT_PATHS = [
	"piolium/tmp",
	"piolium/chamber-workspace",
	"piolium/probe-workspace",
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
const PER_FINDING_MAX_RETRIES = readPositiveIntEnv("PIOLIUM_PER_FINDING_MAX_RETRIES", 10);
const PER_FINDING_ATTEMPT_TIMEOUT_MS = readPositiveIntEnv(
	"PIOLIUM_PER_FINDING_ATTEMPT_TIMEOUT_MS",
	30 * 60 * 1000,
);
const PER_FINDING_BACKOFF_BASE_MS = readPositiveIntEnv("PIOLIUM_PER_FINDING_BACKOFF_BASE_MS", 5000);
const PER_FINDING_BACKOFF_MAX_MS = readPositiveIntEnv(
	"PIOLIUM_PER_FINDING_BACKOFF_MAX_MS",
	120_000,
);

function exists(cwd: string, rel: string): boolean {
	return existsSync(join(cwd, rel));
}

function ensureAttackSurfaceDir(cwd: string): void {
	mkdirSync(join(cwd, ATTACK_SURFACE_DIR), { recursive: true });
}

function findingHasPoc(path: string): boolean {
	try {
		return (
			readdirSync(path).some((f) => f.startsWith("poc.")) ||
			existsSync(join(path, "poc.theoretical.md"))
		);
	} catch {
		return false;
	}
}

function findingHasReport(path: string): boolean {
	try {
		const report = join(path, "report.md");
		return existsSync(report) && statSync(report).size > 500;
	} catch {
		return false;
	}
}

function perFindingGate(phase: "P13" | "P14", path: string): boolean {
	return phase === "P13" ? findingHasPoc(path) : findingHasReport(path);
}

function retryBackoffMs(attempt: number): number {
	const exponent = Math.max(0, attempt - 1);
	const raw = PER_FINDING_BACKOFF_BASE_MS * 2 ** exponent;
	return Math.min(PER_FINDING_BACKOFF_MAX_MS, raw);
}

async function sleep(ms: number, signal: AbortSignal | undefined): Promise<void> {
	if (ms <= 0) return;
	if (signal?.aborted) throw signal.reason ?? new Error("Aborted");
	await new Promise<void>((resolve, reject) => {
		const cleanup = () => {
			clearTimeout(timeout);
			signal?.removeEventListener("abort", onAbort);
		};
		const timeout = setTimeout(() => {
			cleanup();
			resolve();
		}, ms);
		const onAbort = () => {
			cleanup();
			reject(signal?.reason ?? new Error("Aborted"));
		};
		signal?.addEventListener("abort", onAbort, { once: true });
	});
}

function errorMessage(err: unknown): string {
	return err instanceof Error ? err.message : typeof err === "string" ? err : "Unknown error";
}

const PREREQS: Record<string, string[]> = {
	P1: [],
	P2: ["P1"],
	P3: ["P1"],
	P4: ["P3"],
	P5: ["P3"],
	P6: ["P3"],
	P7: ["P3"],
	P8: ["P3", "P4"],
	P9: ["P4", "P8"],
	P10: ["P5", "P6", "P7", "P8", "P9"],
	P11: ["P10"],
	P12: ["P11"],
	P13: ["P12"],
	P14: ["P13"],
	P15: ["P14"],
	P16: ["P15"],
	P17: ["P16"],
};

function pickResume(
	cwd: string,
	force: boolean,
	allowComplete: boolean,
): AuditRunState | undefined {
	if (force) return undefined;
	const state = readAuditState(cwd).state;
	const audit = state ? latestAudit(state) : undefined;
	if (!audit) return undefined;
	if (audit.mode !== "deep") return undefined;
	if (audit.status === "complete" && !allowComplete) return undefined;
	return audit;
}

function shouldRun(name: string, only: string[] | undefined): boolean {
	if (!only) return true;
	return only.includes(name);
}

function ensurePrereqs(audit: AuditRunState, name: string): void {
	const prereqs = PREREQS[name] ?? [];
	for (const prereq of prereqs) {
		const status = audit.phases[prereq]?.status;
		if (status !== "complete" && status !== "skipped") {
			throw new Error(
				`Cannot run ${name}: prerequisite ${prereq} is "${status ?? "missing"}". Resume or rerun upstream phases first.`,
			);
		}
	}
}

function buildTask(phase: string, cwd: string, hasGit: boolean): string {
	switch (phase) {
		case "P1":
			return [
				"You are running Stage 01 (Intelligence & Dependency Risk) of /piolium-deep.",
				`Build \`${ADVISORY_SUMMARY}\` covering CVE/GHSA/OSV advisories, dependency intel, and architecture hints. Use the bash + WebFetch tools (run \`curl\` against advisory APIs if needed; WebSearch will return a fallback message — use bash+curl instead).`,
				`Target repository: ${cwd}.`,
			].join("\n\n");
		case "P2":
			return [
				"You are running Stage 02 (Patch History & Bypass Review) of /piolium-deep.",
				hasGit
					? `Sweep git history for security-relevant commits. Set \`MAX_COMMITS="\${PIOLIUM_COMMIT_SCAN_LIMIT:-500}"\` and \`MAX_AGE="\${PIOLIUM_COMMIT_SCAN_SINCE:-60 days ago}"\`; every \`git log\` must include \`-n "$MAX_COMMITS" --since="$MAX_AGE"\`. For each historical fix, check bypassability today. Write \`${PATCH_BYPASS_SUMMARY}\` with: relevant commits, bypass attempts, conclusions.`
					: `(no-git target — return immediately with a short note in \`${PATCH_BYPASS_SUMMARY}\` saying P2 is skipped.)`,
			].join("\n\n");
		case "P3":
			return [
				"You are running Stage 03 (Architecture & Threat Model) of /piolium-deep.",
				`Build the deep KB at \`${KB_REPORT}\`. Use the security-threat-model skill if available.`,
				"Sections: Project Type, Trust Boundaries, DFD slices, CFD slices, Framework Contracts and Hidden Control Channels, Domain Attack Modes (apply sharp-edges, wooyun-legacy, insecure-defaults, last30days as applicable), Coverage Gaps.",
				`Also write \`${ATTACK_SURFACE_ARCHITECTURE}\` with a reusable inventory of entry points, public routes/URLs if visible, attacker-controlled sources, high-value sinks, and key source files.`,
				"This KB drives every later phase — be thorough.",
			].join("\n\n");
		case "P4":
			return [
				"You are running Stage 04 (Static Analysis & Triage) of /piolium-deep.",
				"Use codeql + semgrep skills if available; otherwise fall back to grep + read.",
				"Read `piolium/attack-surface/candidates-summary.md` and `piolium/attack-surface/candidates.jsonl` first; prioritize precise/high-score candidate files before expanding coverage.",
				"Pay special attention to `hidden-control-channel` candidates: request headers or framework/proxy context that can affect auth, routing, tenant selection, middleware execution, runtime mode, debug/admin/preview behavior, or cache keys.",
				"Required artifacts:",
				`  - \`${SAST_REPORT}\``,
				"  - draft findings `piolium/findings-draft/p4-NNN-<slug>.md`",
				"Record attacker-controlled sources, sinks, and source-to-sink paths in the attack-surface artifact.",
				"Each draft frontmatter MUST include id (p4-NNN), phase (P4), slug, severity.",
				"Cap drafts at 30.",
			].join("\n\n");
		case "P5":
			return [
				"You are running Stage 05 (Authorization & Access Control) of /piolium-deep.",
				`Read \`${KB_REPORT}\` and \`${ATTACK_SURFACE_ARCHITECTURE}\` if present. Build \`${AUTHZ_MATRIX}\` with rows: public route/URL/operation × roles, expected vs actual checks, including middleware/proxy-derived identity and hidden control channels. Mark cells with anomalies as draft findings under \`piolium/findings-draft/p5-NNN-<slug>.md\`.`,
			].join("\n\n");
		case "P6":
			return [
				"You are running Stage 06 (State Machine & Concurrency) of /piolium-deep.",
				`Find race conditions, TOCTOU, atomicity-of-money, double-spend, idempotency gaps. Write \`${STATE_CONCURRENCY}\` and drafts \`piolium/findings-draft/p6-NNN-<slug>.md\`.`,
			].join("\n\n");
		case "P7":
			return [
				"You are running Stage 07 (Specification, Framework Contract & Parser Gaps) of /piolium-deep.",
				`Use spec-to-code-compliance skill if available. Compare implementations against authoritative specs (RFCs, language standards, framework contracts) and hidden control-channel assumptions. Hunt internal/reserved headers, proxy trust headers, middleware ordering, matcher exclusions, rewrites, method/path overrides, runtime-mode differences, and parsing/canonicalization differentials. Write \`${SPEC_GAP}\` and drafts \`piolium/findings-draft/p7-NNN-<slug>.md\`.`,
			].join("\n\n");
		case "P8":
			return [
				"You are running Stage 08 (Manual Attack Surface Probe) of /piolium-deep.",
				"This is a SINGLE-TEAM probe in MVP — no multi-team scheduling.",
				"Steps:",
				`  1. Read \`${KB_REPORT}\`, \`${ATTACK_SURFACE_DIR}/candidates-summary.md\`, plus \`${ATTACK_SURFACE_DIR}/\` artifacts from P3-P7 if present. Pick the highest-impact slices.`,
				`  2. Write \`${MANUAL_ATTACK_SURFACE}\` with public routes/URLs, attacker sources, sinks, source files, hidden control channels, and exploit-relevant paths.`,
				"  3. Generate hypotheses (backward + contradiction reasoning, inline).",
				"  4. Verify with read/grep/bash — file:line evidence required.",
				"  5. Write drafts `piolium/findings-draft/p8-NNN-<slug>.md`.",
				`  6. Write \`${PROBE_SUMMARY}\`.`,
			].join("\n\n");
		case "P9":
			return [
				"You are running Stage 09 (Cross-Service Data Flow) of /piolium-deep.",
				`Read \`${ATTACK_SURFACE_DIR}/\` artifacts before tracing service boundaries.`,
				`If the target is a single-service repo, write \`${CROSS_SERVICE}\` containing \`{"single_service": true}\` and stop.`,
				`Otherwise: trace data flow across service boundaries and produce \`${CROSS_SERVICE}\` (machine-readable) plus \`${CROSS_SERVICE_REPORT}\` (human-readable). Drafts go to \`piolium/findings-draft/p9-NNN-<slug>.md\`.`,
			].join("\n\n");
		case "P10":
			return [
				"You are running Stage 10 (Adversarial Review Chamber) of /piolium-deep.",
				`Read \`${ATTACK_SURFACE_DIR}/\` artifacts as the shared attack-surface index for routes, sources, sinks, and cross-service edges.`,
				"Group draft findings (p4-, p5-, p6-, p7-, p8-, p9-) into clusters by attack class. For each cluster, run an inline chamber:",
				"  - Synthesizer (you) — orchestrator + final verdict",
				"  - Ideator — challenge each finding with attack scenarios (do this inline)",
				"  - Devil's Advocate — try to reject each finding (inline)",
				"Do not delete weak drafts. Mark rejected drafts with frontmatter `status: rejected-fp` and `rejection_reason: <short reason>`.",
				"Survivors get copied to `piolium/findings-draft/p10-NNN-<slug>.md` with frontmatter `status: valid` and normalised severity.",
				"Write per-cluster transcripts under `piolium/chamber-workspace/<cluster-id>/debate.md` and an index at `piolium/chamber-workspace/index.md`.",
			].join("\n\n");
		case "P11":
			return [
				"You are running Stage 11 (False-Positive Verification) of /piolium-deep.",
				"For each draft surviving P10 with severity critical/high, do a COLD verification — re-read the code from scratch with no priors. Confirm or reject. Write `piolium/adversarial-reviews/<id>.md` per verification.",
				"Drafts that fail verification are marked `status: rejected-fp` with a rejection reason and left on disk.",
			].join("\n\n");
		case "P12":
			return [
				"You are running Stage 12 (Variant Search) of /piolium-deep.",
				`For each surviving finding, search the codebase and \`${ATTACK_SURFACE_DIR}/\` for similar routes, sources, sinks, and flow patterns. Use the variant-analysis skill if available. Write new drafts \`piolium/findings-draft/p12-NNN-<slug>.md\` (id namespace p12) for each variant. Write \`${VARIANT_SUMMARY}\`.`,
			].join("\n\n");
		case "P13":
			return [
				"You are running Stage 13 (Proof-of-Concept Construction) of /piolium-deep — this prompt is for a SINGLE finding.",
				"Read draft.md, build a minimal PoC, write `<finding-dir>/poc.{py|sh|js|rb|go}`, evidence to `<finding-dir>/evidence/`. If runtime exploitation isn't possible, write a `<finding-dir>/poc.theoretical.md` explaining the chain.",
			].join("\n\n");
		case "P14":
			return [
				"You are running Stage 14 (Finding Report Drafting) of /piolium-deep — this prompt is for a SINGLE finding.",
				"Use the vuln-report skill if available. Produce `<finding-dir>/report.md` (>500 bytes) with Summary, Details, Root Cause, PoC, Impact, Remediation.",
			].join("\n\n");
		case "P15":
			return [
				"You are running Stage 15 (Final Report Assembly) of /piolium-deep.",
				"Verify every directory under `piolium/findings/` has `report.md` >500 bytes. If any are missing, fail with a clear error.",
				`Compose \`piolium/final-audit-report.md\`: Executive Summary, Findings by Severity (with links), Attack Surface Summary (linking \`${ATTACK_SURFACE_DIR}/\` artifacts), Coverage Gaps, Methodology Notes.`,
			].join("\n\n");
		default:
			return `Phase ${phase} task description not implemented.`;
	}
}

function gateFor(phase: string, cwd: string): () => boolean {
	switch (phase) {
		case "P1":
			return () => exists(cwd, ADVISORY_SUMMARY);
		case "P2":
			return () => exists(cwd, PATCH_BYPASS_SUMMARY);
		case "P3":
			return () => exists(cwd, KB_REPORT) && exists(cwd, ATTACK_SURFACE_ARCHITECTURE);
		case "P4":
			return () => exists(cwd, SAST_REPORT);
		case "P5":
			return () => exists(cwd, AUTHZ_MATRIX);
		case "P6":
			return () => exists(cwd, STATE_CONCURRENCY);
		case "P7":
			return () => exists(cwd, SPEC_GAP);
		case "P8":
			return () => exists(cwd, MANUAL_ATTACK_SURFACE) && exists(cwd, PROBE_SUMMARY);
		case "P9":
			return () => exists(cwd, CROSS_SERVICE);
		case "P10":
			return () => exists(cwd, CHAMBER_INDEX);
		case "P11":
			return () =>
				listFindingDirs(cwd).length === 0 || existsSync(join(cwd, "piolium", "adversarial-reviews"));
		case "P12":
			return () => exists(cwd, VARIANT_SUMMARY);
		case "P13":
			return () => {
				const dirs = listFindingDirs(cwd);
				return dirs.length === 0 || dirs.every((d) => findingHasPoc(d.path));
			};
		case "P14":
			return () => {
				const dirs = listFindingDirs(cwd);
				return dirs.length === 0 || dirs.every((d) => findingHasReport(d.path));
			};
		case "P15":
			return () => exists(cwd, FINAL_REPORT);
		case "P16":
			return () => findingDirsWithReports(cwd).length === 0 || exists(cwd, CONFIRM_REPORT);
		case "P17":
			return () => exists(cwd, DEEP_CLEANUP_SUMMARY);
		default:
			return () => true;
	}
}

interface PhaseSpec {
	name: string;
	agent: AgentDefinition | undefined;
	missingMessage: string;
	statusLabel: string;
}

async function runOne(
	cwd: string,
	audit: AuditRunState,
	spec: PhaseSpec,
	hasGit: boolean,
	signal: AbortSignal | undefined,
	ui: DeepUiHooks | undefined,
	agentRuntime?: AgentRuntimeModel,
): Promise<void> {
	await runAgentPhase({
		cwd,
		audit,
		phaseName: spec.name,
		statusKey: "piolium-deep",
		statusLabel: spec.statusLabel,
		agent: spec.agent,
		missingAgentMessage: spec.missingMessage,
		task: buildTask(spec.name, cwd, hasGit),
		gate: gateFor(spec.name, cwd),
		mode: "deep",
		ui,
		agentRuntime,
		...(signal ? { signal } : {}),
	});
}

async function runFanout3(
	cwd: string,
	audit: AuditRunState,
	specs: PhaseSpec[],
	hasGit: boolean,
	signal: AbortSignal | undefined,
	ui: DeepUiHooks | undefined,
	agentRuntime?: AgentRuntimeModel,
): Promise<{ failed: boolean }> {
	const scheduler = new Scheduler({ maxConcurrent: 3, ...(signal ? { signal } : {}) });
	const settled = await Promise.allSettled(
		specs.map((s) =>
			scheduler.enqueue({
				id: s.name,
				run: (sig) => runOne(cwd, audit, s, hasGit, sig, ui, agentRuntime),
			}),
		),
	);
	scheduler.dispose();
	return { failed: settled.some((r) => r.status === "rejected") };
}

async function runPerFinding(
	cwd: string,
	audit: AuditRunState,
	phase: "P13" | "P14",
	agent: AgentDefinition | undefined,
	signal: AbortSignal | undefined,
	ui: DeepUiHooks | undefined,
	agentRuntime?: AgentRuntimeModel,
): Promise<{ failed: boolean }> {
	if (!agent) {
		await applyPhaseStatus(cwd, audit, phase, {
			status: "failed",
			error: `agent missing for ${phase}`,
		});
		return { failed: true };
	}
	await applyPhaseStatus(cwd, audit, phase, { status: "in_progress" });
	const dirs = listFindingDirs(cwd);
	if (dirs.length === 0) {
		await applyPhaseStatus(cwd, audit, phase, { status: "skipped" });
		return { failed: false };
	}
	const maxAttempts = PER_FINDING_MAX_RETRIES + 1;
	const scheduler = new Scheduler({ maxConcurrent: 3, ...(signal ? { signal } : {}) });
	const settled = await Promise.allSettled(
		dirs.map((d) =>
			scheduler.enqueue({
				id: `${phase}:${d.id}`,
				run: async (sig) => {
					const phaseName = `${phase}:${d.id}`;
					const gate = () => perFindingGate(phase, d.path);
					if (gate()) {
						await applyPhaseStatus(cwd, audit, phaseName, {
							status: "complete",
							attempt: audit.phases[phaseName]?.attempt ?? 0,
							max_attempts: maxAttempts,
							retry_backoff_ms: null,
							next_retry_at: null,
							last_error: null,
						});
						return;
					}

					let lastError = "Unknown error";
					for (let attempt = 1; attempt <= maxAttempts; attempt++) {
						try {
							await applyPhaseStatus(cwd, audit, phaseName, {
								status: "in_progress",
								attempt,
								max_attempts: maxAttempts,
								retry_backoff_ms: null,
								next_retry_at: null,
								error: `Attempt ${attempt}/${maxAttempts} running.`,
							});
							await runAgentPhase({
								cwd,
								audit,
								phaseName,
								statusKey: "piolium-deep",
								statusLabel: `● ${phase} ${d.id} (${attempt}/${maxAttempts})`,
								agent,
								missingAgentMessage: `agent missing for ${phase}`,
								task: `${buildTask(phase, cwd, true)}\n\nFinding directory: ${d.path}\nSlug: ${d.slug}`,
								gate,
								mode: "deep",
								ui,
								agentRuntime,
								timeoutMs: PER_FINDING_ATTEMPT_TIMEOUT_MS,
								maxRetries: 0,
								...(sig ? { signal: sig } : {}),
							});
							return;
						} catch (err) {
							lastError = errorMessage(err);
							if (gate()) {
								await applyPhaseStatus(cwd, audit, phaseName, {
									status: "complete",
									attempt,
									max_attempts: maxAttempts,
									retry_backoff_ms: null,
									next_retry_at: null,
									last_error: null,
								});
								return;
							}

							if (attempt >= maxAttempts) {
								await applyPhaseStatus(cwd, audit, phaseName, {
									status: "failed",
									error: `Failed after ${PER_FINDING_MAX_RETRIES} retries: ${lastError}`,
									attempt,
									max_attempts: maxAttempts,
									retry_backoff_ms: null,
									next_retry_at: null,
									last_error: lastError,
								});
								throw err;
							}

							const backoffMs = retryBackoffMs(attempt);
							const nextRetryAt = new Date(Date.now() + backoffMs).toISOString();
							await applyPhaseStatus(cwd, audit, phaseName, {
								status: "in_progress",
								error: `Attempt ${attempt}/${maxAttempts} failed: ${lastError}. Retrying at ${nextRetryAt}.`,
								attempt,
								max_attempts: maxAttempts,
								retry_backoff_ms: backoffMs,
								next_retry_at: nextRetryAt,
								last_error: lastError,
							});
							await sleep(backoffMs, sig);
						}
					}
				},
			}),
		),
	);
	scheduler.dispose();
	const failed = settled.some((r) => r.status === "rejected");
	await applyPhaseStatus(cwd, audit, phase, {
		status: failed ? "failed" : "complete",
		...(failed ? { error: `Some per-finding ${phase} runs failed.` } : {}),
	});
	return { failed };
}

export interface DeepTransientCleanupResult {
	summaryPath: string;
	removed: string[];
	missing: string[];
	retained: string[];
}

export function cleanupDeepTransientArtifacts(cwd: string): DeepTransientCleanupResult {
	ensureAttackSurfaceDir(cwd);
	const removed: string[] = [];
	const missing: string[] = [];
	for (const rel of DEEP_TRANSIENT_PATHS) {
		const abs = join(cwd, rel);
		if (!existsSync(abs)) {
			missing.push(rel);
			continue;
		}
		rmSync(abs, { recursive: true, force: true });
		removed.push(rel);
	}
	const result: DeepTransientCleanupResult = {
		summaryPath: DEEP_CLEANUP_SUMMARY,
		removed,
		missing,
		retained: [
			"piolium/attack-surface/",
			"piolium/findings/",
			"piolium/final-audit-report.md",
			"piolium/confirmation-report.md",
			"piolium/audit-state.json",
		],
	};
	writeFileSync(join(cwd, DEEP_CLEANUP_SUMMARY), `${JSON.stringify(result, null, "\t")}\n`);
	return result;
}

async function runDeepVerificationCleanup(
	cwd: string,
	audit: AuditRunState,
	agents: ReturnType<typeof loadAgents>["agents"],
	signal: AbortSignal | undefined,
	ui: DeepUiHooks | undefined,
	agentRuntime?: AgentRuntimeModel,
): Promise<{ failed: boolean }> {
	if (audit.phases.P16?.status === "complete" && gateFor("P16", cwd)()) {
		return { failed: false };
	}
	ensureConfirmWorkdir(cwd);
	ui?.setStatus?.("piolium-deep", "● P16 verify");
	await applyPhaseStatus(cwd, audit, "P16", { status: "in_progress" });

	let failed = false;
	const artifacts: string[] = [];

	try {
		const findingReports = findingDirsWithReports(cwd);
		if (findingReports.length === 0) {
			ui?.notify?.("P16 found no finalized findings; verification has nothing to confirm.", "info");
		} else {
			const phaseAgents: Record<
				Exclude<(typeof CONFIRM_AGENT_PHASES)[number], "V1.5">,
				ReturnType<typeof agents.get>
			> = {
				V1: agents.get("env-detective"),
				V2: agents.get("env-detective"),
				V3: agents.get("env-provisioner"),
				V4: agents.get("poc-executor"),
				V5: agents.get("test-mapper"),
				V6: agents.get("confirm-reporter"),
			};

			for (const name of CONFIRM_AGENT_PHASES) {
				// V1.5 (intent cross-check) is a confirm-mode-only annotation phase;
				// deep P16 is a pure live-verification pass and skips it.
				if (name === "V1.5") continue;
				if (name === "V6") {
					const renames = renameFalsePositiveFindings(cwd);
					if (renames.length > 0) {
						ui?.notify?.(
							`Renamed ${renames.length} false-positive finding folder(s) with FP- prefix.`,
							"warning",
						);
					}
				}
				try {
					await runAgentPhase({
						cwd,
						audit,
						phaseName: `P16:${name}`,
						statusKey: "piolium-deep",
						statusLabel: `● P16 ${name}`,
						agent: phaseAgents[name],
						missingAgentMessage: `agent missing for P16 ${name}`,
						task: buildConfirmTask(name, undefined),
						gate: confirmGateFor(name, cwd),
						mode: "confirm",
						ui,
						agentRuntime,
						...(signal ? { signal } : {}),
					});
				} catch (err) {
					failed = true;
					if (name === "V1" || name === "V6") break;
					ui?.notify?.(
						`P16 verification subphase ${name} failed (${errorMessage(err)}); continuing to collect/report remaining evidence.`,
						"warning",
					);
				}
			}

			if (exists(cwd, CONFIRM_REPORT)) artifacts.push(CONFIRM_REPORT);
			const confirmCleanup = cleanupConfirmArtifacts(cwd);
			if (confirmCleanup.formatIssues.length > 0) {
				ui?.notify?.(
					`P16 verification completed with ${confirmCleanup.formatIssues.length} final-folder format warning(s).`,
					"warning",
				);
			}
		}

		await applyPhaseStatus(cwd, audit, "P16", {
			status: failed ? "failed" : "complete",
			artifacts,
			...(failed
				? {
						error:
							"One or more verification subphases failed; confirmation artifacts were still written.",
					}
				: {}),
		});
		return { failed };
	} catch (err) {
		await applyPhaseStatus(cwd, audit, "P16", {
			status: "failed",
			error: errorMessage(err),
			artifacts,
		});
		throw err;
	} finally {
		ui?.setStatus?.("piolium-deep", undefined);
	}
}

async function runDeepCleanupPhase(
	cwd: string,
	audit: AuditRunState,
	signal: AbortSignal | undefined,
	ui: DeepUiHooks | undefined,
): Promise<{ failed: boolean }> {
	if (audit.phases.P17?.status === "complete" && gateFor("P17", cwd)()) {
		return { failed: false };
	}
	if (signal?.aborted) throw signal.reason ?? new Error("Aborted");
	ui?.setStatus?.("piolium-deep", "● P17 cleanup");
	await applyPhaseStatus(cwd, audit, "P17", { status: "in_progress" });
	try {
		const transientCleanup = cleanupDeepTransientArtifacts(cwd);
		await applyPhaseStatus(cwd, audit, "P17", {
			status: "complete",
			artifacts: [transientCleanup.summaryPath],
		});
		return { failed: false };
	} catch (err) {
		await applyPhaseStatus(cwd, audit, "P17", {
			status: "failed",
			error: errorMessage(err),
		});
		return { failed: true };
	} finally {
		ui?.setStatus?.("piolium-deep", undefined);
	}
}

export async function runDeepAudit(opts: RunDeepOptions): Promise<RunDeepResult> {
	const { cwd, signal, ui } = opts;
	ui?.setStatus?.("piolium-deep", "● preparing recon");
	const recon = await runReconAsync(cwd, { signal });
	ensureAttackSurfaceDir(cwd);
	ui?.setStatus?.("piolium-deep", "● scanning candidate files");
	const candidateScan = await runCandidateScanAsync(cwd, { signal });
	ui?.notify?.(
		`Candidate scan: ${candidateScan.candidateCount} match(es) across ${candidateScan.candidateFiles} file(s).`,
		"info",
	);
	let audit = pickResume(cwd, opts.forceFresh ?? false, Boolean(opts.only?.length));
	if (!audit) {
		audit = await initAudit(cwd, {
			mode: "deep",
			...(recon.commit ? { commit: recon.commit } : { commit: null }),
			...(recon.branch ? { branch: recon.branch } : { branch: "nogit" }),
			...(recon.repository ? { repository: recon.repository } : {}),
			history_available: recon.historyAvailable,
			agent_sdk: "pi",
		});
	}

	const { agents } = loadAgents({ cwd });
	const specs: Record<string, PhaseSpec> = {
		P1: {
			name: "P1",
			agent: agents.get("advisory-hunter"),
			missingMessage: "advisory-hunter missing",
			statusLabel: "● P1 intelligence-risk",
		},
		P2: {
			name: "P2",
			agent: agents.get("patch-bypass-checker"),
			missingMessage: "patch-bypass-checker missing",
			statusLabel: "● P2 bypass-review",
		},
		P3: {
			name: "P3",
			agent: agents.get("knowledge-base-builder"),
			missingMessage: "knowledge-base-builder missing",
			statusLabel: "● P3 threat-model",
		},
		P4: {
			name: "P4",
			agent: agents.get("static-analyzer"),
			missingMessage: "static-analyzer missing",
			statusLabel: "● P4 static-triage",
		},
		P5: {
			name: "P5",
			agent: agents.get("authz-auditor"),
			missingMessage: "authz-auditor missing",
			statusLabel: "● P5 access-control",
		},
		P6: {
			name: "P6",
			agent: agents.get("state-concurrency-auditor"),
			missingMessage: "state-concurrency-auditor missing",
			statusLabel: "● P6 state-concurrency",
		},
		P7: {
			name: "P7",
			agent: agents.get("spec-gap-analyst"),
			missingMessage: "spec-gap-analyst missing",
			statusLabel: "● P7 spec-parser",
		},
		P8: {
			name: "P8",
			agent: agents.get("probe-strategist"),
			missingMessage: "probe-strategist missing",
			statusLabel: "● P8 attack-probe",
		},
		P9: {
			name: "P9",
			agent: agents.get("cross-service-auditor"),
			missingMessage: "cross-service-auditor missing",
			statusLabel: "● P9 data-flow",
		},
		P10: {
			name: "P10",
			agent: agents.get("chamber-synthesizer"),
			missingMessage: "chamber-synthesizer missing",
			statusLabel: "● P10 review-chamber",
		},
		P11: {
			name: "P11",
			agent: agents.get("cold-verifier"),
			missingMessage: "cold-verifier missing",
			statusLabel: "● P11 fp-verify",
		},
		P12: {
			name: "P12",
			agent: agents.get("variant-hunter"),
			missingMessage: "variant-hunter missing",
			statusLabel: "● P12 variant-search",
		},
		P13: {
			name: "P13",
			agent: agents.get("poc-builder"),
			missingMessage: "poc-builder missing",
			statusLabel: "● P13 poc-build",
		},
		P14: {
			name: "P14",
			agent: agents.get("finding-reporter"),
			missingMessage: "finding-reporter missing",
			statusLabel: "● P14 finding-report",
		},
		P15: {
			name: "P15",
			agent: agents.get("report-assembler"),
			missingMessage: "report-assembler missing",
			statusLabel: "● P15 final-report",
		},
	};

	const spec = (name: keyof typeof specs): PhaseSpec => {
		const s = specs[name];
		if (!s) throw new Error(`Internal: phase spec ${name} missing`);
		return s;
	};

	let failed = false;
	const want = (name: string) => shouldRun(name, opts.only);

	const runSequential = async (name: string, fn: () => Promise<void>) => {
		if (!want(name)) return;
		ensurePrereqs(audit, name);
		try {
			await fn();
		} catch {
			failed = true;
			throw new Error(`Phase ${name} failed`);
		}
	};

	try {
		await runSequential("P1", () =>
			runOne(cwd, audit, spec("P1"), recon.historyAvailable, signal, ui, opts.agentRuntime),
		);

		// P2 — skip when no git
		if (want("P2")) {
			ensurePrereqs(audit, "P2");
			if (!recon.historyAvailable) {
				await applyPhaseStatus(cwd, audit, "P2", {
					status: "skipped",
					error: "no git history available",
				});
			} else {
				try {
					await runOne(cwd, audit, spec("P2"), true, signal, ui, opts.agentRuntime);
				} catch {
					failed = true;
				}
			}
		}

		await runSequential("P3", () =>
			runOne(cwd, audit, spec("P3"), recon.historyAvailable, signal, ui, opts.agentRuntime),
		);
		await runSequential("P4", () =>
			runOne(cwd, audit, spec("P4"), recon.historyAvailable, signal, ui, opts.agentRuntime),
		);

		if (!failed && (want("P5") || want("P6") || want("P7"))) {
			const fanout = [spec("P5"), spec("P6"), spec("P7")].filter((s) => want(s.name));
			for (const s of fanout) ensurePrereqs(audit, s.name);
			const r = await runFanout3(
				cwd,
				audit,
				fanout,
				recon.historyAvailable,
				signal,
				ui,
				opts.agentRuntime,
			);
			if (r.failed) failed = true;
		}

		if (!failed) {
			await runSequential("P8", () =>
				runOne(cwd, audit, spec("P8"), recon.historyAvailable, signal, ui, opts.agentRuntime),
			);
			await runSequential("P9", () =>
				runOne(cwd, audit, spec("P9"), recon.historyAvailable, signal, ui, opts.agentRuntime),
			);
			await runSequential("P10", () =>
				runOne(cwd, audit, spec("P10"), recon.historyAvailable, signal, ui, opts.agentRuntime),
			);

			// Promote chamber-survived drafts.
			promoteDraftsByPrefix(cwd, "p10-");

			await runSequential("P11", () =>
				runOne(cwd, audit, spec("P11"), recon.historyAvailable, signal, ui, opts.agentRuntime),
			);
			await runSequential("P12", () =>
				runOne(cwd, audit, spec("P12"), recon.historyAvailable, signal, ui, opts.agentRuntime),
			);
			// Promote any p12-* variants surfaced after P11/P12.
			promoteDraftsByPrefix(cwd, "p12-");

			if (want("P13")) {
				ensurePrereqs(audit, "P13");
				const r = await runPerFinding(
					cwd,
					audit,
					"P13",
					spec("P13").agent,
					signal,
					ui,
					opts.agentRuntime,
				);
				if (r.failed) failed = true;
			}
			if (!failed && want("P14")) {
				ensurePrereqs(audit, "P14");
				const r = await runPerFinding(
					cwd,
					audit,
					"P14",
					spec("P14").agent,
					signal,
					ui,
					opts.agentRuntime,
				);
				if (r.failed) failed = true;
			}
			if (!failed && want("P15")) {
				await runSequential("P15", () =>
					runOne(cwd, audit, spec("P15"), recon.historyAvailable, signal, ui, opts.agentRuntime),
				);
			}
			if (!failed && want("P16")) {
				ensurePrereqs(audit, "P16");
				const r = await runDeepVerificationCleanup(cwd, audit, agents, signal, ui, opts.agentRuntime);
				if (r.failed) failed = true;
			}
			if (!failed && want("P17")) {
				ensurePrereqs(audit, "P17");
				const r = await runDeepCleanupPhase(cwd, audit, signal, ui);
				if (r.failed) failed = true;
			}
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
	ui?.notify?.(failed ? "Deep audit failed." : "Deep audit complete.", failed ? "error" : "info");
	return { auditId: audit.audit_id, status: failed ? "failed" : "complete", phases };
}
