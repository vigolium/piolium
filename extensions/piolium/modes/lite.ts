/**
 * Lite mode orchestrator.
 *
 * Pipeline (from command-defs/lite.md):
 *
 *   Q0 Quick Recon   →   [Q1 Secrets Scan + Q2 Fast SAST]
 *                    →   Q3 Promotion + PoC Construction
 *                    →   Q4 Verification & Cleanup
 *
 * Q0 is deterministic and runs in-process (no model). Q1 runs as a
 * deterministic external-tool driven scan. Q2 spawns the static-analyzer
 * agent with a tightly-scoped lite-mode task. Q1 and Q2 race in parallel
 * under the global concurrency cap. Q3 promotes draft findings (q1-*, q2-*)
 * into severity-prefixed `findings/<ID>-<slug>/` directories and dispatches
 * one `poc-builder` agent per finding. Q4 verifies the final layout and
 * removes transient artifacts while retaining draft evidence for review.
 *
 * The orchestrator also writes the audit-state file, performs lightweight
 * resume by re-running phases whose artifact gates fail, and surfaces
 * progress via optional UI hooks.
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
import {
	candidateSummaryPath,
	candidatesJsonlPath,
	runCandidateScanAsync,
} from "../candidate-scan.ts";
import { type ConsolidationResult, consolidateDrafts, listFindingDirs } from "../findings.ts";
import { reconReportPath, runReconAsync } from "../recon.ts";
import { errorMessage, readNonNegativeIntEnv, readPositiveIntEnv, runWithRetry } from "../retry.ts";
import { Scheduler } from "../scheduler.ts";
import { Q1_SECRETS_SUMMARY, findingsDraftDir, runQ1SecretsScan } from "../secrets.ts";
import { type PhaseUiHooks, runAgentPhase } from "./phase-runner.ts";

export type LiteUiHooks = PhaseUiHooks;

export interface RunLiteOptions {
	cwd: string;
	signal?: AbortSignal;
	ui?: LiteUiHooks;
	/** When true, restart from scratch even if an in-progress audit exists. */
	forceFresh?: boolean;
	agentRuntime?: AgentRuntimeModel;
}

export interface RunLiteResult {
	auditId: string;
	status: "complete" | "failed";
	phases: Record<string, "complete" | "failed" | "skipped">;
	summaryPath: string;
}

export const LITE_ATTACK_SURFACE_DIR = "piolium/attack-surface";
export const Q1_SUMMARY = Q1_SECRETS_SUMMARY;
export const Q2_SUMMARY = `${LITE_ATTACK_SURFACE_DIR}/lite-q2-summary.md`;
export const Q3_CONSOLIDATION_MANIFEST = `${LITE_ATTACK_SURFACE_DIR}/lite-consolidation-manifest.json`;
export const Q4_VERIFICATION_SUMMARY = `${LITE_ATTACK_SURFACE_DIR}/lite-verification-summary.md`;
export const Q4_CLEANUP_SUMMARY = `${LITE_ATTACK_SURFACE_DIR}/lite-cleanup-summary.json`;
/** @deprecated kept for backward compatibility; use Q4_VERIFICATION_SUMMARY. */
export const Q3_VERIFICATION_SUMMARY = Q4_VERIFICATION_SUMMARY;
/** @deprecated kept for backward compatibility; use Q4_CLEANUP_SUMMARY. */
export const Q3_CLEANUP_SUMMARY = Q4_CLEANUP_SUMMARY;
const LITE_TRANSIENT_PATHS = [
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

function litePhaseMaxRetries(): number {
	return readNonNegativeIntEnv(
		"PIOLIUM_LITE_PHASE_MAX_RETRIES",
		readNonNegativeIntEnv("PIOLIUM_PHASE_MAX_RETRIES", 5),
	);
}

function litePhaseBackoffBaseMs(): number {
	return readPositiveIntEnv(
		"PIOLIUM_LITE_PHASE_BACKOFF_BASE_MS",
		readPositiveIntEnv("PIOLIUM_PHASE_BACKOFF_BASE_MS", 5000),
	);
}

function litePhaseBackoffMaxMs(): number {
	return readPositiveIntEnv(
		"PIOLIUM_LITE_PHASE_BACKOFF_MAX_MS",
		readPositiveIntEnv("PIOLIUM_PHASE_BACKOFF_MAX_MS", 120_000),
	);
}

function gatePass(cwd: string, phase: "Q0" | "Q1" | "Q2" | "Q3" | "Q4"): boolean {
	switch (phase) {
		case "Q0":
			return (
				existsSync(reconReportPath(cwd)) &&
				existsSync(candidateSummaryPath(cwd)) &&
				existsSync(candidatesJsonlPath(cwd))
			);
		case "Q1":
			return existsSync(join(cwd, Q1_SUMMARY));
		case "Q2":
			return existsSync(join(cwd, Q2_SUMMARY));
		case "Q3":
			return existsSync(join(cwd, Q3_CONSOLIDATION_MANIFEST));
		case "Q4":
			return existsSync(join(cwd, Q4_VERIFICATION_SUMMARY));
	}
}

function pickResumeAudit(cwd: string, forceFresh: boolean): AuditRunState | undefined {
	if (forceFresh) return undefined;
	const state = readAuditState(cwd).state;
	if (!state) return undefined;
	const audit = latestAudit(state);
	if (!audit) return undefined;
	if (audit.mode !== "lite") return undefined;
	if (audit.status === "complete") return undefined;
	return audit;
}

function notify(
	ui: LiteUiHooks | undefined,
	level: Parameters<NonNullable<LiteUiHooks["notify"]>>[1],
	msg: string,
) {
	ui?.notify?.(msg, level);
}

function setStatus(ui: LiteUiHooks | undefined, key: string, text?: string) {
	ui?.setStatus?.(key, text);
}

interface LiteLocalPhaseResult {
	artifacts: string[];
	notifyText?: string;
}

async function runLiteLocalPhase(
	cwd: string,
	audit: AuditRunState,
	phaseName: "Q0" | "Q1",
	statusLabel: string,
	gate: () => boolean,
	run: () => LiteLocalPhaseResult | Promise<LiteLocalPhaseResult>,
	signal: AbortSignal | undefined,
	ui?: LiteUiHooks,
): Promise<void> {
	if (audit.phases[phaseName]?.status === "complete" && gate()) {
		return;
	}

	const maxRetries = litePhaseMaxRetries();
	const maxAttempts = maxRetries + 1;
	const backoffBaseMs = litePhaseBackoffBaseMs();
	const backoffMaxMs = litePhaseBackoffMaxMs();
	try {
		const result = await runWithRetry(
			async (attempt, attempts) => {
				const attemptLabel = attempts > 1 ? `${statusLabel} (${attempt}/${attempts})` : statusLabel;
				setStatus(ui, "piolium-lite", attemptLabel);
				await applyPhaseStatus(cwd, audit, phaseName, {
					status: "in_progress",
					attempt,
					max_attempts: attempts,
					retry_backoff_ms: null,
					next_retry_at: null,
					...(attempt > 1 ? { error: `Retry attempt ${attempt}/${attempts} running.` } : {}),
				});

				try {
					const phaseResult = await run();
					if (!gate()) {
						throw new Error(`Phase ${phaseName} gate failed — expected artifact missing.`);
					}
					await applyPhaseStatus(cwd, audit, phaseName, {
						status: "complete",
						artifacts: phaseResult.artifacts,
						attempt,
						max_attempts: attempts,
						retry_backoff_ms: null,
						next_retry_at: null,
						last_error: null,
					});
					return phaseResult;
				} catch (err) {
					if (gate()) {
						await applyPhaseStatus(cwd, audit, phaseName, {
							status: "complete",
							attempt,
							max_attempts: attempts,
							retry_backoff_ms: null,
							next_retry_at: null,
							last_error: null,
						});
						notify(
							ui,
							"warning",
							`Phase ${phaseName} errored but its required artifact exists; treating it as complete.`,
						);
						return { artifacts: [] };
					}
					throw err;
				}
			},
			{
				maxRetries,
				backoffBaseMs,
				backoffMaxMs,
				...(signal ? { signal } : {}),
				onRetry: async (info) => {
					await applyPhaseStatus(cwd, audit, phaseName, {
						status: "in_progress",
						error: `Attempt ${info.attempt}/${info.maxAttempts} failed: ${info.errorMessage}. Retrying at ${info.nextRetryAt}.`,
						attempt: info.attempt,
						max_attempts: info.maxAttempts,
						retry_backoff_ms: info.backoffMs,
						next_retry_at: info.nextRetryAt,
						last_error: info.errorMessage,
					});
					notify(
						ui,
						"warning",
						`Phase ${phaseName} attempt ${info.attempt}/${info.maxAttempts} failed; retrying in ${Math.ceil(info.backoffMs / 1000)}s.`,
					);
					setStatus(
						ui,
						"piolium-lite",
						`${statusLabel} retrying in ${Math.ceil(info.backoffMs / 1000)}s`,
					);
				},
			},
		);
		if (result.notifyText) notify(ui, "info", result.notifyText);
	} catch (err) {
		const message = errorMessage(err);
		await applyPhaseStatus(cwd, audit, phaseName, {
			status: "failed",
			error: maxRetries > 0 ? `Failed after ${maxRetries} retries: ${message}` : message,
			attempt: maxAttempts,
			max_attempts: maxAttempts,
			retry_backoff_ms: null,
			next_retry_at: null,
			last_error: message,
		});
		throw err;
	}
}

async function runQ0(
	cwd: string,
	audit: AuditRunState,
	signal: AbortSignal | undefined,
	ui?: LiteUiHooks,
): Promise<void> {
	await runLiteLocalPhase(
		cwd,
		audit,
		"Q0",
		"● Q0 recon",
		() => gatePass(cwd, "Q0"),
		async () => {
			const recon = await runReconAsync(cwd, { signal });
			const candidates = await runCandidateScanAsync(cwd, { signal });
			return {
				artifacts: [recon.reportPath, candidates.summaryPath, candidates.candidatesPath],
				notifyText: `Q0 recon: ${candidates.candidateCount} candidate match(es) across ${candidates.candidateFiles} file(s).`,
			};
		},
		signal,
		ui,
	);
}

async function runQ1(
	cwd: string,
	audit: AuditRunState,
	signal: AbortSignal | undefined,
	ui?: LiteUiHooks,
): Promise<void> {
	await runLiteLocalPhase(
		cwd,
		audit,
		"Q1",
		"● Q1 secrets",
		() => gatePass(cwd, "Q1"),
		() => {
			const result = runQ1SecretsScan(cwd);
			return {
				artifacts: [join(cwd, Q1_SUMMARY), ...result.draftPaths],
				notifyText: `Q1 ${result.backend}: ${result.findings.length} draft finding(s).`,
			};
		},
		signal,
		ui,
	);
}

function buildQ2Task(cwd: string): string {
	return [
		"You are running the Q2 phase of a /piolium-lite scan.",
		"This is a TIGHTLY SCOPED lite-mode SAST pass — not a full audit. Constraints:",
		"  - Hard time budget: 5 minutes wall-clock.",
		"  - Do NOT build CodeQL/Semgrep databases. If those tools aren't already installed, fall back to grep + read.",
		"  - Focus on cheap, high-signal patterns: command injection, path traversal, SSRF, hardcoded crypto, broken authn/z.",
		"  - Read `piolium/attack-surface/lite-recon.md`, `piolium/attack-surface/candidates-summary.md`, `piolium/attack-surface/candidates.jsonl`, and `piolium/attack-surface/lite-q1-summary.md` if present.",
		"  - Prioritize precise/high-score candidate files first, but validate with source evidence before drafting.",
		"  - For each candidate issue, write a draft finding to `piolium/findings-draft/q2-NNN-<slug>.md`.",
		`  - Write a phase summary to \`${Q2_SUMMARY}\` even when nothing is found.`,
		"  - Stop after at most 8 candidate findings — quality over quantity.",
		"",
		`Target repository: ${cwd}`,
		"",
		"Each finding draft should follow this frontmatter:",
		"  ---",
		"  id: q2-NNN",
		"  phase: Q2",
		"  slug: <kebab-case>",
		"  severity: high|medium|low",
		"  ---",
		"",
		"Begin now.",
	].join("\n");
}

async function runQ2(
	cwd: string,
	audit: AuditRunState,
	staticAnalyzer: AgentDefinition | undefined,
	signal: AbortSignal | undefined,
	ui?: LiteUiHooks,
	agentRuntime?: AgentRuntimeModel,
): Promise<void> {
	await runAgentPhase({
		cwd,
		audit,
		phaseName: "Q2",
		statusKey: "piolium-lite",
		statusLabel: "● Q2 fast SAST",
		agent: staticAnalyzer,
		missingAgentMessage: "static-analyzer agent not found in bundled agents/.",
		task: buildQ2Task(cwd),
		runtimeExtras: {
			outputPaths: [findingsDraftDir(cwd), join(cwd, Q2_SUMMARY)],
			notes: ["Lite mode — keep the run under 5 minutes wall-clock."],
		},
		gate: () => gatePass(cwd, "Q2"),
		mode: "lite",
		ui,
		agentRuntime,
		...(signal ? { signal } : {}),
	});
	notify(ui, "info", `Q2 produced ${listQ2Drafts(cwd).length} draft finding(s).`);
}

function listQ2Drafts(cwd: string): string[] {
	return listDraftFiles(cwd, "q2-");
}

function listDraftFiles(cwd: string, prefix: string): string[] {
	const dir = findingsDraftDir(cwd);
	if (!existsSync(dir)) return [];
	return readdirSync(dir)
		.filter((f) => f.startsWith(prefix) && f.endsWith(".md"))
		.map((f) => join(dir, f));
}

export interface LiteCleanupResult {
	summaryPath: string;
	removed: string[];
	missing: string[];
	retained: string[];
}

export function cleanupLiteTransientArtifacts(cwd: string): LiteCleanupResult {
	mkdirSync(join(cwd, LITE_ATTACK_SURFACE_DIR), { recursive: true });
	const removed: string[] = [];
	const missing: string[] = [];
	for (const rel of LITE_TRANSIENT_PATHS) {
		const abs = join(cwd, rel);
		if (!existsSync(abs)) {
			missing.push(rel);
			continue;
		}
		rmSync(abs, { recursive: true, force: true });
		removed.push(rel);
	}
	const result: LiteCleanupResult = {
		summaryPath: Q4_CLEANUP_SUMMARY,
		removed,
		missing,
		retained: ["piolium/attack-surface/", "piolium/findings/", "piolium/audit-state.json"],
	};
	writeFileSync(join(cwd, Q4_CLEANUP_SUMMARY), `${JSON.stringify(result, null, "\t")}\n`);
	return result;
}

function buildLiteQ3PocTask(findingDir: string, id: string, slug: string): string {
	return [
		"You are running Phase Q3 (PoC Construction) for a single finding in /piolium-lite.",
		"",
		`Finding directory: ${findingDir}`,
		`Assigned ID: ${id}`,
		`Slug: ${slug}`,
		"",
		"Steps:",
		"  1. Read `draft.md` in the finding directory.",
		"  2. Build a minimal proof-of-concept demonstrating exploitability.",
		"  3. Write the PoC to `<finding-dir>/poc.{py|sh|js|rb|go}` (pick the most natural language).",
		"  4. Capture commands run and observed output under `<finding-dir>/evidence/`.",
		"  5. If exploitation requires a runtime that's unavailable, write a `poc.theoretical.md` documenting the chain.",
		"",
		"Lite-mode constraints:",
		"  - Hard cap: 3 minutes wall-clock per finding.",
		"  - Do NOT regenerate or rewrite `draft.md`.",
		"  - Do NOT author `report.md` — that is out of scope for lite mode.",
		"",
		"Stop after the PoC + evidence are written.",
	].join("\n");
}

async function runQ3PoCPerFinding(
	cwd: string,
	audit: AuditRunState,
	pocBuilder: AgentDefinition | undefined,
	consolidation: ConsolidationResult,
	signal: AbortSignal | undefined,
	ui?: LiteUiHooks,
	agentRuntime?: AgentRuntimeModel,
): Promise<{ failed: boolean }> {
	if (consolidation.promoted.length === 0) return { failed: false };
	if (!pocBuilder) {
		notify(ui, "warning", "poc-builder agent missing; skipping Q3 per-finding PoC construction.");
		return { failed: false };
	}
	const scheduler = new Scheduler({ maxConcurrent: 3, ...(signal ? { signal } : {}) });
	const settled = await Promise.allSettled(
		consolidation.promoted.map((entry) =>
			scheduler.enqueue({
				id: `Q3:${entry.id}`,
				run: (sig) =>
					runAgentPhase({
						cwd,
						audit,
						phaseName: `Q3:${entry.id}`,
						statusKey: "piolium-lite",
						statusLabel: `● Q3 PoC ${entry.id}`,
						agent: pocBuilder,
						missingAgentMessage: "poc-builder agent missing",
						task: buildLiteQ3PocTask(entry.findingDir, entry.id, entry.slug),
						runtimeExtras: {
							outputPaths: [entry.findingDir],
							notes: ["Lite mode — keep the run under 3 minutes wall-clock per finding."],
						},
						gate: () => {
							const dir = entry.findingDir;
							if (!existsSync(dir)) return false;
							return (
								readdirSync(dir).some((f) => f.startsWith("poc.")) ||
								existsSync(join(dir, "poc.theoretical.md"))
							);
						},
						mode: "lite",
						ui,
						agentRuntime,
						...(sig ? { signal: sig } : {}),
					}),
			}),
		),
	);
	scheduler.dispose();
	return { failed: settled.some((s) => s.status === "rejected") };
}

async function runQ3(
	cwd: string,
	audit: AuditRunState,
	pocBuilder: AgentDefinition | undefined,
	signal: AbortSignal | undefined,
	ui?: LiteUiHooks,
	agentRuntime?: AgentRuntimeModel,
): Promise<void> {
	if (audit.phases.Q3?.status === "complete" && gatePass(cwd, "Q3")) return;
	if (signal?.aborted) throw signal.reason ?? new Error("Aborted");
	setStatus(ui, "piolium-lite", "● Q3 promote+poc");
	await applyPhaseStatus(cwd, audit, "Q3", { status: "in_progress" });
	try {
		mkdirSync(join(cwd, LITE_ATTACK_SURFACE_DIR), { recursive: true });
		const consolidation = consolidateDrafts(cwd, ["q1-", "q2-"]);
		const manifest = {
			generated_at: new Date().toISOString(),
			source_prefixes: ["q1-", "q2-"],
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
		writeFileSync(join(cwd, Q3_CONSOLIDATION_MANIFEST), `${JSON.stringify(manifest, null, "\t")}\n`);
		notify(
			ui,
			"info",
			`Q3 promoted ${consolidation.promoted.length} finding(s); dropped ${consolidation.dropped.length} low/info draft(s).`,
		);

		const pocResult = await runQ3PoCPerFinding(
			cwd,
			audit,
			pocBuilder,
			consolidation,
			signal,
			ui,
			agentRuntime,
		);
		await applyPhaseStatus(cwd, audit, "Q3", {
			status: pocResult.failed ? "failed" : "complete",
			artifacts: [Q3_CONSOLIDATION_MANIFEST],
			...(pocResult.failed
				? { error: "One or more per-finding PoC builds failed; see Q3:* sub-phases." }
				: {}),
		});
		if (pocResult.failed) {
			throw new Error("Q3 PoC construction had failures.");
		}
	} catch (err) {
		await applyPhaseStatus(cwd, audit, "Q3", {
			status: "failed",
			error: errorMessage(err),
		});
		throw err;
	} finally {
		setStatus(ui, "piolium-lite", undefined);
	}
}

async function runQ4(
	cwd: string,
	audit: AuditRunState,
	signal: AbortSignal | undefined,
	ui?: LiteUiHooks,
): Promise<void> {
	if (audit.phases.Q4?.status === "complete" && gatePass(cwd, "Q4")) return;
	if (signal?.aborted) throw signal.reason ?? new Error("Aborted");
	setStatus(ui, "piolium-lite", "● Q4 verify-cleanup");
	await applyPhaseStatus(cwd, audit, "Q4", { status: "in_progress" });
	try {
		mkdirSync(join(cwd, LITE_ATTACK_SURFACE_DIR), { recursive: true });
		const dirs = listFindingDirs(cwd);
		const missingPocs = dirs
			.filter((d) => !d.hasPoc && !existsSync(join(d.path, "poc.theoretical.md")))
			.map((d) => `${d.id}-${d.slug}`);
		const cleanup = cleanupLiteTransientArtifacts(cwd);
		writeFileSync(
			join(cwd, Q4_VERIFICATION_SUMMARY),
			[
				"# Lite Verification & Cleanup",
				"",
				`Generated: ${new Date().toISOString()}`,
				"",
				"## Verification",
				"",
				"- Scope: lightweight package verification; live target confirmation remains `/piolium-confirm`.",
				`- Final finding directories: ${dirs.length}`,
				`- Missing PoC artifact: ${missingPocs.length > 0 ? missingPocs.join(", ") : "none"}`,
				"- Durable review inputs remain under `piolium/attack-surface/`.",
				"",
				"## Cleanup",
				"",
				`- Removed: ${cleanup.removed.length > 0 ? cleanup.removed.map((p) => `\`${p}\``).join(", ") : "(none)"}`,
				`- Missing: ${cleanup.missing.length > 0 ? cleanup.missing.map((p) => `\`${p}\``).join(", ") : "(none)"}`,
				`- Cleanup summary: \`${cleanup.summaryPath}\``,
				"",
			].join("\n"),
		);
		await applyPhaseStatus(cwd, audit, "Q4", {
			status: "complete",
			artifacts: [Q4_VERIFICATION_SUMMARY, cleanup.summaryPath],
		});
	} catch (err) {
		await applyPhaseStatus(cwd, audit, "Q4", {
			status: "failed",
			error: errorMessage(err),
		});
		throw err;
	} finally {
		setStatus(ui, "piolium-lite", undefined);
	}
}

export async function runLiteAudit(opts: RunLiteOptions): Promise<RunLiteResult> {
	const { cwd, signal, ui } = opts;
	mkdirSync(join(cwd, LITE_ATTACK_SURFACE_DIR), { recursive: true });

	ui?.setStatus?.("piolium-lite", "● preparing recon");
	const recon0 = await runReconAsync(cwd, { signal });
	ui?.setStatus?.("piolium-lite", "● scanning candidate files");
	const candidateScan = await runCandidateScanAsync(cwd, { signal });
	ui?.notify?.(
		`Candidate scan: ${candidateScan.candidateCount} match(es) across ${candidateScan.candidateFiles} file(s).`,
		"info",
	);
	let audit = pickResumeAudit(cwd, opts.forceFresh ?? false);
	if (!audit) {
		audit = await initAudit(cwd, {
			mode: "lite",
			...(recon0.commit ? { commit: recon0.commit } : { commit: null }),
			...(recon0.branch ? { branch: recon0.branch } : { branch: "nogit" }),
			...(recon0.repository ? { repository: recon0.repository } : {}),
			history_available: recon0.historyAvailable,
			agent_sdk: "pi",
		});
	}

	// Q0 first, deterministic. Required for Q2 task to have target context.
	try {
		await runQ0(cwd, audit, signal, ui);
	} catch {
		await markAuditStatus(cwd, audit.audit_id, "failed");
		setStatus(ui, "piolium-lite", undefined);
		return finalResult(audit, "failed", cwd);
	}

	// Q1 + Q2 race under the cap. Both are independent.
	const scheduler = new Scheduler({ maxConcurrent: 3, ...(signal ? { signal } : {}) });
	const { agents } = loadAgents({ cwd });
	const staticAnalyzer = agents.get("static-analyzer");
	const pocBuilder = agents.get("poc-builder");

	const settled = await Promise.allSettled([
		scheduler.enqueue({ id: "Q1", run: (sig) => runQ1(cwd, audit, sig, ui) }),
		scheduler.enqueue({
			id: "Q2",
			run: (sig) => runQ2(cwd, audit, staticAnalyzer, sig, ui, opts.agentRuntime),
		}),
	]);
	scheduler.dispose();

	let failed = settled.some((s) => s.status === "rejected");
	if (!failed) {
		try {
			await runQ3(cwd, audit, pocBuilder, signal, ui, opts.agentRuntime);
		} catch {
			failed = true;
		}
	}
	if (!failed) {
		try {
			await runQ4(cwd, audit, signal, ui);
		} catch {
			failed = true;
		}
	}
	const final = await markAuditStatus(cwd, audit.audit_id, failed ? "failed" : "complete");
	setStatus(ui, "piolium-lite", undefined);
	if (failed) {
		notify(
			ui,
			"error",
			`Lite audit failed (${settled.filter((s) => s.status === "rejected").length} phase failure(s)).`,
		);
	} else {
		notify(ui, "info", "Lite audit complete.");
	}
	return finalResult(final ?? audit, failed ? "failed" : "complete", cwd);
}

function finalResult(
	audit: AuditRunState,
	status: "complete" | "failed",
	cwd: string,
): RunLiteResult {
	const phases: Record<string, "complete" | "failed" | "skipped"> = {};
	for (const [name, phase] of Object.entries(audit.phases)) {
		if (phase.status === "complete" || phase.status === "failed" || phase.status === "skipped") {
			phases[name] = phase.status;
		}
	}
	return {
		auditId: audit.audit_id,
		status,
		phases,
		summaryPath: reconReportPath(cwd),
	};
}
