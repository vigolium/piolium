/**
 * Longshot mode (`/piolium-longshot`).
 *
 * "Hail Mary" hunt — point an agent at every interesting source file in the
 * repo and tell it to dig as hard as possible for vulnerabilities.
 *
 * Pipeline:
 *
 *   X1 Enumerate → X2 Hunt (fan-out under Scheduler) → X3 Aggregate
 *
 * X1 is deterministic and runs in-process. X2 spawns one `longshot-hunter`
 * sub-agent per target file (capped by Scheduler.maxConcurrent). X3 runs a
 * single `longshot-aggregator` agent that reads every draft and produces a
 * curated, deduplicated summary.
 *
 * Scale guardrails:
 *   - --plm-longshot-limit / PIOLIUM_LONGSHOT_LIMIT (default 1000)
 *   - --plm-longshot-timeout / PIOLIUM_LONGSHOT_TIMEOUT_MS (default 6h per file)
 *   - Files >1MB skipped automatically.
 *   - Tests + generated files filtered out (see longshot.ts).
 */

import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { type AgentRuntimeModel, runAgent } from "../agent-runner.ts";
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
import {
	LONGSHOT_DEFAULT_LIMIT,
	LONGSHOT_DEFAULT_TIMEOUT_MS,
	LONGSHOT_FINDINGS_DRAFT_DIR,
	LONGSHOT_SUMMARY_PATH,
	LONGSHOT_TARGETS_PATH,
	type LongshotTarget,
	type LongshotTargetsFile,
	enumerateTargets,
	pendingTargets,
	readLongshotTargets,
	updateTargetStatus,
	writeLongshotTargets,
} from "../longshot.ts";
import { runReconAsync } from "../recon.ts";
import { errorMessage, readPositiveIntEnv } from "../retry.ts";
import { Scheduler } from "../scheduler.ts";
import { type PhaseUiHooks, runAgentPhase } from "./phase-runner.ts";

export type LongshotUiHooks = PhaseUiHooks;

export interface RunLongshotOptions {
	cwd: string;
	signal?: AbortSignal;
	ui?: LongshotUiHooks;
	forceFresh?: boolean;
	agentRuntime?: AgentRuntimeModel;
	/** Per-run override for the file cap. */
	limit?: number;
	/** Per-file kill timer in milliseconds. */
	perFileTimeoutMs?: number;
	/** Comma-list (e.g. ["Python", "Go"]) — overrides auto-detection. */
	languages?: string[];
	/** When true, include test files in enumeration. */
	includeTests?: boolean;
}

export interface RunLongshotResult {
	auditId: string;
	status: "complete" | "failed";
	phases: Record<string, "complete" | "failed" | "skipped">;
	targetsPath: string;
	summaryPath: string;
	targetsTotal: number;
	targetsCompleted: number;
	targetsFailed: number;
}

const STATUS_KEY = "piolium-longshot";

function readLimit(opt?: number): number {
	if (opt && opt > 0) return opt;
	return readPositiveIntEnv("PIOLIUM_LONGSHOT_LIMIT", LONGSHOT_DEFAULT_LIMIT);
}

function readPerFileTimeoutMs(opt?: number): number {
	if (opt && opt > 0) return opt;
	return readPositiveIntEnv("PIOLIUM_LONGSHOT_TIMEOUT_MS", LONGSHOT_DEFAULT_TIMEOUT_MS);
}

function readLanguages(opt?: string[]): string[] | undefined {
	if (opt && opt.length > 0) return opt;
	const raw = process.env.PIOLIUM_LONGSHOT_LANGS;
	if (!raw) return undefined;
	const parts = raw
		.split(/[,\s]+/)
		.map((s) => s.trim())
		.filter(Boolean);
	return parts.length > 0 ? parts : undefined;
}

function readIncludeTests(opt?: boolean): boolean {
	if (opt) return true;
	const raw = process.env.PIOLIUM_LONGSHOT_INCLUDE_TESTS;
	if (!raw) return false;
	return /^(1|true|yes|on)$/i.test(raw.trim());
}

function pickResumeAudit(cwd: string, forceFresh: boolean): AuditRunState | undefined {
	if (forceFresh) return undefined;
	const state = readAuditState(cwd).state;
	if (!state) return undefined;
	const audit = latestAudit(state);
	if (!audit) return undefined;
	if (audit.mode !== "longshot") return undefined;
	if (audit.status === "complete") return undefined;
	return audit;
}

function notify(ui: LongshotUiHooks | undefined, level: "info" | "warning" | "error", msg: string) {
	ui?.notify?.(msg, level);
}

function setStatus(ui: LongshotUiHooks | undefined, text?: string) {
	ui?.setStatus?.(STATUS_KEY, text);
}

async function runX1(
	cwd: string,
	audit: AuditRunState,
	options: RunLongshotOptions,
	ui?: LongshotUiHooks,
): Promise<LongshotTargetsFile> {
	const existing = readLongshotTargets(cwd);
	const phaseState = audit.phases.X1;
	if (existing && phaseState?.status === "complete") {
		return existing;
	}

	setStatus(ui, "● X1 enumerating targets");
	await applyPhaseStatus(cwd, audit, "X1", { status: "in_progress" });
	try {
		mkdirSync(join(cwd, "piolium", "attack-surface"), { recursive: true });
		const limit = readLimit(options.limit);
		const languages = readLanguages(options.languages);
		const includeTests = readIncludeTests(options.includeTests);
		const result = enumerateTargets({
			cwd,
			limit,
			...(languages ? { languages } : {}),
			includeTests,
		});

		if (existing) {
			// Resume: keep prior status for files still in the new target list
			// so we don't re-run completed work after a fresh enumeration.
			const priorByPath = new Map(existing.targets.map((t) => [t.path, t]));
			result.targets = result.targets.map((t) => {
				const prior = priorByPath.get(t.path);
				if (!prior) return t;
				return {
					...t,
					status: prior.status,
					attempts: prior.attempts,
					last_error: prior.last_error,
					completed_at: prior.completed_at,
					run_id: prior.run_id,
					draft_count: prior.draft_count,
				};
			});
		}

		writeLongshotTargets(cwd, result);
		await applyPhaseStatus(cwd, audit, "X1", {
			status: "complete",
			artifacts: [LONGSHOT_TARGETS_PATH],
		});
		notify(
			ui,
			"info",
			`X1 enumerated ${result.targets.length} target file(s) (skipped ${result.skipped_tests} test, ${result.skipped_generated} generated, ${result.skipped_oversized} oversized).`,
		);
		return result;
	} catch (err) {
		await applyPhaseStatus(cwd, audit, "X1", {
			status: "failed",
			error: errorMessage(err),
		});
		throw err;
	} finally {
		setStatus(ui, undefined);
	}
}

function buildHunterTask(target: LongshotTarget, totalFiles: number, rank: number): string {
	return [
		"You are running the X2 phase of a /piolium-longshot hail-mary scan.",
		"Your job is to find real, exploitable vulnerabilities anchored on a single target file.",
		"",
		`Target file (anchor): \`${target.path}\``,
		`Language: ${target.language}`,
		`Rank in this run: ${rank}/${totalFiles}  ·  Heuristic score: ${target.score}`,
		`File hash slug: ${target.sha8}`,
		"",
		"Hard rules — read carefully:",
		"  1. The anchor file is your starting point. You MUST read it in full first.",
		"  2. You MAY follow imports, callers, and called functions across the repo to understand context.",
		"     Use Grep/Glob to locate references; read every file you reason about.",
		"  3. Evidence is mandatory. Every claim about behavior must cite `path:line` from a file you actually read.",
		"  4. Do NOT fabricate. If you cannot verify the chain, write a clear theoretical/uncertain note instead.",
		"  5. Stay under 6 hours wall-clock. If you find nothing concrete after exhausting your obvious leads, exit cleanly.",
		"  6. Do NOT run network requests, do NOT execute the application, do NOT mutate the repo outside of writing draft markdown files.",
		"",
		"What to look for (non-exhaustive — pick what fits the file):",
		"  - Command injection, SQLi, SSRF, RCE via deserialization, prototype pollution",
		"  - Path traversal, unsafe file/archive handling",
		"  - Missing/broken authn or authz on a route or operation",
		"  - Race conditions, TOCTOU, idempotency gaps",
		"  - Hardcoded crypto/secrets, weak primitives, unsafe randomness",
		"  - Trust boundary violations: user input flowing into privileged sinks without validation",
		"  - Logic flaws specific to this code (don't force a generic CWE; describe what's actually wrong)",
		"",
		`For every concrete finding, write a draft to \`${LONGSHOT_FINDINGS_DRAFT_DIR}/longshot-${target.sha8}-NNN-<slug>.md\` (NNN starts at 001 for this anchor).`,
		"",
		"Draft frontmatter:",
		"  ---",
		"  id: longshot-<sha8>-NNN",
		"  phase: X2",
		"  anchor: <relative-path-of-anchor>",
		"  slug: <kebab-case>",
		"  severity: critical|high|medium|low",
		"  confidence: high|medium|low",
		"  ---",
		"",
		"Draft body — required sections:",
		"  ## Summary",
		"  ## Location  (file:line ranges, all files involved in the chain)",
		"  ## Attacker Control",
		"  ## Trust Boundary Crossed",
		"  ## Impact",
		"  ## Evidence  (verbatim code excerpts with path:line)",
		"  ## Exploit Sketch  (high-level — no live PoC)",
		"  ## Open Questions  (anything you couldn't verify)",
		"",
		"If the file genuinely has nothing exploitable after rigorous review, write a single short note draft titled `longshot-<sha8>-000-no-finding.md` with a one-line `## Summary` saying so, and exit. Do not pad with false positives.",
		"",
		"Begin now. Start by reading the anchor file in full.",
	].join("\n");
}

async function runX2(
	cwd: string,
	audit: AuditRunState,
	hunter: AgentDefinition | undefined,
	targets: LongshotTargetsFile,
	options: RunLongshotOptions,
	ui?: LongshotUiHooks,
): Promise<{ completed: number; failed: number }> {
	const phaseState = audit.phases.X2;
	const remaining = pendingTargets(targets);
	if (remaining.length === 0 && phaseState?.status === "complete") {
		const completedAlready = targets.targets.filter((t) => t.status === "complete").length;
		return { completed: completedAlready, failed: 0 };
	}
	if (!hunter) {
		await applyPhaseStatus(cwd, audit, "X2", {
			status: "failed",
			error: "longshot-hunter agent not found in bundled agents/.",
		});
		throw new Error("longshot-hunter agent missing");
	}

	await applyPhaseStatus(cwd, audit, "X2", { status: "in_progress" });
	setStatus(ui, `● X2 hunting ${remaining.length} file(s)`);

	const perFileTimeoutMs = readPerFileTimeoutMs(options.perFileTimeoutMs);
	const scheduler = new Scheduler({
		maxConcurrent: 3,
		...(options.signal ? { signal: options.signal } : {}),
	});

	let completed = 0;
	let failed = 0;
	const total = targets.targets.length;
	const previouslyCompleted = total - remaining.length;
	completed += previouslyCompleted;

	const updateProgressStatus = () => {
		setStatus(
			ui,
			`● X2 hunting (${completed}/${total} done${failed > 0 ? `, ${failed} failed` : ""})`,
		);
	};
	updateProgressStatus();

	const auditIdSafe = audit.audit_id.replace(/[:.]/g, "-");
	const tasks = remaining.map((target) => {
		const rank = targets.targets.findIndex((t) => t.path === target.path) + 1;
		return {
			id: `longshot-${target.sha8}`,
			timeoutMs: perFileTimeoutMs,
			run: async (signal: AbortSignal) => {
				const runId = `x2-${auditIdSafe}-${target.sha8}-${randomUUID().slice(0, 8)}`;
				await updateTargetStatus(cwd, target.path, {
					status: "in_progress",
					incrementAttempts: true,
					run_id: runId,
				});
				try {
					const draftsBefore = countDraftsForAnchor(cwd, target.sha8);
					await runAgent({
						agent: hunter,
						task: buildHunterTask(target, total, rank),
						runId,
						runtime: {
							cwd,
							mode: "longshot",
							phase: "X2",
							outputPaths: [
								join(cwd, LONGSHOT_FINDINGS_DRAFT_DIR),
								join(cwd, "piolium", "attack-surface"),
							],
							notes: [
								`Anchor file: ${target.path}`,
								`Language: ${target.language}`,
								`Per-file timeout: ${perFileTimeoutMs}ms`,
								`This is a single tile in a swarm of ${remaining.length} parallel hunts (rank ${rank} of ${total}).`,
								"Stay anchored on this file; cross-file reading is allowed but don't sprawl.",
							],
						},
						...(options.agentRuntime ? options.agentRuntime : {}),
						signal,
						onEvent: (event) => ui?.onAgentEvent?.("X2", event),
					});
					const draftsAfter = countDraftsForAnchor(cwd, target.sha8);
					const drafts = Math.max(0, draftsAfter - draftsBefore);
					await updateTargetStatus(cwd, target.path, {
						status: "complete",
						completed_at: new Date().toISOString(),
						draft_count: drafts,
					});
					completed++;
					updateProgressStatus();
				} catch (err) {
					failed++;
					await updateTargetStatus(cwd, target.path, {
						status: "failed",
						last_error: errorMessage(err),
					});
					updateProgressStatus();
					notify(ui, "warning", `Longshot ${target.sha8} (${target.path}) failed: ${errorMessage(err)}`);
				}
			},
		};
	});

	await scheduler.runBatch(tasks);
	scheduler.dispose();

	if (failed > 0 && completed === previouslyCompleted) {
		// Every remaining task failed — flag X2 as failed so the user sees it.
		await applyPhaseStatus(cwd, audit, "X2", {
			status: "failed",
			error: `All ${failed} hunter tasks failed.`,
			artifacts: [LONGSHOT_TARGETS_PATH],
		});
	} else {
		await applyPhaseStatus(cwd, audit, "X2", {
			status: "complete",
			artifacts: [LONGSHOT_TARGETS_PATH],
		});
	}
	setStatus(ui, undefined);
	return { completed, failed };
}

function countDraftsForAnchor(cwd: string, sha8: string): number {
	const dir = join(cwd, LONGSHOT_FINDINGS_DRAFT_DIR);
	if (!existsSync(dir)) return 0;
	try {
		return readdirSync(dir).filter((f) => f.startsWith(`longshot-${sha8}-`) && f.endsWith(".md"))
			.length;
	} catch {
		return 0;
	}
}

function buildAggregatorTask(targets: LongshotTargetsFile): string {
	return [
		"You are running the X3 phase of /piolium-longshot.",
		"X2 produced a flood of per-file drafts under `piolium/findings-draft/longshot-*.md`.",
		"Your job: read every draft, deduplicate overlapping findings, rank by severity + confidence,",
		"and emit a curated report.",
		"",
		"Inputs:",
		`  - Targets file:  \`${LONGSHOT_TARGETS_PATH}\` (read it for anchor → sha8 mapping)`,
		"  - Drafts:        `piolium/findings-draft/longshot-*.md`",
		`  - Total anchors hunted: ${targets.targets.length}`,
		`  - Anchors completed:    ${targets.targets.filter((t) => t.status === "complete").length}`,
		`  - Anchors failed:       ${targets.targets.filter((t) => t.status === "failed").length}`,
		"",
		"Steps:",
		"  1. List every `longshot-*-NNN-*.md` draft in the findings-draft directory.",
		"  2. Read each one. Skip `*-000-no-finding.md` files (those are explicit no-result markers).",
		"  3. Group drafts by root cause / sink / vulnerable symbol. Two drafts that point at the",
		"     same underlying bug from different files are duplicates — merge them.",
		"  4. For each unique vulnerability, write a curated draft to",
		"     `piolium/findings-draft/longshot-curated-NNN-<slug>.md` with:",
		"       - frontmatter: id, phase: X3, slug, severity, confidence, source_drafts (list of merged paths)",
		"       - sections: Summary, Affected Files, Root Cause, Attacker Control, Impact, Evidence, Exploit Sketch, Confidence Notes.",
		"  5. Rank curated findings by severity (critical > high > medium > low) then confidence.",
		`  6. Write \`${LONGSHOT_SUMMARY_PATH}\` with:`,
		"       - Run metadata (date, anchor counts, languages targeted)",
		"       - Per-anchor table: path, score, status, draft_count",
		"       - Curated finding table: id, severity, confidence, slug, anchor file(s)",
		"       - Top 5 most concerning findings with one-paragraph summaries.",
		"",
		"Hard rules:",
		"  - Don't invent findings the drafts don't already claim. You are summarizing, not hunting.",
		"  - If two drafts disagree about severity, pick the better-evidenced one and note the discrepancy.",
		"  - Drop drafts that have no `## Evidence` section or lack `path:line` citations — they are unreliable.",
		"  - Always write the summary file even if zero findings survive curation.",
	].join("\n");
}

async function runX3(
	cwd: string,
	audit: AuditRunState,
	aggregator: AgentDefinition | undefined,
	targets: LongshotTargetsFile,
	options: RunLongshotOptions,
	ui?: LongshotUiHooks,
): Promise<void> {
	const summaryAbs = join(cwd, LONGSHOT_SUMMARY_PATH);
	if (!aggregator) {
		await applyPhaseStatus(cwd, audit, "X3", {
			status: "failed",
			error: "longshot-aggregator agent not found in bundled agents/.",
		});
		throw new Error("longshot-aggregator agent missing");
	}
	await runAgentPhase({
		cwd,
		audit,
		phaseName: "X3",
		statusKey: STATUS_KEY,
		statusLabel: "● X3 aggregating drafts",
		agent: aggregator,
		missingAgentMessage: "longshot-aggregator agent missing",
		task: buildAggregatorTask(targets),
		runtimeExtras: {
			outputPaths: [join(cwd, LONGSHOT_FINDINGS_DRAFT_DIR), join(cwd, "piolium", "attack-surface")],
			notes: [`Targets file: ${LONGSHOT_TARGETS_PATH}`, "Read drafts; do not re-run hunts."],
		},
		gate: () => existsSync(summaryAbs),
		mode: "longshot",
		ui,
		agentRuntime: options.agentRuntime,
		...(options.signal ? { signal: options.signal } : {}),
	});
}

export async function runLongshotAudit(opts: RunLongshotOptions): Promise<RunLongshotResult> {
	const { cwd, ui } = opts;
	mkdirSync(join(cwd, "piolium", "attack-surface"), { recursive: true });
	mkdirSync(join(cwd, LONGSHOT_FINDINGS_DRAFT_DIR), { recursive: true });

	ui?.setStatus?.(STATUS_KEY, "● preparing recon");
	const recon = await runReconAsync(cwd, { signal: opts.signal });
	ui?.setStatus?.(STATUS_KEY, "● scanning candidate files");
	const candidateScan = await runCandidateScanAsync(cwd, { signal: opts.signal });
	ui?.notify?.(
		`Candidate scan: ${candidateScan.candidateCount} match(es) across ${candidateScan.candidateFiles} file(s).`,
		"info",
	);
	let audit = pickResumeAudit(cwd, opts.forceFresh ?? false);
	if (!audit) {
		audit = await initAudit(cwd, {
			mode: "longshot",
			...(recon.commit ? { commit: recon.commit } : { commit: null }),
			...(recon.branch ? { branch: recon.branch } : { branch: "nogit" }),
			...(recon.repository ? { repository: recon.repository } : {}),
			history_available: recon.historyAvailable,
			agent_sdk: "pi",
		});
	}

	const { agents } = loadAgents({ cwd });
	const hunter = agents.get("longshot-hunter");
	const aggregator = agents.get("longshot-aggregator");

	let targets: LongshotTargetsFile;
	let failed = false;
	try {
		targets = await runX1(cwd, audit, opts, ui);
	} catch {
		await markAuditStatus(cwd, audit.audit_id, "failed");
		setStatus(ui, undefined);
		return finalResult(audit, "failed", cwd, undefined);
	}

	if (targets.targets.length === 0) {
		notify(
			ui,
			"warning",
			"X1 produced 0 candidate files. Check --plm-longshot-langs or repository contents.",
		);
		// Skip X2/X3 — nothing to hunt or aggregate.
		await applyPhaseStatus(cwd, audit, "X2", { status: "skipped" });
		await applyPhaseStatus(cwd, audit, "X3", { status: "skipped" });
		writeFileSync(
			join(cwd, LONGSHOT_SUMMARY_PATH),
			[
				"# piolium Longshot Summary",
				"",
				`Generated: ${new Date().toISOString()}`,
				"",
				"No candidate files matched the longshot enumeration filters. Adjust",
				"`--plm-longshot-langs` or run on a repository with recognized source files.",
				"",
			].join("\n"),
		);
		await markAuditStatus(cwd, audit.audit_id, "complete");
		return finalResult(audit, "complete", cwd, targets);
	}

	let huntStats = { completed: 0, failed: 0 };
	try {
		huntStats = await runX2(cwd, audit, hunter, targets, opts, ui);
	} catch {
		failed = true;
	}

	// Reload latest sidecar in case X2 updated statuses.
	const refreshedTargets = readLongshotTargets(cwd) ?? targets;

	if (!failed) {
		try {
			await runX3(cwd, audit, aggregator, refreshedTargets, opts, ui);
		} catch {
			failed = true;
		}
	}

	const final = await markAuditStatus(cwd, audit.audit_id, failed ? "failed" : "complete");
	setStatus(ui, undefined);
	if (failed) {
		notify(
			ui,
			"error",
			`Longshot audit failed (X2 completed ${huntStats.completed}, failed ${huntStats.failed}).`,
		);
	} else {
		notify(
			ui,
			"info",
			`Longshot audit complete. ${huntStats.completed} file(s) hunted, ${huntStats.failed} failed.`,
		);
	}
	return finalResult(final ?? audit, failed ? "failed" : "complete", cwd, refreshedTargets);
}

function finalResult(
	audit: AuditRunState,
	status: "complete" | "failed",
	cwd: string,
	targets: LongshotTargetsFile | undefined,
): RunLongshotResult {
	const phases: Record<string, "complete" | "failed" | "skipped"> = {};
	for (const [name, phase] of Object.entries(audit.phases)) {
		if (phase.status === "complete" || phase.status === "failed" || phase.status === "skipped") {
			phases[name] = phase.status;
		}
	}
	const completed = targets?.targets.filter((t) => t.status === "complete").length ?? 0;
	const failedCount = targets?.targets.filter((t) => t.status === "failed").length ?? 0;
	return {
		auditId: audit.audit_id,
		status,
		phases,
		targetsPath: join(cwd, LONGSHOT_TARGETS_PATH),
		summaryPath: join(cwd, LONGSHOT_SUMMARY_PATH),
		targetsTotal: targets?.targets.length ?? 0,
		targetsCompleted: completed,
		targetsFailed: failedCount,
	};
}

export { LONGSHOT_TARGETS_PATH, LONGSHOT_SUMMARY_PATH, LONGSHOT_FINDINGS_DRAFT_DIR };
