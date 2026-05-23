// Reinvest mode (`/piolium-reinvest`). Cross-agent re-verification of
// CRITICAL/HIGH findings produced by a prior audit. I1 enumerate → I2
// wave-verifier fan-out (cap 3) → I3 consensus summary. Existing report.md /
// poc / evidence / prior audits[] entries are immutable; only
// piolium/reinvest-report.md is produced.

import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
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
import { type FindingDir, listFindingDirs } from "../findings.ts";
import { errorMessage } from "../retry.ts";
import { Scheduler } from "../scheduler.ts";
import type { PhaseUiHooks } from "./phase-runner.ts";

export interface RunReinvestOptions {
	cwd: string;
	signal?: AbortSignal;
	ui?: PhaseUiHooks;
	forceFresh?: boolean;
	agentRuntime?: AgentRuntimeModel;
	/**
	 * Optional comma-separated ID allow-list (e.g. `["C1", "H1", "H3"]`). When
	 * empty, every C-prefixed and H-prefixed finding under `piolium/findings/`
	 * is reinvested. MEDIUM/LOW are always excluded — too numerous to justify
	 * a mass second-pass at this verifier cost.
	 */
	scope?: readonly string[];
}

export interface RunReinvestResult {
	auditId: string;
	status: "complete" | "failed";
	phases: Record<string, "complete" | "failed" | "skipped">;
	reportPath: string;
	reinvestedCount: number;
	flippedCount: number;
	uncertainCount: number;
}

export const REINVEST_WORKSPACE = "piolium/reinvest-workspace";
export const REINVEST_SCOPE_FILE = `${REINVEST_WORKSPACE}/scope.json`;
export const REINVEST_REPORT = "piolium/reinvest-report.md";
const REINVEST_BURST_CAP = 3;
const STATUS_KEY = "piolium-reinvest";

interface ReinvestScopeEntry {
	id: string;
	slug: string;
	dir: string;
	wave: number;
}

interface ReinvestScopeFile {
	parent_audit_id: string | null;
	baseline_agent_sdk: string | null;
	baseline_model: string | null;
	current_agent_sdk: string;
	scope: ReinvestScopeEntry[];
}

function isCritOrHigh(id: string): boolean {
	return /^[CH][0-9]+$/i.test(id);
}

function nextWaveNumber(findingDir: string): number {
	const re = /^wave-(\d+)-verdict\.md$/;
	let max = 1;
	for (const entry of readdirSync(findingDir)) {
		const raw = re.exec(entry)?.[1];
		if (!raw) continue;
		const n = Number.parseInt(raw, 10);
		if (n > max) max = n;
	}
	return max + 1;
}

function pickResume(cwd: string, force: boolean): AuditRunState | undefined {
	if (force) return undefined;
	const state = readAuditState(cwd).state;
	const audit = state ? latestAudit(state) : undefined;
	if (!audit) return undefined;
	if (audit.mode !== "reinvest") return undefined;
	if (audit.status === "complete") return undefined;
	return audit;
}

function setStatus(ui: PhaseUiHooks | undefined, text?: string): void {
	ui?.setStatus?.(STATUS_KEY, text);
}

function ensureWorkdir(cwd: string): void {
	mkdirSync(join(cwd, REINVEST_WORKSPACE), { recursive: true });
}

/**
 * I1 — Enumerate. Build the reinvest scope. Returns the list of in-scope
 * finding directories with their assigned wave numbers. Writes
 * `piolium/reinvest-workspace/scope.json` for downstream phases to read.
 */
function runI1(
	cwd: string,
	audit: AuditRunState,
	opts: RunReinvestOptions,
	priorAudit: AuditRunState | undefined,
	critHigh: FindingDir[],
): ReinvestScopeFile {
	const scope =
		opts.scope && opts.scope.length > 0
			? critHigh.filter((d) =>
					opts.scope?.some((requested) => requested.toUpperCase() === d.id.toUpperCase()),
				)
			: critHigh;

	const scopeFile: ReinvestScopeFile = {
		parent_audit_id: priorAudit?.audit_id ?? null,
		baseline_agent_sdk: priorAudit?.agent_sdk ?? null,
		baseline_model: priorAudit?.model ?? null,
		current_agent_sdk: audit.agent_sdk ?? "pi",
		scope: scope.map((d) => ({
			id: d.id,
			slug: d.slug,
			dir: d.path,
			wave: nextWaveNumber(d.path),
		})),
	};

	ensureWorkdir(cwd);
	writeFileSync(join(cwd, REINVEST_SCOPE_FILE), `${JSON.stringify(scopeFile, null, "\t")}\n`);
	return scopeFile;
}

function buildVerifierTask(
	cwd: string,
	entry: ReinvestScopeEntry,
	scope: ReinvestScopeFile,
	totalInScope: number,
	rank: number,
): string {
	const relDir = relative(cwd, entry.dir);
	const baseline = scope.baseline_agent_sdk
		? `${scope.baseline_agent_sdk}${scope.baseline_model ? `/${scope.baseline_model}` : ""}`
		: "(unknown prior agent)";
	return [
		`Cross-agent reinvest of \`${relDir}\`.`,
		`This is finding ${rank} of ${totalInScope} in the current reinvest wave.`,
		`Assign wave number ${entry.wave} (filename: wave-${entry.wave}-verdict.md).`,
		`You are running under \`${scope.current_agent_sdk}\` — the original verdict came from \`${baseline}\`.`,
		"",
		"Procedure:",
		"  1. Read this finding's `report.md` and the contents of `evidence/`.",
		"  2. Restate the claim independently in your own words (do not paraphrase report.md's `Trace:` block).",
		"  3. Trace from source code, not from the report's quoted snippets.",
		"  4. Look for protections that may invalidate the claim (input validation, capability checks, framework defaults, etc.).",
		"  5. If a runnable `poc.*` exists and is safely runnable in your environment, attempt reproduction.",
		"  6. ONLY AFTER forming your own view, read any prior `wave-*-verdict.md` files and explicitly acknowledge agreement or disagreement.",
		"",
		`Write \`${relDir}/wave-${entry.wave}-verdict.md\` with:`,
		"  - Verdict: CONFIRMED | DISPROVED | UNCERTAIN",
		`  - Wave-${entry.wave}-Agent: ${scope.current_agent_sdk}`,
		"  - Independent-Trace: a fresh trace from source to sink",
		"  - Protections-Considered: list each protection examined and why it does/doesn't invalidate the claim",
		"  - PoC-Attempt: command + outcome (or 'not attempted: reason')",
		"  - Agreement-With-Prior-Waves: explicit per-wave agreement/disagreement notes",
		"",
		`Also append \`Wave-${entry.wave}-Verdict:\` and \`Wave-${entry.wave}-Agent:\` lines to this finding's \`draft.md\` frontmatter (if draft.md exists).`,
		"",
		"DO NOT modify report.md, poc.*, evidence/, or any other finding directory. The original audit's artefacts are immutable in reinvest mode.",
	].join("\n");
}

/**
 * I2 — Fan-out wave-verifier across the scope (burst cap 3). Each task gets
 * one retry on failure; persistent failure is recorded in the audit-state
 * artifacts and surfaced in the I3 report's "Failed Reinvests" section.
 */
async function runI2(
	cwd: string,
	audit: AuditRunState,
	verifier: AgentDefinition | undefined,
	scope: ReinvestScopeFile,
	opts: RunReinvestOptions,
): Promise<{ completed: number; failed: string[] }> {
	if (scope.scope.length === 0) {
		await applyPhaseStatus(cwd, audit, "I2", {
			status: "skipped",
			error: "No CRIT/HIGH findings in scope; nothing to verify.",
		});
		return { completed: 0, failed: [] };
	}
	if (!verifier) {
		await applyPhaseStatus(cwd, audit, "I2", {
			status: "failed",
			error: "wave-verifier agent not found in bundled agents/.",
		});
		throw new Error("wave-verifier agent missing");
	}

	await applyPhaseStatus(cwd, audit, "I2", { status: "in_progress" });
	setStatus(opts.ui, `● I2 verifying ${scope.scope.length} finding(s)`);

	const scheduler = new Scheduler({
		maxConcurrent: REINVEST_BURST_CAP,
		...(opts.signal ? { signal: opts.signal } : {}),
	});
	const auditIdSafe = audit.audit_id.replace(/[:.]/g, "-");
	const total = scope.scope.length;
	let completed = 0;
	const failed: string[] = [];

	const updateStatus = () => {
		setStatus(
			opts.ui,
			`● I2 verifying (${completed}/${total} done${failed.length > 0 ? `, ${failed.length} failed` : ""})`,
		);
	};
	updateStatus();

	const tasks = scope.scope.map((entry, idx) => ({
		id: `reinvest-${entry.id}`,
		run: async (signal: AbortSignal) => {
			const verdictPath = join(entry.dir, `wave-${entry.wave}-verdict.md`);
			for (let attempt = 1; attempt <= 2; attempt++) {
				const runId = `i2-${auditIdSafe}-${entry.id.toLowerCase()}-a${attempt}-${randomUUID().slice(0, 8)}`;
				try {
					await runAgent({
						agent: verifier,
						task: buildVerifierTask(cwd, entry, scope, total, idx + 1),
						runId,
						runtime: {
							cwd,
							mode: "reinvest",
							phase: "I2",
							outputPaths: [entry.dir],
							notes: [
								`Finding: ${entry.id}-${entry.slug}`,
								`Wave: ${entry.wave}`,
								`Burst cap: ${REINVEST_BURST_CAP}`,
								`Baseline agent: ${scope.baseline_agent_sdk ?? "(unknown)"}`,
							],
						},
						...(opts.agentRuntime ? opts.agentRuntime : {}),
						signal,
						onEvent: (event) => opts.ui?.onAgentEvent?.("I2", event),
					});
					if (!existsSync(verdictPath)) {
						throw new Error(`wave-verifier did not write ${verdictPath}`);
					}
					completed++;
					updateStatus();
					return;
				} catch (err) {
					if (attempt === 1) {
						opts.ui?.notify?.(
							`Reinvest ${entry.id} attempt ${attempt} failed: ${errorMessage(err)}. Retrying.`,
							"warning",
						);
						continue;
					}
					failed.push(`${entry.id}: ${errorMessage(err)}`);
					updateStatus();
					return;
				}
			}
		},
	}));

	await scheduler.runBatch(tasks);
	scheduler.dispose();

	if (failed.length === total) {
		await applyPhaseStatus(cwd, audit, "I2", {
			status: "failed",
			error: `All ${total} wave-verifier tasks failed.`,
		});
	} else {
		await applyPhaseStatus(cwd, audit, "I2", {
			status: "complete",
			...(failed.length > 0
				? { error: `${failed.length}/${total} wave-verifiers failed; see report.` }
				: {}),
		});
	}
	setStatus(opts.ui, undefined);
	return { completed, failed };
}

type WaveVerdict = "CONFIRMED" | "DISPROVED" | "UNCERTAIN" | "UNKNOWN";

function parseVerdict(text: string): WaveVerdict {
	const m = /^\s*(?:Verdict|verdict)\s*:\s*([A-Z]+)/m.exec(text);
	if (!m) return "UNKNOWN";
	const v = (m[1] ?? "").toUpperCase();
	if (v === "CONFIRMED" || v === "DISPROVED" || v === "UNCERTAIN") return v;
	return "UNKNOWN";
}

interface FindingConsensus {
	id: string;
	slug: string;
	verdictsByWave: Array<{ wave: number; verdict: WaveVerdict }>;
	consensus: "stable-confirmed" | "flipped-disproved" | "mixed-uncertain" | "no-verdicts";
}

function classifyConsensus(verdicts: WaveVerdict[]): FindingConsensus["consensus"] {
	if (verdicts.length === 0) return "no-verdicts";
	if (verdicts.includes("DISPROVED")) return "flipped-disproved";
	if (verdicts.includes("UNCERTAIN") || verdicts.includes("UNKNOWN")) return "mixed-uncertain";
	if (verdicts.every((v) => v === "CONFIRMED")) return "stable-confirmed";
	return "mixed-uncertain";
}

function readFindingConsensus(entry: ReinvestScopeEntry): FindingConsensus {
	const re = /^wave-(\d+)-verdict\.md$/;
	const verdictsByWave: FindingConsensus["verdictsByWave"] = [];
	for (const file of readdirSync(entry.dir)) {
		const m = re.exec(file);
		const raw = m?.[1];
		if (!raw) continue;
		const text = readFileSync(join(entry.dir, file), "utf8");
		verdictsByWave.push({ wave: Number.parseInt(raw, 10), verdict: parseVerdict(text) });
	}
	verdictsByWave.sort((a, b) => a.wave - b.wave);
	return {
		id: entry.id,
		slug: entry.slug,
		verdictsByWave,
		consensus: classifyConsensus(verdictsByWave.map((v) => v.verdict)),
	};
}

/**
 * I3 — Walk every reinvested finding, read its wave verdicts, compute the
 * consensus, and write the delta report. Pure local logic.
 */
function runI3(
	cwd: string,
	audit: AuditRunState,
	scope: ReinvestScopeFile,
	failedFindings: string[],
): { reportPath: string; reinvested: number; flipped: number; uncertain: number } {
	const consensusList = scope.scope.map(readFindingConsensus);

	const flipped = consensusList.filter((c) => c.consensus === "flipped-disproved");
	const uncertain = consensusList.filter((c) => c.consensus === "mixed-uncertain");
	const stable = consensusList.filter((c) => c.consensus === "stable-confirmed");

	const baseline = scope.baseline_agent_sdk
		? `${scope.baseline_agent_sdk}${scope.baseline_model ? ` / ${scope.baseline_model}` : ""}`
		: "(unknown — no prior audit recorded an agent_sdk)";

	const lines: string[] = [
		"# Cross-Agent Reinvest Report",
		"",
		`**Reinvest audit_id:** ${audit.audit_id}`,
		`**Parent audit:** ${scope.parent_audit_id ?? "(none)"} (${baseline})`,
		`**Reinvest agent:** ${scope.current_agent_sdk}`,
		`**Findings reinvested:** ${consensusList.length}`,
		`**Stable confirmed:** ${stable.length}`,
		`**Flipped to disproved:** ${flipped.length}`,
		`**Mixed / uncertain:** ${uncertain.length}`,
		"",
		"## Consensus",
		"",
		"| ID | Slug | Waves | Verdicts | Consensus |",
		"| --- | --- | --- | --- | --- |",
	];
	for (const c of consensusList) {
		const waves = c.verdictsByWave.map((v) => v.wave).join(", ") || "—";
		const verdicts = c.verdictsByWave.map((v) => v.verdict).join(" → ") || "—";
		lines.push(`| ${c.id} | ${c.slug} | ${waves} | ${verdicts} | ${c.consensus} |`);
	}
	lines.push("");

	if (flipped.length > 0) {
		lines.push("## Findings That Flipped to DISPROVED", "");
		for (const c of flipped) {
			lines.push(
				`- **${c.id} ${c.slug}** — verdicts: ${c.verdictsByWave.map((v) => `wave ${v.wave}=${v.verdict}`).join(", ")}.`,
			);
		}
		lines.push("");
	}
	if (uncertain.length > 0) {
		lines.push("## Findings That Remain Uncertain", "");
		for (const c of uncertain) {
			lines.push(
				`- **${c.id} ${c.slug}** — verdicts: ${c.verdictsByWave.map((v) => `wave ${v.wave}=${v.verdict}`).join(", ")}.`,
			);
		}
		lines.push("");
	}
	if (failedFindings.length > 0) {
		lines.push("## Failed Reinvests", "");
		for (const msg of failedFindings) {
			lines.push(`- ${msg}`);
		}
		lines.push("");
	}

	const path = join(cwd, REINVEST_REPORT);
	writeFileSync(path, `${lines.join("\n").trimEnd()}\n`);
	return {
		reportPath: path,
		reinvested: consensusList.length,
		flipped: flipped.length,
		uncertain: uncertain.length,
	};
}

export async function runReinvestAudit(opts: RunReinvestOptions): Promise<RunReinvestResult> {
	const { cwd, ui } = opts;

	// Preflight: an existing audit state is required for `parent_audit_id`.
	const stateResult = readAuditState(cwd);
	if (!stateResult.exists || !stateResult.state) {
		throw new Error("Reinvest requires a prior audit. Run /piolium-deep or /piolium-balanced first.");
	}

	// Baseline = most recent non-reinvest audit; if there are only reinvests
	// recorded, fall back to the freshest entry so we still record a parent.
	const priorAudit =
		[...stateResult.state.audits]
			.sort((a, b) => (a.started_at < b.started_at ? 1 : -1))
			.find((a) => a.mode !== "reinvest") ?? latestAudit(stateResult.state);

	const critHigh = listFindingDirs(cwd).filter((d) => d.hasReport && isCritOrHigh(d.id));
	if (critHigh.length === 0) {
		throw new Error(
			"No CRITICAL or HIGH finding directories under piolium/findings/. Nothing to reinvest.",
		);
	}

	ensureWorkdir(cwd);
	let audit = pickResume(cwd, opts.forceFresh ?? false);
	if (!audit) {
		audit = await initAudit(cwd, {
			mode: "reinvest",
			...(priorAudit?.commit !== undefined ? { commit: priorAudit.commit } : {}),
			...(priorAudit?.branch !== undefined ? { branch: priorAudit.branch } : {}),
			...(priorAudit?.repository !== undefined ? { repository: priorAudit.repository } : {}),
			...(priorAudit?.history_available !== undefined
				? { history_available: priorAudit.history_available }
				: {}),
			agent_sdk: "pi",
		});
	}

	const { agents } = loadAgents({ cwd });
	const verifier = agents.get("wave-verifier");

	setStatus(ui, "● I1 enumerating CRIT/HIGH findings");
	await applyPhaseStatus(cwd, audit, "I1", { status: "in_progress" });
	let scope: ReinvestScopeFile;
	try {
		scope = runI1(cwd, audit, opts, priorAudit, critHigh);
		await applyPhaseStatus(cwd, audit, "I1", {
			status: "complete",
			artifacts: [REINVEST_SCOPE_FILE],
		});
	} catch (err) {
		await applyPhaseStatus(cwd, audit, "I1", {
			status: "failed",
			error: errorMessage(err),
		});
		await markAuditStatus(cwd, audit.audit_id, "failed");
		throw err;
	}

	if (scope.scope.length === 0) {
		ui?.notify?.(
			opts.scope && opts.scope.length > 0
				? `Reinvest scope (${opts.scope.join(", ")}) matched no CRIT/HIGH findings.`
				: "No CRITICAL or HIGH findings to reinvest.",
			"info",
		);
	}

	let failedFindings: string[] = [];
	let failedI2 = false;
	try {
		const result = await runI2(cwd, audit, verifier, scope, opts);
		failedFindings = result.failed;
	} catch (err) {
		failedI2 = true;
		ui?.notify?.(`I2 fan-out aborted: ${errorMessage(err)}`, "error");
	}

	let reportInfo: { reportPath: string; reinvested: number; flipped: number; uncertain: number };
	setStatus(ui, "● I3 computing consensus");
	await applyPhaseStatus(cwd, audit, "I3", { status: "in_progress" });
	try {
		reportInfo = runI3(cwd, audit, scope, failedFindings);
		await applyPhaseStatus(cwd, audit, "I3", {
			status: "complete",
			artifacts: [REINVEST_REPORT],
		});
	} catch (err) {
		await applyPhaseStatus(cwd, audit, "I3", {
			status: "failed",
			error: errorMessage(err),
		});
		await markAuditStatus(cwd, audit.audit_id, "failed");
		throw err;
	}
	setStatus(ui, undefined);

	const auditFailed = failedI2 || failedFindings.length > 0;
	await markAuditStatus(cwd, audit.audit_id, auditFailed ? "failed" : "complete");

	const fresh =
		readAuditState(cwd).state?.audits.find((a) => a.audit_id === audit.audit_id) ?? audit;
	const phases: Record<string, "complete" | "failed" | "skipped"> = {};
	for (const [name, p] of Object.entries(fresh.phases)) {
		if (p.status === "complete" || p.status === "failed" || p.status === "skipped") {
			phases[name] = p.status;
		}
	}

	ui?.notify?.(
		auditFailed
			? `Reinvest completed with ${failedFindings.length} failed wave-verifier(s); see ${REINVEST_REPORT}.`
			: `Reinvest complete. Report: ${REINVEST_REPORT}.`,
		auditFailed ? "warning" : "info",
	);

	return {
		auditId: audit.audit_id,
		status: auditFailed ? "failed" : "complete",
		phases,
		reportPath: reportInfo.reportPath,
		reinvestedCount: reportInfo.reinvested,
		flippedCount: reportInfo.flipped,
		uncertainCount: reportInfo.uncertain,
	};
}
