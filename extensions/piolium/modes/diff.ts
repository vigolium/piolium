/**
 * Diff mode (`/piolium-diff`).
 *
 * Re-audit only what's changed since the last audited commit. Conservative
 * MVP: if the prior audit isn't found / completed, ask the user to run
 * balanced first. If the change set is too broad, recommend rerunning
 * balanced or deep.
 *
 * Otherwise, run a focused balanced-style pipeline limited to changed
 * files. Implementation is a single agent run with the static-analyzer
 * agent and a tightly scoped task prompt.
 */

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import type { AgentRuntimeModel } from "../agent-runner.ts";
import { loadAgents } from "../agents.ts";
import {
	type AuditRunState,
	initAudit,
	latestAudit,
	markAuditStatus,
	readAuditState,
} from "../audit-state.ts";
import { runCandidateScanAsync } from "../candidate-scan.ts";
import { runReconAsync } from "../recon.ts";
import { type PhaseUiHooks, runAgentPhase } from "./phase-runner.ts";

export interface RunDiffOptions {
	cwd: string;
	signal?: AbortSignal;
	ui?: PhaseUiHooks;
	agentRuntime?: AgentRuntimeModel;
	/** Compare against this commit instead of the prior audited commit. */
	since?: string;
	/** Hard limit on changed files; abort with guidance if exceeded. Default 200. */
	maxChangedFiles?: number;
}

export interface RunDiffResult {
	auditId?: string;
	status: "complete" | "failed" | "skipped";
	changedFiles: string[];
	priorCommit?: string;
}

export const DIFF_ATTACK_SURFACE_DIR = "piolium/attack-surface";
export const DIFF_SUMMARY = `${DIFF_ATTACK_SURFACE_DIR}/diff-summary.md`;

function safeExec(file: string, args: string[], cwd: string): string | undefined {
	try {
		return execFileSync(file, args, {
			cwd,
			encoding: "utf8",
			stdio: ["ignore", "pipe", "ignore"],
			maxBuffer: 32 * 1024 * 1024,
		}).trim();
	} catch {
		return undefined;
	}
}

function findPriorCommit(state: AuditRunState | undefined, override?: string): string | undefined {
	if (override) return override;
	if (!state) return undefined;
	if (state.status !== "complete") return undefined;
	if (!state.commit) return undefined;
	return state.commit;
}

export async function runDiffAudit(opts: RunDiffOptions): Promise<RunDiffResult> {
	const { cwd, signal, ui } = opts;
	ui?.setStatus?.("piolium-diff", "● preparing recon");
	const recon = await runReconAsync(cwd, { signal });
	mkdirSync(join(cwd, DIFF_ATTACK_SURFACE_DIR), { recursive: true });
	ui?.setStatus?.("piolium-diff", "● scanning candidate files");
	const candidateScan = await runCandidateScanAsync(cwd, { signal });
	ui?.notify?.(
		`Candidate scan: ${candidateScan.candidateCount} match(es) across ${candidateScan.candidateFiles} file(s).`,
		"info",
	);
	if (!recon.historyAvailable) {
		ui?.notify?.(
			"Diff mode requires git history. Run /piolium-balanced or /piolium-deep instead.",
			"warning",
		);
		return { status: "skipped", changedFiles: [] };
	}

	const stateFile = readAuditState(cwd).state;
	const prior = findPriorCommit(stateFile ? latestAudit(stateFile) : undefined, opts.since);
	if (!prior) {
		ui?.notify?.(
			"No completed prior audit found. Run /piolium-balanced or /piolium-deep first, then come back.",
			"warning",
		);
		return { status: "skipped", changedFiles: [] };
	}

	const diff = safeExec("git", ["diff", "--name-only", `${prior}...HEAD`], cwd);
	if (diff === undefined) {
		ui?.notify?.(`git diff against ${prior} failed.`, "error");
		return { status: "failed", changedFiles: [], priorCommit: prior };
	}
	const changedFiles = diff.split("\n").filter(Boolean);
	const cap = opts.maxChangedFiles ?? 200;
	if (changedFiles.length > cap) {
		ui?.notify?.(
			`${changedFiles.length} files changed since ${prior.slice(0, 10)} — too broad for diff mode. Run /piolium-balanced.`,
			"warning",
		);
		return { status: "skipped", changedFiles, priorCommit: prior };
	}
	if (changedFiles.length === 0) {
		ui?.notify?.(`No code changes since ${prior.slice(0, 10)}. Diff mode has nothing to do.`, "info");
		return { status: "skipped", changedFiles, priorCommit: prior };
	}

	const audit = await initAudit(cwd, {
		mode: "diff",
		commit: recon.commit ?? null,
		...(recon.branch ? { branch: recon.branch } : {}),
		...(recon.repository ? { repository: recon.repository } : {}),
		history_available: recon.historyAvailable,
		agent_sdk: "pi",
		phases: ["D1"],
	});

	const { agents } = loadAgents({ cwd });
	const staticAnalyzer = agents.get("static-analyzer");

	let failed = false;
	try {
		await runAgentPhase({
			cwd,
			audit,
			phaseName: "D1",
			statusKey: "piolium-diff",
			statusLabel: "● diff scan",
			agent: staticAnalyzer,
			missingAgentMessage: "static-analyzer missing",
			task: [
				"You are running /piolium-diff against a previously-audited repository.",
				`Prior commit: ${prior}`,
				`Current commit: ${recon.commit ?? "(unknown)"}`,
				"",
				"Changed files:",
				...changedFiles.map((f) => `  - ${f}`),
				"",
				"Read prior durable context from `piolium/attack-surface/` when present, especially `candidates-summary.md`, `candidates.jsonl`, `knowledge-base-report.md`, `architecture-entrypoints.md`, `source-sink-flows-all-severities.md`, and `manual-attack-surface-inventory.md`.",
				"",
				"Steps:",
				"  1. Read the diff (`git diff PRIOR...HEAD -- <file>`) for each changed file.",
				"  2. Apply the same patterns as Phase L3/P4 (command injection, SSRF, authn/z, race conditions, etc.) but ONLY against the changed regions and their immediate callers.",
				"  3. Surface drafts to `piolium/findings-draft/diff-NNN-<slug>.md`.",
				`  4. Write a durable changed-attack-surface summary to \`${DIFF_SUMMARY}\` listing changed files, scope decisions, touched routes/sources/sinks, and finding pointers.`,
			].join("\n"),
			gate: () => existsSync(join(cwd, DIFF_SUMMARY)),
			mode: "diff",
			ui,
			agentRuntime: opts.agentRuntime,
			...(signal ? { signal } : {}),
		});
	} catch {
		failed = true;
	}

	await markAuditStatus(cwd, audit.audit_id, failed ? "failed" : "complete");
	ui?.notify?.(failed ? "Diff mode failed." : "Diff mode complete.", failed ? "error" : "info");
	return {
		auditId: audit.audit_id,
		status: failed ? "failed" : "complete",
		changedFiles,
		priorCommit: prior,
	};
}
