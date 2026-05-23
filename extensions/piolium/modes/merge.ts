/**
 * Merge mode (`/piolium-merge`).
 *
 * Combines multiple `piolium/` result trees into one. Two stages:
 *
 *   M1    (deterministic): copy each source's findings + attack-surface into
 *                          the workspace under per-source aliases.
 *   M2-M7 (agent-driven):  semantic dedup + auto-fix + quarantine + renumber +
 *                          apply rename + final report.
 *
 * MVP scope:
 *   - The deterministic stage (M1) is fully implemented in TypeScript here.
 *   - The agent-driven stage runs as a single chamber-synthesizer pass with a
 *     long task prompt covering all of M2-M7. That pass runs under phase M2;
 *     M3-M7 are stamped to match the work it performs so a `complete` audit
 *     never leaves merge phases stuck in `pending`.
 *
 * Each input directory is identified by an alias (`a`, `b`, ...) that gets
 * prepended to colliding finding ids so the dedup agent has clean inputs.
 */

import { cpSync, existsSync, mkdirSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import type { AgentRuntimeModel } from "../agent-runner.ts";
import { loadAgents } from "../agents.ts";
import { applyPhaseStatus, initAudit, markAuditStatus } from "../audit-state.ts";
import { runReconAsync } from "../recon.ts";
import { type PhaseUiHooks, runAgentPhase } from "./phase-runner.ts";

export interface RunMergeOptions {
	cwd: string;
	/** Source `piolium/` trees to merge. Must be ≥2. */
	sources: string[];
	signal?: AbortSignal;
	ui?: PhaseUiHooks;
	agentRuntime?: AgentRuntimeModel;
}

export interface RunMergeResult {
	auditId: string;
	status: "complete" | "failed";
	mergedFindings: string[];
}

const ATTACK_SURFACE_DIR = "piolium/attack-surface";
export const MERGE_ATTACK_SURFACE_SUMMARY = `${ATTACK_SURFACE_DIR}/merge-summary.md`;

function aliasFor(index: number): string {
	return String.fromCharCode("a".charCodeAt(0) + index);
}

function copyTree(src: string, dest: string): void {
	cpSync(src, dest, { recursive: true });
}

function copyFindings(src: string, dest: string, alias: string): string[] {
	const srcFindings = join(src, "findings");
	if (!existsSync(srcFindings)) return [];
	const destFindings = join(dest, "findings");
	mkdirSync(destFindings, { recursive: true });
	const written: string[] = [];
	for (const entry of readdirSync(srcFindings)) {
		const srcDir = join(srcFindings, entry);
		if (!statSync(srcDir).isDirectory()) continue;
		const renamed = `${alias}-${entry}`;
		const destDir = join(destFindings, renamed);
		if (existsSync(destDir)) continue; // shouldn't happen with alias prefix
		mkdirSync(destDir, { recursive: true });
		copyTree(srcDir, destDir);
		written.push(destDir);
	}
	return written;
}

function copyAttackSurface(src: string, dest: string, alias: string): string | undefined {
	const srcAttackSurface = join(src, "attack-surface");
	if (!existsSync(srcAttackSurface)) return undefined;
	const destRoot = join(dest, "attack-surface");
	mkdirSync(destRoot, { recursive: true });
	const destAttackSurface = join(destRoot, alias);
	if (existsSync(destAttackSurface)) return destAttackSurface;
	copyTree(srcAttackSurface, destAttackSurface);
	return destAttackSurface;
}

export async function runMergeAudit(opts: RunMergeOptions): Promise<RunMergeResult> {
	const { cwd, signal, ui } = opts;
	if (opts.sources.length < 2) {
		throw new Error("Merge requires at least two source piolium/ trees.");
	}

	ui?.setStatus?.("piolium-merge", "● preparing recon");
	const recon = await runReconAsync(cwd, { signal });
	const audit = await initAudit(cwd, {
		mode: "merge",
		...(recon.commit ? { commit: recon.commit } : { commit: null }),
		...(recon.branch ? { branch: recon.branch } : { branch: "nogit" }),
		...(recon.repository ? { repository: recon.repository } : {}),
		history_available: recon.historyAvailable,
		agent_sdk: "pi",
	});

	const workspace = join(cwd, "piolium", "merge-workspace");
	mkdirSync(workspace, { recursive: true });
	mkdirSync(join(cwd, ATTACK_SURFACE_DIR), { recursive: true });

	// M1: copy each source's findings/ and attack-surface/ into the workspace under aliases.
	const merged: string[] = [];
	const attackSurfaceSnapshots: Record<string, string> = {};
	const aliasMap: Record<string, string> = {};
	for (let i = 0; i < opts.sources.length; i++) {
		const src = opts.sources[i];
		if (!src) continue;
		const alias = aliasFor(i);
		aliasMap[alias] = src;
		const written = copyFindings(src, workspace, alias);
		merged.push(...written);
		const attackSurface = copyAttackSurface(src, workspace, alias);
		if (attackSurface) attackSurfaceSnapshots[alias] = attackSurface;
	}
	writeFileSync(
		join(workspace, "findings-index.json"),
		`${JSON.stringify({ aliasMap, merged: merged.map((p) => basename(p)) }, null, "\t")}\n`,
	);
	writeFileSync(
		join(workspace, "attack-surface-index.json"),
		`${JSON.stringify(
			{
				aliasMap,
				attackSurfaceSnapshots: Object.fromEntries(
					Object.entries(attackSurfaceSnapshots).map(([alias, path]) => [alias, basename(path)]),
				),
			},
			null,
			"\t",
		)}\n`,
	);

	// M1 (the deterministic copy above) is complete once the workspace and
	// index files exist.
	await applyPhaseStatus(cwd, audit, "M1", { status: "complete" });

	// M2-M7: agent-driven semantic dedup + renumber + final report.
	const { agents } = loadAgents({ cwd });
	const synth = agents.get("chamber-synthesizer");

	const task = [
		"You are running /piolium-merge: combining multiple piolium/ result trees into one canonical piolium/ output.",
		"",
		`Workspace: ${workspace}`,
		"Each finding directory there is named `<alias>-<original-id>-<slug>` (alias = a/b/c... per source).",
		"Each source attack-surface corpus, when present, is copied under `merge-workspace/attack-surface/<alias>/`.",
		`Source map (alias → path):\n${Object.entries(aliasMap)
			.map(([k, v]) => `  ${k}: ${v}`)
			.join("\n")}`,
		"",
		"Steps:",
		"  M2 — semantic dedup: identify findings that describe the same root cause across aliases. Decide canonical winner. Record decisions in `merge-workspace/dedup-decisions.json`.",
		"  M3 — auto-fix: repair frontmatter, malformed PoC JSON, naming violations.",
		"  M4 — quarantine: move unfixable findings to `piolium/quarantine/<orig-id>-<slug>/QUARANTINE.md` with reason.",
		"  M5 — renumber: assign deterministic IDs by severity (M-001 critical … M-NNN info). Write `merge-workspace/rename-map.json`.",
		"  M6 — apply rename: rename surviving finding directories under `piolium/findings/` and rewrite per-report internal links.",
		`  M7 — merge durable source context into \`${MERGE_ATTACK_SURFACE_SUMMARY}\`, then regenerate \`piolium/final-audit-report.md\` from the merged findings with an Attack Surface Summary linking \`${ATTACK_SURFACE_DIR}/\`.`,
		"",
		"Cap surviving findings at 60. Quality > quantity.",
	].join("\n");

	// The single chamber-synthesizer pass performs M2-M7; it runs under M2 and
	// M3-M7 are stamped to mirror its outcome.
	const downstreamPhases = ["M3", "M4", "M5", "M6", "M7"] as const;
	let failed = false;
	try {
		await runAgentPhase({
			cwd,
			audit,
			phaseName: "M2",
			statusKey: "piolium-merge",
			statusLabel: "● merge dedup",
			agent: synth,
			missingAgentMessage: "chamber-synthesizer missing",
			task,
			gate: () =>
				existsSync(join(cwd, "piolium/final-audit-report.md")) &&
				existsSync(join(cwd, MERGE_ATTACK_SURFACE_SUMMARY)),
			mode: "merge",
			ui,
			agentRuntime: opts.agentRuntime,
			...(signal ? { signal } : {}),
		});
		// The pass covered the remaining stages too.
		for (const phase of downstreamPhases) {
			await applyPhaseStatus(cwd, audit, phase, { status: "complete" });
		}
	} catch {
		failed = true;
		// M2 was marked failed by runAgentPhase; the later stages never ran.
		for (const phase of downstreamPhases) {
			if (audit.phases[phase]?.status !== "complete") {
				await applyPhaseStatus(cwd, audit, phase, { status: "skipped" });
			}
		}
	}

	await markAuditStatus(cwd, audit.audit_id, failed ? "failed" : "complete");
	ui?.notify?.(failed ? "Merge failed." : "Merge complete.", failed ? "error" : "info");
	return { auditId: audit.audit_id, status: failed ? "failed" : "complete", mergedFindings: merged };
}
