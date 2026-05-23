/**
 * Revisit mode (`/piolium-revisit`).
 *
 * Second-or-Nth pass over a completed audit, with anti-anchoring prompts.
 * Reuses existing durable `piolium/attack-surface/` context but re-runs the
 * reasoning-heavy phases:
 *
 *   R0 intent cartography (build repo-local intent corpus; soft prioritization
 *                          signal — never a gate for downstream phases)
 *   R5 deep probe (with negative-list seeded from prior findings)
 *   R7-R8 chamber rounds (anti-anchoring)
 *   R9 FP elim
 *   R10 variants
 *   R10k corner cases
 *   R11 / R11b / R11c
 *
 * MVP: each phase is a single agent run with anti-anchoring instructions
 * folded into the task prompt. R0's failure is non-blocking: subsequent
 * phases just proceed without the corpus.
 */

import { existsSync, mkdirSync, readFileSync } from "node:fs";
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
import { listFindingDirs, promoteDraftsByPrefix } from "../findings.ts";
import { runReconAsync } from "../recon.ts";
import { type PhaseUiHooks, runAgentPhase } from "./phase-runner.ts";

export interface RunRevisitOptions {
	cwd: string;
	signal?: AbortSignal;
	ui?: PhaseUiHooks;
	forceFresh?: boolean;
	agentRuntime?: AgentRuntimeModel;
}

export interface RunRevisitResult {
	auditId: string;
	status: "complete" | "failed";
	phases: Record<string, "complete" | "failed" | "skipped">;
}

const ATTACK_SURFACE_DIR = "piolium/attack-surface";
const REVISIT_TMP_DIR = "piolium/tmp/piolium/revisit";
export const REVISIT_INTENT_CORPUS = `${ATTACK_SURFACE_DIR}/intent-corpus.json`;
export const REVISIT_ATTACK_SURFACE_INVENTORY = `${ATTACK_SURFACE_DIR}/revisit-attack-surface-inventory.md`;
export const REVISIT_PROBE_SUMMARY = `${ATTACK_SURFACE_DIR}/revisit-probe-summary.md`;
export const REVISIT_R7_CHAMBER_SUMMARY = `${ATTACK_SURFACE_DIR}/revisit-r7-chamber-summary.md`;
export const REVISIT_R8_CHAMBER_SUMMARY = `${ATTACK_SURFACE_DIR}/revisit-r8-chamber-summary.md`;

function exists(cwd: string, rel: string): boolean {
	return existsSync(join(cwd, rel));
}

function pickResume(cwd: string, force: boolean): AuditRunState | undefined {
	if (force) return undefined;
	const state = readAuditState(cwd).state;
	const audit = state ? latestAudit(state) : undefined;
	if (!audit) return undefined;
	if (audit.mode !== "revisit") return undefined;
	if (audit.status === "complete") return undefined;
	return audit;
}

const ANTI_ANCHOR_PREAMBLE = [
	"REVISIT MODE — anti-anchoring rules:",
	"  - Do NOT reuse prior conclusions. Treat existing findings/ as a NEGATIVE LIST: do not re-surface them.",
	"  - Re-derive hypotheses from primary sources (code, advisories, KB) — don't copy from prior reports.",
	"  - Severity should be re-assessed independently.",
].join("\n");

function priorFindingNegatives(cwd: string): string {
	const dirs = listFindingDirs(cwd);
	if (dirs.length === 0) return "(no prior findings recorded)";
	return dirs.map((d) => `  - ${d.id} ${d.slug}`).join("\n");
}

function buildTask(phase: string, cwd: string): string {
	const negatives = priorFindingNegatives(cwd);
	switch (phase) {
		case "R0":
			return [
				"Run Phase R0 (Intent Cartography) of /piolium-revisit.",
				"Scan the target repository for documented security intent: SECURITY.md, README security sections, docs/security/, threat-model files, inline `#security:` / `// security:` pragmas.",
				"Produce a structured corpus with two lists: `intentional_behaviors[]` (project-declared safe-by-design behaviors) and `acknowledged_risks[]` (vuln classes the project explicitly considers in scope).",
				`Output: \`${REVISIT_INTENT_CORPUS}\`. Always overwrite — the corpus is rebuilt per revisit round so doc changes between rounds are reflected.`,
				"No findings cross-check is required in this mode (unlike confirm V1.5). Build the corpus only.",
				"If the repo has no security docs, write an empty `{intentional_behaviors: [], acknowledged_risks: []}` corpus; downstream phases tolerate emptiness.",
				"Note for downstream phases: the corpus is a SOFT priority hint — `intentional_behaviors[]` is a defense argument cold-verifier / devils-advocate may cite but never a gate; `acknowledged_risks[]` lets probe-strategist push harder on listed classes but never excludes classes that are absent.",
			].join("\n");
		case "R5":
			return [
				ANTI_ANCHOR_PREAMBLE,
				"",
				"Run a fresh Deep Probe pass for /piolium-revisit.",
				"Negative list (do NOT re-surface):",
				negatives,
				`Read the durable prior attack-surface corpus from \`${ATTACK_SURFACE_DIR}/\`, including candidates-summary.md, candidates.jsonl, the KB, route/authz matrix, source/sink flows, probe summary, and cross-service edges when present.`,
				`Write updated reusable attack-surface inventory to \`${REVISIT_ATTACK_SURFACE_INVENTORY}\`.`,
				`Write the probe execution summary to \`${REVISIT_PROBE_SUMMARY}\`.`,
				`Transient workspace, if needed: ${REVISIT_TMP_DIR}/r5/.`,
				"Drafts: piolium/findings-draft/r5-NNN-<slug>.md",
			].join("\n");
		case "R7":
		case "R8": {
			const chamberSummary = phase === "R7" ? REVISIT_R7_CHAMBER_SUMMARY : REVISIT_R8_CHAMBER_SUMMARY;
			return [
				ANTI_ANCHOR_PREAMBLE,
				`Run Phase ${phase} (Review Chamber) for /piolium-revisit.`,
				"Negative list:",
				negatives,
				`Read \`${ATTACK_SURFACE_DIR}/\` first so chamber decisions reference current candidate files, routes, sources, sinks, and trust boundaries.`,
				`Transient workspace: ${REVISIT_TMP_DIR}/${phase.toLowerCase()}/`,
				`Durable chamber summary: ${chamberSummary}`,
				`Surviving drafts: piolium/findings-draft/${phase.toLowerCase()}-NNN-<slug>.md`,
			].join("\n");
		}
		case "R9":
			return [
				ANTI_ANCHOR_PREAMBLE,
				"Run Phase R9 (FP Elimination) on every revisit-stage draft. Reject anything weakly grounded.",
			].join("\n");
		case "R10":
			return [
				ANTI_ANCHOR_PREAMBLE,
				"Run Phase R10 (Variant Analysis). Drafts: piolium/findings-draft/r10-NNN-<slug>.md",
			].join("\n");
		case "R10k":
			return [
				ANTI_ANCHOR_PREAMBLE,
				"Run Phase R10k (Corner Cases). Surface edge cases that prior passes likely missed.",
			].join("\n");
		case "R11":
			return [
				ANTI_ANCHOR_PREAMBLE,
				"Run Phase R11 (PoC) for each revisit-stage finding. Build PoCs and evidence.",
			].join("\n");
		case "R11b":
			return [
				ANTI_ANCHOR_PREAMBLE,
				"Run Phase R11b (Finding Finalisation) on revisit-stage findings.",
			].join("\n");
		case "R11c":
			return [
				ANTI_ANCHOR_PREAMBLE,
				"Run Phase R11c (Final Report). Append a `## Discoveries by Round` section to piolium/final-audit-report.md describing what each round added.",
			].join("\n");
		default:
			return `Unknown revisit phase: ${phase}`;
	}
}

function gateFor(phase: string, cwd: string): () => boolean {
	switch (phase) {
		case "R0":
			return () => exists(cwd, REVISIT_INTENT_CORPUS);
		case "R5":
			return () => exists(cwd, REVISIT_PROBE_SUMMARY);
		case "R7":
			return () => exists(cwd, REVISIT_R7_CHAMBER_SUMMARY);
		case "R8":
			return () => exists(cwd, REVISIT_R8_CHAMBER_SUMMARY);
		case "R9":
			return () => true;
		case "R10":
			return () => true;
		case "R10k":
			return () => true;
		case "R11":
		case "R11b":
			return () => true;
		case "R11c":
			return () => {
				const path = join(cwd, "piolium/final-audit-report.md");
				if (!existsSync(path)) return false;
				return readFileSync(path, "utf8").includes("Discoveries by Round");
			};
		default:
			return () => true;
	}
}

export async function runRevisitAudit(opts: RunRevisitOptions): Promise<RunRevisitResult> {
	const { cwd, signal, ui } = opts;
	ui?.setStatus?.("piolium-revisit", "● preparing recon");
	const recon = await runReconAsync(cwd, { signal });
	mkdirSync(join(cwd, ATTACK_SURFACE_DIR), { recursive: true });
	ui?.setStatus?.("piolium-revisit", "● scanning candidate files");
	const candidateScan = await runCandidateScanAsync(cwd, { signal });
	ui?.notify?.(
		`Candidate scan: ${candidateScan.candidateCount} match(es) across ${candidateScan.candidateFiles} file(s).`,
		"info",
	);
	mkdirSync(join(cwd, REVISIT_TMP_DIR), { recursive: true });
	let audit = pickResume(cwd, opts.forceFresh ?? false);
	if (!audit) {
		audit = await initAudit(cwd, {
			mode: "revisit",
			...(recon.commit ? { commit: recon.commit } : { commit: null }),
			...(recon.branch ? { branch: recon.branch } : { branch: "nogit" }),
			...(recon.repository ? { repository: recon.repository } : {}),
			history_available: recon.historyAvailable,
			agent_sdk: "pi",
		});
	}

	const { agents } = loadAgents({ cwd });
	const phaseAgents = {
		R0: agents.get("intent-cartographer"),
		R5: agents.get("probe-strategist"),
		R7: agents.get("chamber-synthesizer"),
		R8: agents.get("chamber-synthesizer"),
		R9: agents.get("cold-verifier"),
		R10: agents.get("variant-hunter"),
		R10k: agents.get("variant-hunter"),
		R11: agents.get("poc-builder"),
		R11b: agents.get("finding-reporter"),
		R11c: agents.get("report-assembler"),
	};

	let failed = false;
	for (const name of ["R0", "R5", "R7", "R8", "R9", "R10", "R10k", "R11", "R11b", "R11c"] as const) {
		try {
			await runAgentPhase({
				cwd,
				audit,
				phaseName: name,
				statusKey: "piolium-revisit",
				statusLabel: `● ${name}`,
				agent: phaseAgents[name],
				missingAgentMessage: `agent missing for ${name}`,
				task: buildTask(name, cwd),
				gate: gateFor(name, cwd),
				mode: "revisit",
				ui,
				agentRuntime: opts.agentRuntime,
				...(signal ? { signal } : {}),
			});
			// Promote drafts surfaced in chamber rounds.
			if (name === "R7") promoteDraftsByPrefix(cwd, "r7-");
			if (name === "R8") promoteDraftsByPrefix(cwd, "r8-");
			if (name === "R10") promoteDraftsByPrefix(cwd, "r10-");
		} catch {
			// R0 is a soft prioritization signal — its failure is non-blocking
			// per the intent-cartographer's skip-and-continue contract. Every
			// other phase is load-bearing for revisit's output, so we abort.
			if (name === "R0") {
				ui?.notify?.("R0 intent cartography failed; continuing revisit without the corpus.", "warning");
				continue;
			}
			failed = true;
			break;
		}
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
	ui?.notify?.(failed ? "Revisit failed." : "Revisit complete.", failed ? "error" : "info");
	return { auditId: audit.audit_id, status: failed ? "failed" : "complete", phases };
}
