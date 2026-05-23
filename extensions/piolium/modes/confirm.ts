/**
 * Confirm mode (`/piolium-confirm`).
 *
 * Verification pass over an already-completed audit. Eight phases:
 *
 *   V1   inventory          (env-detective surveys findings)
 *   V1.5 intent cross-check (intent-cartographer cross-references findings against repo-local
 *                            SECURITY.md / threat models; annotates `Documented-Intent` on each
 *                            finding's draft — never overrides Severity-Final or skips PoC)
 *   V2   env discovery      (env-detective probes target environment)
 *   V3   provisioner        (env-provisioner sets up exploit targets)
 *   V4   PoC executor       (poc-executor actually runs PoCs)
 *   V5   test mapper        (test-mapper maps PoCs onto unit tests when runtime is unavailable)
 *   V6   reporter           (confirm-reporter writes piolium/confirmation-report.md)
 *   V7   cleanup            (deterministic cleanup, redaction, and format checks)
 *
 * MVP simplification: V1-V6 are one agent run each, then V7 runs deterministic
 * local cleanup. No real Docker/VM provisioning is built into the orchestrator;
 * the env-provisioner agent's own prompt covers that and writes
 * `piolium/confirm-workspace/env-connection.json`.
 */

import {
	existsSync,
	mkdirSync,
	readFileSync,
	readdirSync,
	renameSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { basename, extname, join } from "node:path";
import type { AgentRuntimeModel } from "../agent-runner.ts";
import { loadAgents } from "../agents.ts";
import {
	type AuditRunState,
	applyPhaseStatus,
	initAudit,
	latestAudit,
	markAuditStatus,
	readAuditState,
} from "../audit-state.ts";
import { runReconAsync } from "../recon.ts";
import { errorMessage } from "../retry.ts";
import { type PhaseUiHooks, runAgentPhase } from "./phase-runner.ts";

export interface RunConfirmOptions {
	cwd: string;
	signal?: AbortSignal;
	ui?: PhaseUiHooks;
	forceFresh?: boolean;
	agentRuntime?: AgentRuntimeModel;
	/** Optional remote URL (e.g. https://target.example.com) — bypasses local provisioning. */
	target?: string;
}

export interface RunConfirmResult {
	auditId: string;
	status: "complete" | "failed";
	phases: Record<string, "complete" | "failed" | "skipped">;
}

export const CONFIRM_WORKSPACE = "piolium/confirm-workspace";
export const CONFIRM_REPORT = "piolium/confirmation-report.md";
const WORK = CONFIRM_WORKSPACE;
const REPORT = CONFIRM_REPORT;
export const POC_RESULTS = `${WORK}/poc-results.json`;
export const INTENT_CORPUS = `${WORK}/intent-corpus.json`;
const FP_RENAMES = `${WORK}/false-positive-renames.json`;
export const CLEANUP_SUMMARY = `${WORK}/cleanup-summary.json`;
const MAX_REDACTABLE_BYTES = 5 * 1024 * 1024;

export const CONFIRM_AGENT_PHASES = ["V1", "V1.5", "V2", "V3", "V4", "V5", "V6"] as const;
const CONFIRM_PHASES = [...CONFIRM_AGENT_PHASES, "V7"] as const;

const TEXT_EXTENSIONS = new Set([
	".csv",
	".curl",
	".env",
	".err",
	".html",
	".http",
	".java",
	".js",
	".json",
	".jsonl",
	".jsx",
	".log",
	".md",
	".out",
	".php",
	".py",
	".rb",
	".rs",
	".sh",
	".stderr",
	".stdout",
	".ts",
	".tsx",
	".tsv",
	".txt",
	".xml",
	".yaml",
	".yml",
]);
const TEXT_BASENAMES = new Set([".env", "Dockerfile", "Makefile"]);

const SECRET_KEY_NAMES =
	"api[_-]?key|apikey|secret(?:[_-]?key)?|secretaccesskey|access[_-]?key(?:[_-]?id)?|accesskeyid|token|access[_-]?token|accesstoken|refresh[_-]?token|refreshtoken|password|passwd|pwd|client[_-]?secret|clientsecret|private[_-]?key|privatekey|session[_-]?id|sessionid|database[_-]?url|db[_-]?url|redis[_-]?url|mongo(?:db)?[_-]?url|mysql[_-]?url|postgres(?:ql)?[_-]?url|dsn";
const SECRET_VALUE_RE = new RegExp(
	`((?:["']?\\b(?:${SECRET_KEY_NAMES})\\b["']?\\s*[:=]\\s*)(["']?))([^"'\\s,}\\]]{8,})(\\2)`,
	"gi",
);
const SECRET_QUERY_RE = new RegExp(`([?&](?:${SECRET_KEY_NAMES}|key)=)([^&#\\s]+)`, "gi");

function exists(cwd: string, rel: string): boolean {
	return existsSync(join(cwd, rel));
}

export function ensureConfirmWorkdir(cwd: string): void {
	mkdirSync(join(cwd, WORK), { recursive: true });
}

export function findingDirsWithReports(cwd: string): string[] {
	const root = join(cwd, "piolium", "findings");
	if (!existsSync(root)) return [];
	return readdirSync(root)
		.map((entry) => join(root, entry))
		.filter((path) => {
			try {
				return statSync(path).isDirectory() && existsSync(join(path, "report.md"));
			} catch {
				return false;
			}
		})
		.sort();
}

function pickResume(cwd: string, force: boolean): AuditRunState | undefined {
	if (force) return undefined;
	const state = readAuditState(cwd).state;
	const audit = state ? latestAudit(state) : undefined;
	if (!audit) return undefined;
	if (audit.mode !== "confirm") return undefined;
	if (audit.status === "complete") return undefined;
	return audit;
}

const CONFIRMATION_STANDARD = [
	"Confirmation standard (strict):",
	"- Prefer live exploit execution over assertion-only review.",
	"- A confirmed finding needs observable proof: exact command, request/response, before/after state, or stack trace.",
	"- Write evidence under each finding's `evidence/` directory; include enough detail for replay.",
	"- Do not mark confirmed from code plausibility alone.",
	"- Mark `Confirm-Status: false-positive` only when real execution or a targeted reproducer proves the claimed exploit path is blocked, unreachable, or contradicted by code/runtime behavior.",
	"- If evidence is incomplete, use `blocked`, `inconclusive`, or `unconfirmed` instead of false-positive.",
].join("\n");

export function buildConfirmTask(phase: string, target: string | undefined): string {
	const targetLine = target
		? `Target is REMOTE: ${target}. Skip local Docker/VM provisioning; treat the URL as already-running.`
		: "Target is LOCAL — provision via Docker/VM if necessary.";
	switch (phase) {
		case "V1":
			return [
				"You are running V1 (Findings Inventory) of /piolium-confirm.",
				"Read every `report.md` under `piolium/findings/` and treat it as the source of truth.",
				"Extract: id, slug, severity, vulnerability class, title, PoC script path, Protocol, Auth-Required, and existing Confirm-* fields.",
				"Classify each finding as `network-exploitable`, `local-exploitable`, or `non-exploitable`. When unsure, default to network-exploitable so V4 gets a chance.",
				`Write \`${WORK}/findings-inventory.json\` with totals by severity/class and one object per finding.`,
				targetLine,
				CONFIRMATION_STANDARD,
			].join("\n\n");
		case "V1.5":
			return [
				"You are running V1.5 (Intent Cross-Check) of /piolium-confirm.",
				"Build an intent corpus from repo-local security documentation (SECURITY.md, README security sections, docs/security/, threat-model files, inline `#security:` / `// security:` pragmas).",
				"Produce two lists per the intent-cartographer spec: `intentional_behaviors[]` (project-declared safe-by-design behaviors) and `acknowledged_risks[]` (project-acknowledged risks that may still appear as findings).",
				`Write the structured corpus to \`${INTENT_CORPUS}\`.`,
				"Then cross-check every finding in `piolium/findings/`:",
				"  - If a finding overlaps an `intentional_behavior`, append `Documented-Intent: matched` to its `draft.md` frontmatter (or `report.md` if no draft).",
				"  - If a finding partially overlaps (same class, different code path), append `Documented-Intent: partial`.",
				"  - Otherwise, append `Documented-Intent: no-match`.",
				"This phase is annotate-only — NEVER overwrite Severity-Final, never short-circuit later V-phases, and never skip PoC for a `matched` finding. The annotation is a hint for the reporter (V6), not a verdict.",
				"Cold-verifier-style independence is not required here; reading prior verdicts and severity is allowed.",
				targetLine,
				CONFIRMATION_STANDARD,
			].join("\n\n");
		case "V2":
			return [
				"You are running V2 (Environment Discovery) of /piolium-confirm.",
				"Detect exact startup strategies, framework, ports, required env vars, datastores, migrations, seed data, and test framework.",
				"If auth is present, write `piolium/confirm-workspace/auth-spec.json` describing how to create low-privileged and privileged test identities.",
				`Write \`${WORK}/env-strategies.json\` ranked from most reliable to fallback.`,
				targetLine,
				CONFIRMATION_STANDARD,
			].join("\n\n");
		case "V3":
			return [
				"You are running V3 (Environment Provisioning) of /piolium-confirm.",
				"Stand up the target if local using env-strategies.json. Prefer the repo's own docker-compose, Makefile, package scripts, or test server.",
				"Seed test identities from auth-spec.json if present and write usable credentials/tokens to env-connection.json.",
				"Write `piolium/confirm-workspace/env-connection.json` with `{status, base_url, test_identities?, cleanup_cmd, session}`.",
				"On failure, write `piolium/confirm-workspace/healthcheck-failure.log` with the last relevant app/container logs and exit cleanly.",
				targetLine,
				CONFIRMATION_STANDARD,
			].join("\n\n");
		case "V4":
			return [
				"You are running V4 (PoC Execution) of /piolium-confirm.",
				"Read findings-inventory.json and env-connection.json. Skip non-exploitable findings as `Confirm-Status: analytical-only`; route local-only findings to V5.",
				"Before per-finding execution, run one reachability check against base_url with a 5s timeout; if unreachable, mark queued network findings `blocked` and record the reason.",
				"For every network-exploitable finding with a PoC, execute the real PoC against the target. Use a 30s timeout per variant, max 2 variants.",
				"Capture exact command, relevant env, HTTP request/response or stdout/stderr, and observable before/after state to `<finding-dir>/evidence/confirmed-<timestamp>.log`.",
				"Parse structured PoC output if present: final JSON line `{status,evidence,notes}`.",
				"Update each `report.md` with `Confirm-Status: confirmed-live | failed | blocked | analytical-only | false-positive` and `Confirm-Evidence:` pointing at the evidence file.",
				`Write aggregate results to \`${POC_RESULTS}\`.`,
				CONFIRMATION_STANDARD,
			].join("\n\n");
		case "V5":
			return [
				"You are running V5 (Test Mapper) of /piolium-confirm.",
				"For findings whose live PoC did not confirm, had no PoC, or are local-exploitable, generate the smallest reproducer test in the existing test framework.",
				"Actually run the test with a 60s cap (pytest timeout, jest --testTimeout, go test -timeout, etc.).",
				"Keep reproducer files/evidence under each finding dir and write command/output logs under `evidence/`.",
				"Update `report.md`: `Confirm-Status: confirmed-test | failed | blocked | false-positive` and `Confirm-Evidence:`.",
				"Only mark `false-positive` when the reproducer proves the claimed vulnerable path is unreachable, patched, protected, or based on an invalid assumption.",
				`Write \`${WORK}/test-mapping.json\` with per-finding verdicts and evidence pointers.`,
				CONFIRMATION_STANDARD,
			].join("\n\n");
		case "V6":
			return [
				"You are running V6 (Confirmation Report) of /piolium-confirm.",
				"Read `piolium/findings/`, including any directories renamed with `FP-` after V5.",
				`Compose \`${REPORT}\` with: confirmed-live, confirmed-test, analytical-only, blocked, inconclusive/unconfirmed, and false-positive counts.`,
				"Include one line per finding with status, evidence pointer, and reproduction command summary.",
				"Create a dedicated false-positive section listing every `FP-*` directory and the evidence that disproved it.",
				"Include environment setup notes, target URL/base_url, cleanup result, and methodology.",
			].join("\n\n");
		default:
			return "Unknown V phase.";
	}
}

export function confirmGateFor(phase: string, cwd: string): () => boolean {
	switch (phase) {
		case "V1":
			return () => exists(cwd, `${WORK}/findings-inventory.json`);
		case "V1.5":
			return () => exists(cwd, INTENT_CORPUS);
		case "V2":
			return () => exists(cwd, `${WORK}/env-strategies.json`);
		case "V3":
			return () =>
				exists(cwd, `${WORK}/env-connection.json`) || exists(cwd, `${WORK}/healthcheck-failure.log`);
		case "V4":
			return () => exists(cwd, POC_RESULTS);
		case "V5":
			return () => exists(cwd, `${WORK}/test-mapping.json`);
		case "V6":
			return () => exists(cwd, REPORT);
		default:
			return () => true;
	}
}

export function writeRemoteConnection(cwd: string, target: string): void {
	ensureConfirmWorkdir(cwd);
	writeFileSync(
		join(cwd, `${WORK}/env-connection.json`),
		`${JSON.stringify(
			{
				status: "remote",
				base_url: target,
				method_used: "remote-target",
				healthcheck_passed: null,
				cleanup_cmd: null,
			},
			null,
			"\t",
		)}\n`,
	);
}

function reportMarksFalsePositive(text: string): boolean {
	return (
		/^(?:Confirm-Status|Confirmation|Confirm-Verdict|Verdict)\s*:\s*(?:false[-_ ]positive|fp)\b/im.test(
			text,
		) || /"confirm_status"\s*:\s*"false[-_ ]positive"/i.test(text)
	);
}

function uniqueDest(root: string, name: string): string {
	let candidate = join(root, name);
	let suffix = 2;
	while (existsSync(candidate)) {
		candidate = join(root, `${name}-${suffix}`);
		suffix++;
	}
	return candidate;
}

export function renameFalsePositiveFindings(cwd: string): string[] {
	const root = join(cwd, "piolium", "findings");
	if (!existsSync(root)) return [];
	const renames: string[] = [];
	for (const entry of readdirSync(root).sort()) {
		if (entry.startsWith("FP-")) continue;
		const dir = join(root, entry);
		try {
			if (!statSync(dir).isDirectory()) continue;
			const reportPath = join(dir, "report.md");
			if (!existsSync(reportPath)) continue;
			if (!reportMarksFalsePositive(readFileSync(reportPath, "utf8"))) continue;
			const destName = `FP-${entry}`;
			const dest = uniqueDest(root, destName);
			renameSync(dir, dest);
			renames.push(`${entry} -> ${basename(dest)}`);
		} catch {
			// Keep confirmation moving; V6 will still report available evidence.
		}
	}
	ensureConfirmWorkdir(cwd);
	writeFileSync(
		join(cwd, FP_RENAMES),
		`${JSON.stringify({ renamed_at: new Date().toISOString(), renames }, null, "\t")}\n`,
	);
	return renames;
}

export interface ConfirmCleanupResult {
	summaryPath: string;
	checkedFindingDirs: string[];
	createdEvidenceDirs: string[];
	formatIssues: string[];
	falsePositiveRenames: string[];
	redactedFiles: Array<{ path: string; replacements: Record<string, number> }>;
	skippedFiles: Array<{ path: string; reason: string }>;
}

function increment(counts: Record<string, number>, key: string, by = 1): void {
	counts[key] = (counts[key] ?? 0) + by;
}

function replaceStatic(
	text: string,
	counts: Record<string, number>,
	key: string,
	pattern: RegExp,
	replacement: string,
): string {
	pattern.lastIndex = 0;
	const matches = text.match(pattern);
	if (!matches || matches.length === 0) return text;
	increment(counts, key, matches.length);
	pattern.lastIndex = 0;
	return text.replace(pattern, replacement);
}

export function redactSecrets(text: string): {
	text: string;
	replacements: Record<string, number>;
} {
	const replacements: Record<string, number> = {};
	let out = text;

	out = replaceStatic(
		out,
		replacements,
		"private-key",
		/-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g,
		"[REDACTED:private-key]",
	);
	out = replaceStatic(
		out,
		replacements,
		"aws-access-key",
		/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
		"[REDACTED:aws-access-key]",
	);
	out = replaceStatic(
		out,
		replacements,
		"github-token",
		/\b(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b/g,
		"[REDACTED:github-token]",
	);
	out = replaceStatic(
		out,
		replacements,
		"openai-token",
		/\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
		"[REDACTED:openai-token]",
	);
	out = replaceStatic(
		out,
		replacements,
		"slack-token",
		/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
		"[REDACTED:slack-token]",
	);
	out = replaceStatic(
		out,
		replacements,
		"jwt",
		/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
		"[REDACTED:jwt]",
	);

	out = out.replace(
		/(["']?Authorization["']?\s*:\s*["']?Bearer\s+)([^"'\s,}\]]+)/gi,
		(_match: string, prefix: string) => {
			increment(replacements, "authorization-bearer");
			return `${prefix}[REDACTED:bearer]`;
		},
	);
	out = out.replace(
		/(Authorization:\s*Bearer\s+)([^\s`"']+)/gi,
		(_match: string, prefix: string) => {
			increment(replacements, "authorization-bearer");
			return `${prefix}[REDACTED:bearer]`;
		},
	);
	out = out.replace(
		/(Authorization:\s*Basic\s+)([A-Za-z0-9+/=]+)/gi,
		(_match: string, prefix: string) => {
			increment(replacements, "authorization-basic");
			return `${prefix}[REDACTED:basic]`;
		},
	);
	out = out.replace(/((?:Cookie|Set-Cookie):\s*)[^\r\n]+/gi, (_match: string, prefix: string) => {
		increment(replacements, "cookie");
		return `${prefix}[REDACTED:cookie]`;
	});
	out = out.replace(/(\bhttps?:\/\/)([^/\s:@]+):([^/\s@]+)@/gi, (_match: string, prefix: string) => {
		increment(replacements, "url-userinfo");
		return `${prefix}[REDACTED:userinfo]@`;
	});
	out = out.replace(SECRET_QUERY_RE, (_match: string, prefix: string) => {
		increment(replacements, "secret-query-param");
		return `${prefix}[REDACTED:secret]`;
	});
	out = out.replace(
		SECRET_VALUE_RE,
		(_match: string, prefix: string, _quote: string, _value: string, suffix: string) => {
			increment(replacements, "secret-key-value");
			return `${prefix}[REDACTED:secret]${suffix}`;
		},
	);

	return { text: out, replacements };
}

function isTextCandidate(path: string): boolean {
	const name = basename(path);
	return TEXT_BASENAMES.has(name) || TEXT_EXTENSIONS.has(extname(name).toLowerCase());
}

function collectArtifactFiles(
	cwd: string,
	rel: string,
	out: string[],
	skipped: ConfirmCleanupResult["skippedFiles"],
): void {
	const abs = join(cwd, rel);
	if (!existsSync(abs)) return;
	const stat = statSync(abs);
	if (stat.isDirectory()) {
		for (const entry of readdirSync(abs).sort())
			collectArtifactFiles(cwd, `${rel}/${entry}`, out, skipped);
		return;
	}
	if (!stat.isFile()) return;
	if (stat.size > MAX_REDACTABLE_BYTES) {
		skipped.push({ path: rel, reason: `larger than ${MAX_REDACTABLE_BYTES} bytes` });
		return;
	}
	if (!isTextCandidate(abs)) {
		skipped.push({ path: rel, reason: "not a known text artifact extension" });
		return;
	}
	out.push(rel);
}

function redactArtifactFile(
	cwd: string,
	rel: string,
	skipped: ConfirmCleanupResult["skippedFiles"],
): ConfirmCleanupResult["redactedFiles"][number] | undefined {
	const abs = join(cwd, rel);
	const raw = readFileSync(abs);
	if (raw.includes(0)) {
		skipped.push({ path: rel, reason: "appears to be binary" });
		return undefined;
	}
	const original = raw.toString("utf8");
	const redacted = redactSecrets(original);
	if (redacted.text === original) return undefined;
	writeFileSync(abs, redacted.text);
	return { path: rel, replacements: redacted.replacements };
}

function normalizeFindingLayout(
	cwd: string,
): Pick<ConfirmCleanupResult, "checkedFindingDirs" | "createdEvidenceDirs" | "formatIssues"> {
	const root = join(cwd, "piolium", "findings");
	const checkedFindingDirs: string[] = [];
	const createdEvidenceDirs: string[] = [];
	const formatIssues: string[] = [];
	if (!existsSync(root)) {
		formatIssues.push("missing piolium/findings/");
		return { checkedFindingDirs, createdEvidenceDirs, formatIssues };
	}
	for (const entry of readdirSync(root).sort()) {
		const dir = join(root, entry);
		if (!statSync(dir).isDirectory()) {
			formatIssues.push(`non-directory entry under piolium/findings/: ${entry}`);
			continue;
		}
		checkedFindingDirs.push(entry);
		if (!/^(?:FP-)?[A-Za-z0-9]+(?:-\d+)?-[A-Za-z0-9][A-Za-z0-9._-]*$/.test(entry)) {
			formatIssues.push(`finding directory name is non-standard: ${entry}`);
		}
		const report = join(dir, "report.md");
		if (!existsSync(report)) {
			formatIssues.push(`missing report.md: piolium/findings/${entry}/report.md`);
		} else if (statSync(report).size === 0) {
			formatIssues.push(`empty report.md: piolium/findings/${entry}/report.md`);
		}
		const evidence = join(dir, "evidence");
		if (!existsSync(evidence)) {
			mkdirSync(evidence, { recursive: true });
			createdEvidenceDirs.push(`piolium/findings/${entry}/evidence`);
		} else if (!statSync(evidence).isDirectory()) {
			formatIssues.push(`evidence path is not a directory: piolium/findings/${entry}/evidence`);
		}
	}
	return { checkedFindingDirs, createdEvidenceDirs, formatIssues };
}

export function cleanupConfirmArtifacts(cwd: string): ConfirmCleanupResult {
	ensureConfirmWorkdir(cwd);
	const falsePositiveRenames = renameFalsePositiveFindings(cwd);
	const layout = normalizeFindingLayout(cwd);
	const skippedFiles: ConfirmCleanupResult["skippedFiles"] = [];
	const candidates: string[] = [];
	for (const rel of ["piolium/findings", REPORT, WORK]) {
		collectArtifactFiles(cwd, rel, candidates, skippedFiles);
	}
	const redactedFiles = candidates
		.map((rel) => redactArtifactFile(cwd, rel, skippedFiles))
		.filter((item): item is ConfirmCleanupResult["redactedFiles"][number] => item !== undefined);

	const result: ConfirmCleanupResult = {
		summaryPath: CLEANUP_SUMMARY,
		...layout,
		falsePositiveRenames,
		redactedFiles,
		skippedFiles,
	};
	writeFileSync(join(cwd, CLEANUP_SUMMARY), `${JSON.stringify(result, null, "\t")}\n`);
	return result;
}

async function runCleanupPhase(
	cwd: string,
	audit: AuditRunState,
	ui: PhaseUiHooks | undefined,
): Promise<void> {
	if (audit.phases.V7?.status === "complete" && exists(cwd, CLEANUP_SUMMARY)) return;
	ui?.setStatus?.("piolium-confirm", "● V7 cleanup");
	await applyPhaseStatus(cwd, audit, "V7", { status: "in_progress" });
	try {
		const result = cleanupConfirmArtifacts(cwd);
		await applyPhaseStatus(cwd, audit, "V7", {
			status: "complete",
			artifacts: [result.summaryPath],
		});
		if (result.formatIssues.length > 0) {
			ui?.notify?.(
				`Cleanup completed with ${result.formatIssues.length} final-folder format warning(s).`,
				"warning",
			);
		}
	} catch (err) {
		await applyPhaseStatus(cwd, audit, "V7", {
			status: "failed",
			error: err instanceof Error ? err.message : String(err),
		});
		throw err;
	} finally {
		ui?.setStatus?.("piolium-confirm", undefined);
	}
}

export async function runConfirmAudit(opts: RunConfirmOptions): Promise<RunConfirmResult> {
	const { cwd, signal, ui } = opts;
	if (findingDirsWithReports(cwd).length === 0) {
		throw new Error("No findings to confirm. Expected `piolium/findings/*/report.md`.");
	}
	ensureConfirmWorkdir(cwd);

	ui?.setStatus?.("piolium-confirm", "● preparing recon");
	const recon = await runReconAsync(cwd, { signal });
	let audit = pickResume(cwd, opts.forceFresh ?? false);
	if (!audit) {
		audit = await initAudit(cwd, {
			mode: "confirm",
			...(recon.commit ? { commit: recon.commit } : { commit: null }),
			...(recon.branch ? { branch: recon.branch } : { branch: "nogit" }),
			...(recon.repository ? { repository: recon.repository } : {}),
			history_available: recon.historyAvailable,
			agent_sdk: "pi",
		});
	}

	const { agents } = loadAgents({ cwd });
	const phaseAgents: Record<(typeof CONFIRM_AGENT_PHASES)[number], ReturnType<typeof agents.get>> = {
		V1: agents.get("env-detective"),
		"V1.5": agents.get("intent-cartographer"),
		V2: agents.get("env-detective"),
		V3: agents.get("env-provisioner"),
		V4: agents.get("poc-executor"),
		V5: agents.get("test-mapper"),
		V6: agents.get("confirm-reporter"),
	};

	let failed = false;

	for (const name of CONFIRM_PHASES) {
		if (name === "V7") {
			try {
				await runCleanupPhase(cwd, audit, ui);
			} catch {
				failed = true;
			}
			continue;
		}
		if (opts.target && (name === "V2" || name === "V3")) {
			writeRemoteConnection(cwd, opts.target);
			await applyPhaseStatus(cwd, audit, name, {
				status: "skipped",
				error: "Remote target supplied; local environment discovery/provisioning skipped.",
			});
			continue;
		}
		if (opts.target && name === "V5") {
			await applyPhaseStatus(cwd, audit, name, {
				status: "skipped",
				error: "Remote target supplied; local test fallback skipped.",
			});
			continue;
		}
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
				phaseName: name,
				statusKey: "piolium-confirm",
				statusLabel: `● ${name}`,
				agent: phaseAgents[name],
				missingAgentMessage: `agent missing for ${name}`,
				task: buildConfirmTask(name, opts.target),
				gate: confirmGateFor(name, cwd),
				mode: "confirm",
				ui,
				agentRuntime: opts.agentRuntime,
				...(signal ? { signal } : {}),
			});
		} catch (err) {
			failed = true;
			if (name === "V1" || name === "V6") break;
			ui?.notify?.(
				`Confirm phase ${name} failed (${errorMessage(err)}); continuing to collect/report remaining evidence.`,
				"warning",
			);
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
	ui?.notify?.(
		failed ? "Confirm pass failed." : "Confirm pass complete.",
		failed ? "error" : "info",
	);
	return { auditId: audit.audit_id, status: failed ? "failed" : "complete", phases };
}
