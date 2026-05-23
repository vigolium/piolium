/**
 * Q1 secrets scanner.
 *
 * Tries `trufflehog`, then `gitleaks`, then a regex-grep fallback. Each
 * finding is materialised as `piolium/findings-draft/q1-<NNN>-<slug>.md` so
 * later phases (consolidation, finalisation) can pick them up using the same
 * conventions as the rest of the pipeline.
 *
 * Tool detection is best-effort: when a binary isn't on PATH the next
 * fallback is tried and a note is left in the phase summary. We never throw
 * just because a tool is missing — that's expected on slim CI runners.
 */

import { execFileSync } from "node:child_process";
import {
	constants,
	accessSync,
	existsSync,
	mkdirSync,
	readFileSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { delimiter, join } from "node:path";
import { readPositiveIntEnv } from "./retry.ts";

export type SecretsBackend = "trufflehog" | "gitleaks" | "grep" | "none";

/**
 * Hard ceiling so a hung scanner (trufflehog on a giant blob, grep on a stalled
 * network mount) can't wedge the synchronous Q1 phase forever. `execFileSync`
 * blocks the event loop, so without this the phase heartbeat can't even fire.
 * Generous default — full git-history secret scans legitimately run for
 * minutes; override via PIOLIUM_SECRETS_TIMEOUT_MS for very large repos.
 */
const SECRETS_EXEC_TIMEOUT_MS = readPositiveIntEnv("PIOLIUM_SECRETS_TIMEOUT_MS", 300_000);

export interface SecretFinding {
	id: string;
	slug: string;
	severity: "high" | "medium" | "low";
	title: string;
	file: string;
	line?: number;
	rule?: string;
	excerpt?: string;
	source: SecretsBackend;
}

export interface SecretsScanResult {
	backend: SecretsBackend;
	findings: SecretFinding[];
	notes: string[];
	draftPaths: string[];
}

export const Q1_SECRETS_SUMMARY = "piolium/attack-surface/lite-q1-summary.md";

/**
 * Shell-free PATH lookup. Avoids `spawnSync(..., { shell: true })` (which trips
 * Node's DEP0190 deprecation and would be an injection vector if `bin` were
 * ever attacker-controlled) by scanning `$PATH` for an executable file.
 */
function which(bin: string): boolean {
	const dirs = (process.env.PATH ?? "").split(delimiter).filter(Boolean);
	for (const dir of dirs) {
		const candidate = join(dir, bin);
		try {
			if (!statSync(candidate).isFile()) continue;
			accessSync(candidate, constants.X_OK);
			return true;
		} catch {
			// not here, not a file, or not executable — keep looking
		}
	}
	return false;
}

function safeExec(file: string, args: string[], cwd: string): string | undefined {
	try {
		return execFileSync(file, args, {
			cwd,
			encoding: "utf8",
			stdio: ["ignore", "pipe", "pipe"],
			timeout: SECRETS_EXEC_TIMEOUT_MS,
			maxBuffer: 64 * 1024 * 1024,
		});
	} catch (err) {
		const e = err as NodeJS.ErrnoException & { stdout?: string };
		// Many secret-scanning tools exit non-zero specifically *because* they
		// found something — they still print results to stdout. A timeout
		// (ETIMEDOUT) lands here too; return whatever partial output exists,
		// otherwise skip this backend.
		if (typeof e.stdout === "string" && e.stdout.length > 0) return e.stdout;
		return undefined;
	}
}

function slugify(text: string): string {
	return (
		text
			.toLowerCase()
			.replace(/[^a-z0-9]+/g, "-")
			.replace(/^-+|-+$/g, "")
			.slice(0, 60) || "secret"
	);
}

function severityFromRule(rule: string): "high" | "medium" | "low" {
	const lower = rule.toLowerCase();
	if (
		lower.includes("private") ||
		lower.includes("aws") ||
		lower.includes("gcp") ||
		lower.includes("azure")
	)
		return "high";
	if (lower.includes("token") || lower.includes("api") || lower.includes("password"))
		return "medium";
	return "low";
}

interface TruffleHogRecord {
	DetectorName?: string;
	Verified?: boolean;
	Raw?: string;
	SourceMetadata?: {
		Data?: {
			Filesystem?: { file?: string; line?: number };
			Git?: { file?: string; line?: number };
		};
	};
}

function parseTrufflehog(stdout: string): SecretFinding[] {
	const findings: SecretFinding[] = [];
	let counter = 0;
	for (const line of stdout.split(/\r?\n/)) {
		if (!line.trim()) continue;
		try {
			const rec = JSON.parse(line) as TruffleHogRecord;
			const detector = rec.DetectorName ?? "unknown";
			const fsMeta = rec.SourceMetadata?.Data?.Filesystem;
			const gitMeta = rec.SourceMetadata?.Data?.Git;
			const file = fsMeta?.file ?? gitMeta?.file ?? "(unknown)";
			const lineNum = fsMeta?.line ?? gitMeta?.line;
			counter++;
			const id = `q1-${String(counter).padStart(3, "0")}`;
			findings.push({
				id,
				slug: slugify(`${detector}-${file}`),
				severity: rec.Verified ? "high" : severityFromRule(detector),
				title: `${detector} secret detected (${rec.Verified ? "verified" : "unverified"})`,
				file,
				...(lineNum ? { line: lineNum } : {}),
				rule: detector,
				...(rec.Raw ? { excerpt: rec.Raw.slice(0, 200) } : {}),
				source: "trufflehog",
			});
		} catch {
			// non-JSON lines (banners, errors) are ignored
		}
	}
	return findings;
}

interface GitleaksRecord {
	Description?: string;
	File?: string;
	StartLine?: number;
	Match?: string;
	RuleID?: string;
	Secret?: string;
}

function parseGitleaks(stdout: string): SecretFinding[] {
	let arr: GitleaksRecord[];
	try {
		arr = JSON.parse(stdout) as GitleaksRecord[];
		if (!Array.isArray(arr)) return [];
	} catch {
		return [];
	}
	return arr.map((r, i) => {
		const counter = i + 1;
		const file = r.File ?? "(unknown)";
		const rule = r.RuleID ?? r.Description ?? "gitleaks-rule";
		return {
			id: `q1-${String(counter).padStart(3, "0")}`,
			slug: slugify(`${rule}-${file}`),
			severity: severityFromRule(rule),
			title: r.Description ?? "gitleaks finding",
			file,
			...(r.StartLine ? { line: r.StartLine } : {}),
			rule,
			...(r.Match ? { excerpt: r.Match.slice(0, 200) } : {}),
			source: "gitleaks" as const,
		};
	});
}

/**
 * Fallback grep patterns. These are **POSIX ERE** strings (the dialect
 * `grep -E` understands), not JS/PCRE regexes. Two dialect rules matter:
 *   - No `(?:...)` non-capturing groups — use plain `(...)`. ERE has no
 *     non-capturing form and grep errors out on `(?:`.
 *   - No `\s` — use `[[:space:]]`. `\s` is a GNU extension absent from BSD grep.
 * Word boundaries (`\b`) are supported by both GNU and BSD grep. Patterns are
 * passed to grep via `-e` so a leading `-` (e.g. PEM headers) isn't parsed as
 * an option.
 */
const GREP_PATTERNS: Array<{
	rule: string;
	pattern: string;
	ignoreCase?: boolean;
	severity: "high" | "medium" | "low";
}> = [
	{
		rule: "aws-access-key-id",
		pattern: "\\b(AKIA|ASIA)[0-9A-Z]{16}\\b",
		severity: "high",
	},
	{
		rule: "private-key-pem",
		pattern: "-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) (PRIVATE )?KEY-----",
		severity: "high",
	},
	{
		rule: "github-token",
		pattern: "\\bgh[pousr]_[A-Za-z0-9]{36,}\\b",
		severity: "high",
	},
	{
		rule: "slack-token",
		pattern: "\\bxox[baprs]-[A-Za-z0-9-]{10,48}\\b",
		severity: "medium",
	},
	{
		rule: "generic-api-key",
		pattern:
			"(api[_-]?key|secret|password|token)[[:space:]]*[:=][[:space:]]*['\"][A-Za-z0-9+/=_-]{16,}['\"]",
		ignoreCase: true,
		severity: "low",
	},
];

const GREP_INCLUDE = [
	"*.ts",
	"*.tsx",
	"*.js",
	"*.jsx",
	"*.py",
	"*.go",
	"*.rs",
	"*.rb",
	"*.java",
	"*.kt",
	"*.cs",
	"*.php",
	"*.sh",
	"*.bash",
	"*.env",
	"*.yml",
	"*.yaml",
	"*.toml",
	"*.ini",
	"*.cfg",
	"*.conf",
	"*.json",
];

export function runGrepFallback(cwd: string): SecretFinding[] {
	const findings: SecretFinding[] = [];
	let counter = 0;
	for (const { rule, pattern, ignoreCase, severity } of GREP_PATTERNS) {
		const args = [
			"-rEn",
			...(ignoreCase ? ["-i"] : []),
			"--binary-files=without-match",
			"--exclude-dir=node_modules",
			"--exclude-dir=.git",
			"--exclude-dir=vendor",
			"--exclude-dir=dist",
			"--exclude-dir=build",
			"--exclude-dir=piolium",
			...GREP_INCLUDE.flatMap((g) => ["--include", g]),
			// `-e` marks the pattern explicitly so a leading `-` (PEM headers)
			// isn't mistaken for a command-line option.
			"-e",
			pattern,
			".",
		];
		const stdout = safeExec("grep", args, cwd);
		if (!stdout) continue;
		for (const line of stdout.split(/\r?\n/)) {
			if (!line.trim()) continue;
			// Format: ./path/to/file:42:matched text
			const m = line.match(/^(?:\.\/)?(.+?):(\d+):(.*)$/);
			if (!m) continue;
			const file = m[1] ?? "(unknown)";
			const lineNum = Number(m[2]);
			const excerpt = (m[3] ?? "").trim().slice(0, 200);
			counter++;
			findings.push({
				id: `q1-${String(counter).padStart(3, "0")}`,
				slug: slugify(`${rule}-${file}`),
				severity,
				title: `${rule} match`,
				file,
				...(Number.isFinite(lineNum) ? { line: lineNum } : {}),
				rule,
				...(excerpt ? { excerpt } : {}),
				source: "grep" as const,
			});
		}
	}
	return findings;
}

function findingMarkdown(f: SecretFinding): string {
	return [
		"---",
		`id: ${f.id}`,
		"phase: Q1",
		`slug: ${f.slug}`,
		`severity: ${f.severity}`,
		`source: ${f.source}`,
		`rule: ${f.rule ?? "(none)"}`,
		"---",
		"",
		`# ${f.title}`,
		"",
		`- File: \`${f.file}\``,
		f.line ? `- Line: ${f.line}` : "",
		f.excerpt ? "" : "",
		f.excerpt ? `## Excerpt\n\n\`\`\`\n${f.excerpt}\n\`\`\`` : "",
		"",
		"## Notes",
		"",
		"This is a draft finding produced by the Q1 secrets scan. Confirm by inspecting the file in context.",
		"",
	]
		.filter((s) => s !== "")
		.join("\n");
}

export function findingsDraftDir(cwd: string): string {
	return join(cwd, "piolium", "findings-draft");
}

export function runQ1SecretsScan(cwd: string): SecretsScanResult {
	const notes: string[] = [];
	let backend: SecretsBackend = "none";
	let findings: SecretFinding[] = [];

	if (which("trufflehog")) {
		notes.push("Backend: trufflehog (filesystem mode).");
		const out = safeExec(
			"trufflehog",
			["filesystem", "--json", "--no-update", "--exclude-paths=piolium", "."],
			cwd,
		);
		if (out) {
			findings = parseTrufflehog(out);
			backend = "trufflehog";
		} else {
			notes.push("trufflehog returned no output — falling back.");
		}
	}
	if (backend === "none" && which("gitleaks")) {
		notes.push("Backend: gitleaks (no-git mode).");
		const tmp = join(cwd, "piolium", "tmp", "piolium", "gitleaks.json");
		mkdirSync(join(cwd, "piolium", "tmp", "piolium"), { recursive: true });
		safeExec(
			"gitleaks",
			["detect", "--source", ".", "--no-git", "--report-format", "json", "--report-path", tmp],
			cwd,
		);
		if (existsSync(tmp)) {
			try {
				const txt = readFileSync(tmp, "utf8");
				findings = parseGitleaks(txt);
				backend = "gitleaks";
			} catch {
				notes.push("gitleaks report unreadable.");
			}
		}
	}
	if (backend === "none") {
		notes.push("Backend: regex grep fallback (no trufflehog or gitleaks on PATH).");
		findings = runGrepFallback(cwd);
		backend = "grep";
	}

	const draftDir = findingsDraftDir(cwd);
	mkdirSync(draftDir, { recursive: true });
	const draftPaths: string[] = [];
	for (const f of findings) {
		const path = join(draftDir, `${f.id}-${f.slug}.md`);
		writeFileSync(path, findingMarkdown(f));
		draftPaths.push(path);
	}

	// Summary placeholder so the gate has something to read even when no
	// findings surface — distinguishes "scan ran, clean" from "scan never ran".
	const summaryPath = join(cwd, Q1_SECRETS_SUMMARY);
	mkdirSync(join(cwd, "piolium", "attack-surface"), { recursive: true });
	writeFileSync(
		summaryPath,
		[
			"# Q1 Secrets Scan",
			"",
			`Backend: ${backend}`,
			`Findings: ${findings.length}`,
			notes.length > 0 ? `\nNotes:\n${notes.map((n) => `- ${n}`).join("\n")}` : "",
			"",
		].join("\n"),
	);

	return { backend, findings, notes, draftPaths };
}
