/**
 * Deterministic pre-audit reconnaissance (Q0 / first phase of every mode).
 *
 * Runs entirely in the orchestrator process — no model calls. Produces a
 * compact Markdown report describing the target repository so later phases
 * (and human reviewers) have stable ground truth.
 *
 * Designed to be resilient on:
 *   - directories without `.git`
 *   - directories without typical build manifests
 *   - very large repos (caps tree depth + entry count)
 *   - missing `git` binary
 */

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { yieldToEventLoop } from "./retry.ts";

export const RECON_REPORT_PATH = "piolium/attack-surface/lite-recon.md";

export interface ReconResult {
	cwd: string;
	reportPath: string;
	hasGit: boolean;
	commit?: string;
	branch?: string;
	repository?: string;
	historyAvailable: boolean;
	languages: Record<string, number>;
	manifests: string[];
	totalFiles: number;
	totalBytes: number;
}

export interface ReconOptions {
	signal?: AbortSignal;
	yieldEveryEntries?: number;
}

const MANIFEST_FILES = [
	"package.json",
	"go.mod",
	"Cargo.toml",
	"pyproject.toml",
	"requirements.txt",
	"Pipfile",
	"Gemfile",
	"composer.json",
	"pom.xml",
	"build.gradle",
	"build.gradle.kts",
	"setup.py",
	"setup.cfg",
	"Dockerfile",
	"docker-compose.yml",
	"docker-compose.yaml",
];

const LANGUAGE_BY_EXT: Record<string, string> = {
	".ts": "TypeScript",
	".tsx": "TypeScript",
	".js": "JavaScript",
	".jsx": "JavaScript",
	".py": "Python",
	".go": "Go",
	".rs": "Rust",
	".rb": "Ruby",
	".java": "Java",
	".kt": "Kotlin",
	".swift": "Swift",
	".c": "C",
	".h": "C",
	".cpp": "C++",
	".cc": "C++",
	".hpp": "C++",
	".cs": "C#",
	".php": "PHP",
	".scala": "Scala",
	".clj": "Clojure",
	".sh": "Shell",
	".bash": "Shell",
	".zsh": "Shell",
	".sql": "SQL",
	".lua": "Lua",
	".m": "Objective-C",
	".mm": "Objective-C",
};

const SKIP_DIRS = new Set([
	"node_modules",
	".git",
	"vendor",
	"dist",
	"build",
	"target",
	"out",
	".next",
	".nuxt",
	".cache",
	".venv",
	"venv",
	"__pycache__",
	".pytest_cache",
	".mypy_cache",
	".idea",
	".vscode",
	"piolium",
]);

/** Soft caps so we never wedge on a giant repo. */
const MAX_FILES_TO_SCAN = 50_000;
const MAX_BYTES_TO_TALLY = 500 * 1024 * 1024; // 500MB
const DEFAULT_ASYNC_YIELD_EVERY_ENTRIES = 100;

/** Hard ceiling so a hung git command (auth prompt, stalled network mount,
 * unreachable remote) can't wedge the whole recon phase indefinitely. */
const SAFE_EXEC_TIMEOUT_MS = 15_000;

function safeExec(file: string, args: string[], cwd: string): string | undefined {
	try {
		return execFileSync(file, args, {
			cwd,
			encoding: "utf8",
			stdio: ["ignore", "pipe", "ignore"],
			timeout: SAFE_EXEC_TIMEOUT_MS,
			maxBuffer: 32 * 1024 * 1024,
		}).trim();
	} catch {
		// Non-zero exit, missing binary, or timeout — recon is best-effort.
		return undefined;
	}
}

function detectGit(cwd: string): {
	hasGit: boolean;
	commit?: string;
	branch?: string;
	historyAvailable: boolean;
	remote?: string;
	headLog?: string;
} {
	if (!existsSync(join(cwd, ".git"))) {
		return { hasGit: false, historyAvailable: false };
	}
	const commit = safeExec("git", ["rev-parse", "HEAD"], cwd);
	const branch = safeExec("git", ["rev-parse", "--abbrev-ref", "HEAD"], cwd);
	const remote = safeExec("git", ["remote", "get-url", "origin"], cwd);
	const headLog = safeExec("git", ["log", "-n", "10", "--oneline", "--no-decorate"], cwd);
	return {
		hasGit: true,
		historyAvailable: Boolean(commit),
		...(commit ? { commit } : {}),
		...(branch ? { branch } : {}),
		...(remote ? { remote } : {}),
		...(headLog ? { headLog } : {}),
	};
}

function inferRepository(remote: string | undefined): string | undefined {
	if (!remote) return undefined;
	// Strip auth + protocol
	const m = remote.match(
		/(?:github\.com[:/]|gitlab\.com[:/]|bitbucket\.org[:/])([^/]+\/[^/.]+)(?:\.git)?$/,
	);
	if (m?.[1]) return m[1];
	return undefined;
}

function walkAndTally(cwd: string): {
	languages: Record<string, number>;
	manifests: string[];
	totalFiles: number;
	totalBytes: number;
} {
	const languages: Record<string, number> = {};
	const manifests: string[] = [];
	let totalFiles = 0;
	let totalBytes = 0;

	function walk(dir: string): void {
		if (totalFiles >= MAX_FILES_TO_SCAN) return;
		let entries: string[];
		try {
			entries = readdirSync(dir);
		} catch {
			return;
		}
		for (const entry of entries) {
			if (totalFiles >= MAX_FILES_TO_SCAN) return;
			if (SKIP_DIRS.has(entry) || entry.startsWith(".")) continue;
			const full = join(dir, entry);
			let st: ReturnType<typeof statSync>;
			try {
				st = statSync(full);
			} catch {
				continue;
			}
			if (st.isDirectory()) {
				walk(full);
				continue;
			}
			if (!st.isFile()) continue;
			totalFiles++;
			if (totalBytes < MAX_BYTES_TO_TALLY) totalBytes += st.size;
			const lower = entry.toLowerCase();
			if (MANIFEST_FILES.includes(entry)) {
				manifests.push(relative(cwd, full));
			} else if (lower.startsWith("dockerfile")) {
				manifests.push(relative(cwd, full));
			}
			const dotIdx = entry.lastIndexOf(".");
			if (dotIdx > 0) {
				const ext = entry.slice(dotIdx).toLowerCase();
				const lang = LANGUAGE_BY_EXT[ext];
				if (lang) languages[lang] = (languages[lang] ?? 0) + 1;
			}
		}
	}

	walk(cwd);
	return { languages, manifests, totalFiles, totalBytes };
}

async function walkAndTallyAsync(
	cwd: string,
	options: ReconOptions = {},
): Promise<{
	languages: Record<string, number>;
	manifests: string[];
	totalFiles: number;
	totalBytes: number;
}> {
	const languages: Record<string, number> = {};
	const manifests: string[] = [];
	let totalFiles = 0;
	let totalBytes = 0;
	let visitedEntries = 0;
	const yieldEveryEntries = Math.max(
		1,
		options.yieldEveryEntries ?? DEFAULT_ASYNC_YIELD_EVERY_ENTRIES,
	);

	async function maybeYield(): Promise<void> {
		visitedEntries++;
		if (visitedEntries % yieldEveryEntries === 0) {
			await yieldToEventLoop(options.signal);
		}
	}

	async function walk(dir: string): Promise<void> {
		if (options.signal?.aborted) throw options.signal.reason ?? new Error("Aborted");
		if (totalFiles >= MAX_FILES_TO_SCAN) return;
		let entries: string[];
		try {
			entries = readdirSync(dir);
		} catch {
			return;
		}
		for (const entry of entries) {
			await maybeYield();
			if (options.signal?.aborted) throw options.signal.reason ?? new Error("Aborted");
			if (totalFiles >= MAX_FILES_TO_SCAN) return;
			if (SKIP_DIRS.has(entry) || entry.startsWith(".")) continue;
			const full = join(dir, entry);
			let st: ReturnType<typeof statSync>;
			try {
				st = statSync(full);
			} catch {
				continue;
			}
			if (st.isDirectory()) {
				await walk(full);
				continue;
			}
			if (!st.isFile()) continue;
			totalFiles++;
			if (totalBytes < MAX_BYTES_TO_TALLY) totalBytes += st.size;
			const lower = entry.toLowerCase();
			if (MANIFEST_FILES.includes(entry)) {
				manifests.push(relative(cwd, full));
			} else if (lower.startsWith("dockerfile")) {
				manifests.push(relative(cwd, full));
			}
			const dotIdx = entry.lastIndexOf(".");
			if (dotIdx > 0) {
				const ext = entry.slice(dotIdx).toLowerCase();
				const lang = LANGUAGE_BY_EXT[ext];
				if (lang) languages[lang] = (languages[lang] ?? 0) + 1;
			}
		}
	}

	await walk(cwd);
	return { languages, manifests, totalFiles, totalBytes };
}

function formatBytes(bytes: number): string {
	if (bytes < 1024) return `${bytes} B`;
	if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
	if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
	return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function buildReconReport(cwd: string, result: ReconResult, headLog?: string): string {
	const lines: string[] = [];
	lines.push("# Lite Recon — Q0");
	lines.push("");
	lines.push(`Generated by piolium at ${new Date().toISOString()}`);
	lines.push("");
	lines.push("## Target");
	lines.push("");
	lines.push(`- Path: \`${cwd}\``);
	lines.push(`- Repository: ${result.repository ?? "(unknown)"}`);
	lines.push(
		`- Total files (scanned): ${result.totalFiles}${result.totalFiles >= MAX_FILES_TO_SCAN ? " (capped)" : ""}`,
	);
	lines.push(`- Total bytes (scanned): ${formatBytes(result.totalBytes)}`);
	lines.push("");
	lines.push("## Git");
	lines.push("");
	if (result.hasGit) {
		lines.push(`- Commit: ${result.commit ?? "(unknown)"}`);
		lines.push(`- Branch: ${result.branch ?? "(unknown)"}`);
		lines.push(`- History available: ${result.historyAvailable}`);
		if (headLog) {
			lines.push("");
			lines.push("Recent commits:");
			lines.push("");
			lines.push("```");
			lines.push(headLog);
			lines.push("```");
		}
	} else {
		lines.push("- Not a git repository (no `.git/`).");
		lines.push(
			"- Phases that depend on git history (commit archaeology, patch-bypass) will be skipped.",
		);
	}
	lines.push("");
	lines.push("## Languages");
	lines.push("");
	const langEntries = Object.entries(result.languages).sort((a, b) => b[1] - a[1]);
	if (langEntries.length === 0) {
		lines.push("(none recognized)");
	} else {
		for (const [lang, count] of langEntries) lines.push(`- ${lang}: ${count} file(s)`);
	}
	lines.push("");
	lines.push("## Build / Project Manifests");
	lines.push("");
	if (result.manifests.length === 0) {
		lines.push("(none recognized)");
	} else {
		for (const m of result.manifests) lines.push(`- \`${m}\``);
	}
	lines.push("");
	return lines.join("\n");
}

export function runRecon(cwd: string): ReconResult {
	const git = detectGit(cwd);
	const repository = inferRepository(git.remote);
	const tally = walkAndTally(cwd);

	const reportPath = join(cwd, RECON_REPORT_PATH);
	mkdirSync(dirname(reportPath), { recursive: true });

	const result: ReconResult = {
		cwd,
		reportPath,
		hasGit: git.hasGit,
		...(git.commit ? { commit: git.commit } : {}),
		...(git.branch ? { branch: git.branch } : {}),
		...(repository ? { repository } : {}),
		historyAvailable: git.historyAvailable,
		languages: tally.languages,
		manifests: tally.manifests,
		totalFiles: tally.totalFiles,
		totalBytes: tally.totalBytes,
	};

	writeFileSync(reportPath, buildReconReport(cwd, result, git.headLog));
	return result;
}

export async function runReconAsync(cwd: string, options: ReconOptions = {}): Promise<ReconResult> {
	const git = detectGit(cwd);
	await yieldToEventLoop(options.signal);
	const repository = inferRepository(git.remote);
	const tally = await walkAndTallyAsync(cwd, options);

	const reportPath = join(cwd, RECON_REPORT_PATH);
	mkdirSync(dirname(reportPath), { recursive: true });

	const result: ReconResult = {
		cwd,
		reportPath,
		hasGit: git.hasGit,
		...(git.commit ? { commit: git.commit } : {}),
		...(git.branch ? { branch: git.branch } : {}),
		...(repository ? { repository } : {}),
		historyAvailable: git.historyAvailable,
		languages: tally.languages,
		manifests: tally.manifests,
		totalFiles: tally.totalFiles,
		totalBytes: tally.totalBytes,
	};

	writeFileSync(reportPath, buildReconReport(cwd, result, git.headLog));
	return result;
}

export function reconReportPath(cwd: string): string {
	return join(cwd, RECON_REPORT_PATH);
}
