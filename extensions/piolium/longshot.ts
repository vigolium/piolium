/**
 * Longshot mode — file enumeration, scoring, and per-file status sidecar.
 *
 * Pure deterministic helpers used by `modes/longshot.ts`. No model calls.
 *
 * The hail-mary scan picks files matching the dominant project language(s),
 * filters out tests and generated code, scores each file by the density of
 * dangerous-looking tokens + path heuristics, then writes the ordered list
 * to `piolium/attack-surface/longshot-targets.json`. The X2 fan-out reads
 * that sidecar and updates per-file status atomically as it makes progress,
 * which keeps resume cheap (skip files already complete; retry the rest).
 */

import { createHash } from "node:crypto";
import {
	existsSync,
	mkdirSync,
	readFileSync,
	readdirSync,
	renameSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { dirname, join, relative } from "node:path";
import { withFileMutationQueue } from "@earendil-works/pi-coding-agent";
import { readCandidateScores } from "./candidate-scan.ts";

export interface LongshotTarget {
	path: string;
	language: string;
	score: number;
	bytes: number;
	sha8: string;
	status: "pending" | "in_progress" | "complete" | "failed";
	attempts?: number;
	last_error?: string;
	completed_at?: string;
	run_id?: string;
	draft_count?: number;
}

export interface LongshotTargetsFile {
	generated_at: string;
	cwd: string;
	languages: string[];
	limit: number;
	total_candidates: number;
	skipped_tests: number;
	skipped_generated: number;
	skipped_oversized: number;
	skipped_unrecognized: number;
	targets: LongshotTarget[];
}

export const LONGSHOT_ATTACK_SURFACE_DIR = "piolium/attack-surface";
export const LONGSHOT_TARGETS_PATH = `${LONGSHOT_ATTACK_SURFACE_DIR}/longshot-targets.json`;
export const LONGSHOT_SUMMARY_PATH = `${LONGSHOT_ATTACK_SURFACE_DIR}/longshot-summary.md`;
export const LONGSHOT_FINDINGS_DRAFT_DIR = "piolium/findings-draft";
export const LONGSHOT_DEFAULT_LIMIT = 1000;
export const LONGSHOT_DEFAULT_TIMEOUT_MS = 6 * 60 * 60 * 1000; // 6 hours
export const LONGSHOT_MAX_FILE_BYTES = 1024 * 1024; // skip files > 1MB

/** Snake-case-key extension to languages most users will hunt against. */
const LANGUAGE_BY_EXT: Record<string, string> = {
	".ts": "TypeScript",
	".tsx": "TypeScript",
	".js": "JavaScript",
	".jsx": "JavaScript",
	".mjs": "JavaScript",
	".cjs": "JavaScript",
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
	".lua": "Lua",
	".m": "Objective-C",
	".mm": "Objective-C",
};

const EXTS_BY_LANGUAGE: Record<string, string[]> = (() => {
	const map: Record<string, string[]> = {};
	for (const [ext, lang] of Object.entries(LANGUAGE_BY_EXT)) {
		let list = map[lang];
		if (!list) {
			list = [];
			map[lang] = list;
		}
		list.push(ext);
	}
	return map;
})();

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
	"third_party",
	"third-party",
]);

const TEST_DIR_NAMES = new Set([
	"tests",
	"test",
	"__tests__",
	"spec",
	"specs",
	"e2e",
	"fixtures",
	"testdata",
	"test-data",
]);

const TEST_FILE_PATTERNS: RegExp[] = [
	/(^|\/)test_[^/]+\.py$/i,
	/(^|\/)[^/]+_test\.py$/i,
	/(^|\/)[^/]+_test\.go$/i,
	/(^|\/)[^/]+\.test\.(?:ts|tsx|js|jsx|mjs|cjs)$/i,
	/(^|\/)[^/]+\.spec\.(?:ts|tsx|js|jsx|mjs|cjs)$/i,
	/(^|\/)[^/]+\.test\.rb$/i,
	/(^|\/)[^/]+_spec\.rb$/i,
	/(^|\/)[^/]+(?:Test|Tests|Spec|Specs)\.(?:java|kt|kts|scala|cs)$/,
	/(^|\/)test_[^/]+\.rs$/i,
	/(^|\/)[^/]+\.test\.[^/]*$/i,
];

const GENERATED_FILE_PATTERNS: RegExp[] = [
	/\.pb\.go$/i,
	/_pb2\.py$/i,
	/_pb2_grpc\.py$/i,
	/\.pb\.cc$/i,
	/\.pb\.h$/i,
	/\.gen\.go$/i,
	/_generated\./i,
	/\.generated\./i,
	/\.min\.js$/i,
	/\.min\.css$/i,
	/\.bundle\.js$/i,
	/-generated\./i,
	/^bindata\.go$/i,
	/_string\.go$/i,
];

/** Substrings that strongly hint a file is interesting to a vulnerability hunter. */
const CONTENT_SIGNALS: Array<{ pattern: RegExp; weight: number }> = [
	{ pattern: /os\/exec|exec\.Command|subprocess|child_process|popen\(|Runtime\.exec/g, weight: 6 },
	{ pattern: /\beval\(|new Function\(|Function\(['"]/g, weight: 7 },
	{ pattern: /unsafe[A-Za-z_]*|reflect\.unsafe/g, weight: 4 },
	{ pattern: /db\.(?:Exec|Query|Raw)|raw_query|cursor\.execute|conn\.query/gi, weight: 5 },
	{ pattern: /\bSELECT\b[\s\S]{0,80}\bFROM\b/gi, weight: 3 },
	{
		pattern: /http\.(?:Handle|HandleFunc|Get|Post|Put|Delete)|router\.|app\.(?:get|post|put|delete)/g,
		weight: 5,
	},
	{ pattern: /jwt|oauth|saml|sso|auth(?:enticate|orize)?/gi, weight: 4 },
	{
		pattern:
			/\b(headers\s*\(\s*\)|request\.headers|req\.headers|getHeader|Header\.Get|x-forwarded-|x-real-ip|x-original-|x-rewrite-url|x-http-method-override|x-(?:user|auth|tenant|org|admin|internal|debug|preview|middleware))/gi,
		weight: 5,
	},
	{ pattern: /password|passwd|secret|api[_-]?key|token|credential/gi, weight: 3 },
	{ pattern: /crypto|md5|sha1|aes|rsa|pkcs|encrypt|decrypt|sign\(|verify\(/gi, weight: 3 },
	{ pattern: /pickle\.loads|yaml\.load|fromXml|XMLDecoder|unmarshal|deserialize/gi, weight: 6 },
	{ pattern: /readFile|writeFile|open\(|fopen|os\.path\.join|filepath\.Join/gi, weight: 2 },
	{ pattern: /redirect|sendFile|res\.send|response\.write|res\.json/gi, weight: 2 },
	{ pattern: /\.\.\/|path\.resolve|path\.join|os\.path\.abspath/g, weight: 2 },
	{ pattern: /shell=True|cmd \/c|sh -c|bash -c/g, weight: 6 },
	{ pattern: /requests\.(?:get|post)|axios|fetch\(|http\.Get|net\/http/g, weight: 3 },
	{ pattern: /\bSSRF\b|\bRCE\b|\bXXE\b|\bSSTI\b|\bIDOR\b|\bCSRF\b|\bXSS\b/g, weight: 5 },
];

/** Path-segment hints; weights stack additively. */
const PATH_SIGNALS: Array<{ segment: string; weight: number }> = [
	{ segment: "cmd", weight: 4 },
	{ segment: "main", weight: 3 },
	{ segment: "handlers", weight: 5 },
	{ segment: "handler", weight: 5 },
	{ segment: "routes", weight: 5 },
	{ segment: "route", weight: 5 },
	{ segment: "controllers", weight: 5 },
	{ segment: "controller", weight: 5 },
	{ segment: "api", weight: 4 },
	{ segment: "auth", weight: 5 },
	{ segment: "middleware", weight: 4 },
	{ segment: "server", weight: 3 },
	{ segment: "rpc", weight: 4 },
	{ segment: "gateway", weight: 4 },
	{ segment: "session", weight: 3 },
	{ segment: "permissions", weight: 4 },
	{ segment: "users", weight: 3 },
	{ segment: "admin", weight: 4 },
	{ segment: "upload", weight: 5 },
];

export interface EnumerateOptions {
	cwd: string;
	languages?: string[];
	limit?: number;
	includeTests?: boolean;
}

export interface EnumerateResult extends LongshotTargetsFile {}

/**
 * Walk the repo, score every candidate, and return the top `limit` ordered by
 * descending interestingness. Files that are too large, test, or generated
 * are filtered out before scoring.
 *
 * Caller is expected to write the result via `writeLongshotTargets` so the
 * file lands at the canonical path.
 */
export function enumerateTargets(options: EnumerateOptions): EnumerateResult {
	const cwd = options.cwd;
	const includeTests = options.includeTests ?? false;
	const limit = options.limit ?? LONGSHOT_DEFAULT_LIMIT;

	const requestedLanguages = options.languages?.length ? options.languages : detectLanguages(cwd);
	const allowedExts = expandExtensions(requestedLanguages);

	let skippedTests = 0;
	let skippedGenerated = 0;
	let skippedOversized = 0;
	let skippedUnrecognized = 0;

	const candidates: LongshotTarget[] = [];
	const candidateScores = readCandidateScores(cwd);

	const walk = (dir: string): void => {
		let entries: string[];
		try {
			entries = readdirSync(dir);
		} catch {
			return;
		}
		for (const entry of entries) {
			if (SKIP_DIRS.has(entry)) continue;
			if (entry.startsWith(".")) continue;
			const full = join(dir, entry);
			let st: ReturnType<typeof statSync>;
			try {
				st = statSync(full);
			} catch {
				continue;
			}
			if (st.isDirectory()) {
				if (!includeTests && TEST_DIR_NAMES.has(entry.toLowerCase())) {
					skippedTests++;
					continue;
				}
				walk(full);
				continue;
			}
			if (!st.isFile()) continue;

			const rel = relative(cwd, full).split("\\").join("/");
			const ext = extOf(entry);
			if (!ext || !allowedExts.has(ext)) {
				skippedUnrecognized++;
				continue;
			}
			if (!includeTests && isTestFile(rel)) {
				skippedTests++;
				continue;
			}
			if (isGeneratedFile(rel)) {
				skippedGenerated++;
				continue;
			}
			if (st.size > LONGSHOT_MAX_FILE_BYTES) {
				skippedOversized++;
				continue;
			}

			let content = "";
			try {
				content = readFileSync(full, "utf8");
			} catch {
				// Binary or unreadable; treat as zero score but keep ext-detected files.
			}

			const language = LANGUAGE_BY_EXT[ext] ?? "Unknown";
			const score = scoreFile(rel, content) + Math.min(candidateScores.get(rel) ?? 0, 250);
			const sha8 = createHash("sha1").update(rel).digest("hex").slice(0, 8);

			candidates.push({
				path: rel,
				language,
				score,
				bytes: st.size,
				sha8,
				status: "pending",
			});
		}
	};

	walk(cwd);

	candidates.sort((a, b) => {
		if (b.score !== a.score) return b.score - a.score;
		// Stable secondary sort: shorter paths first, then lexicographic.
		if (a.path.length !== b.path.length) return a.path.length - b.path.length;
		return a.path < b.path ? -1 : a.path > b.path ? 1 : 0;
	});

	const targets = candidates.slice(0, Math.max(0, limit));

	return {
		generated_at: new Date().toISOString(),
		cwd,
		languages: requestedLanguages,
		limit,
		total_candidates: candidates.length,
		skipped_tests: skippedTests,
		skipped_generated: skippedGenerated,
		skipped_oversized: skippedOversized,
		skipped_unrecognized: skippedUnrecognized,
		targets,
	};
}

export function scoreFile(relPath: string, content: string): number {
	let score = 0;
	const lower = relPath.toLowerCase();
	for (const { segment, weight } of PATH_SIGNALS) {
		if (lower.includes(`/${segment}/`) || lower.startsWith(`${segment}/`)) score += weight;
	}
	if (!content) return score;
	// Cap the haystack to avoid quadratic regex blowups on very large files.
	const haystack = content.length > 256 * 1024 ? content.slice(0, 256 * 1024) : content;
	for (const { pattern, weight } of CONTENT_SIGNALS) {
		const matches = haystack.match(pattern);
		if (matches) score += weight * Math.min(matches.length, 10);
	}
	return score;
}

export function detectLanguages(cwd: string): string[] {
	const counts: Record<string, number> = {};
	const walk = (dir: string, depth: number): void => {
		if (depth > 6) return;
		let entries: string[];
		try {
			entries = readdirSync(dir);
		} catch {
			return;
		}
		for (const entry of entries) {
			if (SKIP_DIRS.has(entry)) continue;
			if (entry.startsWith(".")) continue;
			const full = join(dir, entry);
			let st: ReturnType<typeof statSync>;
			try {
				st = statSync(full);
			} catch {
				continue;
			}
			if (st.isDirectory()) {
				walk(full, depth + 1);
				continue;
			}
			const ext = extOf(entry);
			if (!ext) continue;
			const lang = LANGUAGE_BY_EXT[ext];
			if (!lang) continue;
			counts[lang] = (counts[lang] ?? 0) + 1;
		}
	};
	walk(cwd, 0);
	const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
	if (sorted.length === 0) return [];
	const top = sorted[0]?.[1] ?? 0;
	// Include any language with at least 25% of the top language's file count
	// so polyglot repos (e.g. Go + Python) get full coverage.
	return sorted.filter(([, count]) => count >= top * 0.25).map(([lang]) => lang);
}

export function expandExtensions(languages: string[]): Set<string> {
	const out = new Set<string>();
	for (const lang of languages) {
		const exts = EXTS_BY_LANGUAGE[lang];
		if (exts) for (const ext of exts) out.add(ext);
	}
	return out;
}

export function isTestFile(relPath: string): boolean {
	for (const re of TEST_FILE_PATTERNS) {
		if (re.test(relPath)) return true;
	}
	return false;
}

export function isGeneratedFile(relPath: string): boolean {
	for (const re of GENERATED_FILE_PATTERNS) {
		if (re.test(relPath)) return true;
	}
	return false;
}

function extOf(filename: string): string | undefined {
	const dot = filename.lastIndexOf(".");
	if (dot <= 0) return undefined;
	return filename.slice(dot).toLowerCase();
}

export function longshotTargetsPath(cwd: string): string {
	return join(cwd, LONGSHOT_TARGETS_PATH);
}

export function readLongshotTargets(cwd: string): LongshotTargetsFile | undefined {
	const path = longshotTargetsPath(cwd);
	if (!existsSync(path)) return undefined;
	try {
		const raw = readFileSync(path, "utf8");
		const parsed = JSON.parse(raw) as unknown;
		if (
			parsed &&
			typeof parsed === "object" &&
			Array.isArray((parsed as { targets?: unknown }).targets)
		) {
			return parsed as LongshotTargetsFile;
		}
	} catch {
		// fall through
	}
	return undefined;
}

/**
 * Atomically rewrite the targets file under the file mutation queue. The
 * transformer receives the current state (or `undefined` if missing) and
 * returns the next state. Returning `undefined` aborts the write.
 */
export async function mutateLongshotTargets(
	cwd: string,
	transform: (state: LongshotTargetsFile | undefined) => LongshotTargetsFile | undefined,
): Promise<LongshotTargetsFile | undefined> {
	const path = longshotTargetsPath(cwd);
	return withFileMutationQueue(path, async () => {
		const current = readLongshotTargets(cwd);
		const next = transform(current);
		if (!next) return current;
		writeAtomic(path, `${JSON.stringify(next, null, "\t")}\n`);
		return next;
	});
}

function writeAtomic(path: string, content: string): void {
	mkdirSync(dirname(path), { recursive: true });
	const tmp = `${path}.tmp-${process.pid}-${Date.now()}`;
	writeFileSync(tmp, content);
	renameSync(tmp, path);
}

export function writeLongshotTargets(cwd: string, file: LongshotTargetsFile): void {
	writeAtomic(longshotTargetsPath(cwd), `${JSON.stringify(file, null, "\t")}\n`);
}

export interface UpdateTargetStatusOptions {
	status: LongshotTarget["status"];
	last_error?: string;
	completed_at?: string;
	run_id?: string;
	draft_count?: number;
	incrementAttempts?: boolean;
}

export async function updateTargetStatus(
	cwd: string,
	path: string,
	update: UpdateTargetStatusOptions,
): Promise<void> {
	await mutateLongshotTargets(cwd, (state) => {
		if (!state) return undefined;
		const idx = state.targets.findIndex((t) => t.path === path);
		if (idx < 0) return undefined;
		const prev = state.targets[idx];
		if (!prev) return undefined;
		const next: LongshotTarget = {
			...prev,
			status: update.status,
		};
		if (update.last_error !== undefined) next.last_error = update.last_error;
		if (update.completed_at !== undefined) next.completed_at = update.completed_at;
		if (update.run_id !== undefined) next.run_id = update.run_id;
		if (update.draft_count !== undefined) next.draft_count = update.draft_count;
		if (update.incrementAttempts) next.attempts = (prev.attempts ?? 0) + 1;
		const targets = [...state.targets];
		targets[idx] = next;
		return { ...state, targets };
	});
}

export interface PendingTarget {
	target: LongshotTarget;
}

/** Targets that still need work — pending or previously failed. */
export function pendingTargets(file: LongshotTargetsFile): LongshotTarget[] {
	return file.targets.filter((t) => t.status !== "complete");
}
