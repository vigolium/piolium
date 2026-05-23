/**
 * Deterministic candidate discovery.
 *
 * This pass runs before model-heavy phases and leaves durable evidence:
 * - `piolium/attack-surface/candidates.jsonl`
 * - `piolium/attack-surface/candidates-summary.md`
 * - `piolium/file-records/<source-path>.json`
 *
 * The records are intentionally lightweight. They help later agents spend
 * attention on higher-risk files without turning this phase into a separate
 * triage gate.
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, extname, join, relative, sep } from "node:path";
import { yieldToEventLoop } from "./retry.ts";

export const CANDIDATE_JSONL_PATH = "piolium/attack-surface/candidates.jsonl";
export const CANDIDATE_SUMMARY_PATH = "piolium/attack-surface/candidates-summary.md";
export const FILE_RECORDS_DIR = "piolium/file-records";

export type CandidateNoise = "precise" | "normal" | "noisy";

export interface CandidateMatch {
	slug: string;
	description: string;
	noise: CandidateNoise;
	filePath: string;
	line: number;
	snippet: string;
	matchedPattern: string;
	score: number;
	source: "builtin" | "custom";
}

export interface FileCandidateRecord {
	filePath: string;
	sha256: string;
	lastScannedAt: string;
	status: "candidate" | "clean";
	candidateCount: number;
	riskScore: number;
	owner?: string[];
	candidates: CandidateMatch[];
}

export interface CandidateScanResult {
	scannedFiles: number;
	candidateFiles: number;
	candidateCount: number;
	candidatesPath: string;
	summaryPath: string;
	fileRecordsDir: string;
	fileRecordsWritten: boolean;
}

export interface CandidateScanOptions {
	/**
	 * Per-file records are useful for offline diagnostics, but on large extracted
	 * appliances they create tens of thousands of tiny files. Keep them opt-in.
	 */
	writeFileRecords?: boolean;
	/** Abort signal for async scans. */
	signal?: AbortSignal;
	/**
	 * Async scans yield after this many candidate files so Pi can repaint status
	 * widgets during preflight. Defaults to 25 in `runCandidateScanAsync`.
	 */
	yieldEveryFiles?: number;
	/**
	 * Async scans yield after this many visited directory entries while walking
	 * the tree, including files that are skipped before content scanning.
	 */
	yieldEveryEntries?: number;
}

interface NativeMatcher {
	slug: string;
	description: string;
	noise: CandidateNoise;
	include?: string[];
	pathIncludes?: string[];
	patterns: Array<{ label: string; regex: RegExp }>;
	source: "builtin" | "custom";
}

interface CustomMatcherConfig {
	matchers?: Array<{
		slug?: string;
		description?: string;
		noise?: string;
		include?: string[];
		pathIncludes?: string[];
		regex?: string;
		flags?: string;
		label?: string;
	}>;
}

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
	"coverage",
	"piolium",
]);

const SOURCE_EXTENSIONS = new Set([
	".ts",
	".tsx",
	".js",
	".jsx",
	".mjs",
	".cjs",
	".py",
	".go",
	".rs",
	".rb",
	".java",
	".kt",
	".swift",
	".c",
	".h",
	".cpp",
	".cc",
	".hpp",
	".cs",
	".php",
	".vue",
	".svelte",
	".scala",
	".clj",
	".sh",
	".bash",
	".zsh",
	".sql",
	".lua",
	".m",
	".mm",
	".yml",
	".yaml",
	".json",
	".tf",
	".dockerfile",
]);

const SPECIAL_FILENAMES = new Set([
	"dockerfile",
	".env",
	"makefile",
	"jenkinsfile",
	"procfile",
	"cloudbuild.yaml",
	"cloudbuild.yml",
]);

const MAX_FILES_TO_SCAN = 80_000;
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_MATCHES_PER_MATCHER_PER_FILE = 20;
const FILE_RECORDS_ENV = "PIOLIUM_FILE_RECORDS";
const DEFAULT_ASYNC_YIELD_EVERY_FILES = 25;
const DEFAULT_ASYNC_YIELD_EVERY_ENTRIES = 100;

const PATH_RISK_HINTS = [
	"admin",
	"auth",
	"api",
	"route",
	"router",
	"handler",
	"controller",
	"upload",
	"download",
	"webhook",
	"payment",
	"billing",
	"permission",
	"policy",
	"middleware",
	"session",
	"token",
	"crypto",
	"secret",
	"gateway",
	"proxy",
	"terraform",
	"workflow",
	".github/workflows",
];

const NOISE_SCORE: Record<CandidateNoise, number> = {
	precise: 80,
	normal: 55,
	noisy: 30,
};

const BUILTIN_MATCHERS: NativeMatcher[] = [
	{
		slug: "command-execution",
		description: "Potential command execution or shell invocation with variable input.",
		noise: "precise",
		include: [".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".rb", ".php", ".java", ".sh"],
		patterns: [
			{ label: "node child_process", regex: /\b(exec|execSync|spawn|spawnSync)\s*\(/g },
			{
				label: "python process",
				regex: /\b(os\.system|subprocess\.(?:Popen|run|call|check_output))\s*\(/g,
			},
			{ label: "go command", regex: /\bexec\.Command(?:Context)?\s*\(/g },
			{ label: "php process", regex: /\b(shell_exec|system|passthru|proc_open|popen)\s*\(/g },
		],
		source: "builtin",
	},
	{
		slug: "dynamic-code-execution",
		description: "Dynamic code execution, expression evaluation, or runtime compilation.",
		noise: "precise",
		include: [".ts", ".tsx", ".js", ".jsx", ".py", ".rb", ".php", ".java"],
		patterns: [
			{ label: "eval", regex: /\beval\s*\(/g },
			{ label: "function constructor", regex: /\bnew\s+Function\s*\(/g },
			{ label: "python eval", regex: /\b(exec|eval|compile)\s*\(/g },
			{ label: "ruby eval", regex: /\b(instance_eval|class_eval|eval)\s*\(/g },
		],
		source: "builtin",
	},
	{
		slug: "raw-sql-query",
		description: "Raw SQL construction or query execution that may need parameterization review.",
		noise: "normal",
		include: [".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".rb", ".java", ".php", ".sql"],
		patterns: [
			{ label: "query call", regex: /\b(query|execute|raw|rawQuery|createQuery)\s*\(/g },
			{
				label: "sql keyword string",
				regex: /[`'"]\s*(SELECT|INSERT|UPDATE|DELETE|DROP)\b[\s\S]{0,160}\$\{/gi,
			},
			{ label: "string concat sql", regex: /\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b[^;\n]{0,160}\+/gi },
		],
		source: "builtin",
	},
	{
		slug: "ssrf-capable-request",
		description: "Outbound HTTP request site that may be attacker-controlled.",
		noise: "normal",
		include: [".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".rb", ".java", ".php"],
		patterns: [
			{
				label: "fetch/http client",
				regex: /\b(fetch|axios\.(?:get|post|request)|request|got|superagent)\s*\(/g,
			},
			{ label: "python requests", regex: /\brequests\.(?:get|post|put|delete|request)\s*\(/g },
			{
				label: "go http client",
				regex: /\bhttp\.(?:Get|Post|NewRequest|NewRequestWithContext)\s*\(/g,
			},
		],
		source: "builtin",
	},
	{
		slug: "path-traversal-file-access",
		description: "Filesystem access using path joins or user-controllable paths.",
		noise: "normal",
		include: [".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".rb", ".java", ".php"],
		patterns: [
			{
				label: "file read/write",
				regex: /\b(readFile|readFileSync|writeFile|writeFileSync|createReadStream|sendFile)\s*\(/g,
			},
			{ label: "path join", regex: /\b(path\.join|join|resolve)\s*\(/g },
			{ label: "python file open", regex: /\b(open|send_file|send_from_directory)\s*\(/g },
		],
		source: "builtin",
	},
	{
		slug: "unsafe-html-or-template",
		description: "HTML injection sink or template escape bypass.",
		noise: "normal",
		include: [".ts", ".tsx", ".js", ".jsx", ".vue", ".svelte", ".php", ".rb", ".py"],
		patterns: [
			{ label: "dangerous html", regex: /\bdangerouslySetInnerHTML\b|v-html\b|innerHTML\s*=/g },
			{ label: "template unescaped", regex: /\|\s*safe\b|raw\s*\}|unescapeHTML|html_safe\b/g },
		],
		source: "builtin",
	},
	{
		slug: "open-redirect",
		description: "Redirect sink that may accept user-controlled URLs.",
		noise: "normal",
		include: [".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".rb", ".java", ".php"],
		patterns: [
			{ label: "redirect call", regex: /\b(redirect|res\.redirect|ctx\.redirect|sendRedirect)\s*\(/g },
			{ label: "location header", regex: /\b(Location|setHeader)\s*\(\s*['"]Location['"]/g },
		],
		source: "builtin",
	},
	{
		slug: "weak-token-or-crypto",
		description: "Token, JWT, randomness, or crypto usage that deserves review.",
		noise: "normal",
		include: [".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".rb", ".java", ".php"],
		patterns: [
			{
				label: "jwt decode",
				regex: /\b(jwt\.decode|verify\s*:\s*false|algorithms?\s*:\s*\[\s*['"]none['"])/g,
			},
			{
				label: "weak random",
				regex: /\b(Math\.random|random\.random|rand\.Int|java\.util\.Random)\b/g,
			},
			{ label: "weak hash", regex: /\b(md5|sha1|createHash\s*\(\s*['"](?:md5|sha1)['"])\b/gi },
		],
		source: "builtin",
	},
	{
		slug: "secret-literal",
		description: "Hardcoded secret-like literal.",
		noise: "precise",
		include: [
			".ts",
			".tsx",
			".js",
			".jsx",
			".py",
			".go",
			".rb",
			".java",
			".php",
			".env",
			".yml",
			".yaml",
			".json",
		],
		patterns: [
			{
				label: "secret assignment",
				regex:
					/\b(api[_-]?key|secret|token|private[_-]?key|client[_-]?secret|password)\b\s*[:=]\s*['"][^'"\n]{12,}['"]/gi,
			},
			{ label: "private key", regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
		],
		source: "builtin",
	},
	{
		slug: "public-entrypoint",
		description: "Public route, handler, controller, workflow, or operation entry point.",
		noise: "noisy",
		include: [".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".rb", ".java", ".php"],
		pathIncludes: ["route", "router", "controller", "handler", "api", "pages", "app"],
		patterns: [
			{ label: "http route", regex: /\.(get|post|put|patch|delete|all)\s*\(\s*['"`/]/g },
			{
				label: "framework route",
				regex: /\b(route|router|app)\.(?:get|post|put|patch|delete|all)\s*\(/g,
			},
			{ label: "decorated route", regex: /@(Get|Post|Put|Patch|Delete|Controller|Route)\b/g },
			{ label: "python route", regex: /@\w+\.route\s*\(/g },
		],
		source: "builtin",
	},
	{
		slug: "webhook-without-obvious-signature",
		description: "Webhook handler path that should be checked for signature verification.",
		noise: "normal",
		pathIncludes: ["webhook"],
		patterns: [
			{ label: "webhook route", regex: /\b(webhook|stripe|github|slack|shopify|callback)\b/gi },
		],
		source: "builtin",
	},
	{
		slug: "hidden-control-channel",
		description:
			"Request header or framework/proxy context read that may influence auth, routing, tenant, runtime, debug, or middleware behavior.",
		noise: "normal",
		include: [".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".rb", ".java", ".kt", ".php", ".cs"],
		patterns: [
			{
				label: "request header read",
				regex:
					/\b(headers\s*\(\s*\)|(?:req|request|ctx|context|event|c|r)\.headers?\b|(?:getHeader|header|Header\.Get|headers\.get)\s*\()/g,
			},
			{
				label: "proxy or original request header",
				regex:
					/\b(?:x-forwarded-(?:for|host|proto|port|prefix)|forwarded|x-real-ip|x-original-(?:url|uri|method)|x-rewrite-url|x-http-method-override|host|origin|referer)\b/gi,
			},
			{
				label: "identity or internal control header",
				regex:
					/\b(?:x-(?:user|auth|tenant|org|workspace|role|admin|internal|debug|preview|middleware|subrequest)[a-z0-9_-]*|middleware|subrequest|preview[_-]?mode)\b/gi,
			},
		],
		source: "builtin",
	},
	{
		slug: "ci-agent-prompt-surface",
		description: "Workflow step passes issue, PR, commit, or comment data into an AI/agent command.",
		noise: "normal",
		include: [".yml", ".yaml"],
		pathIncludes: [".github/workflows"],
		patterns: [
			{
				label: "ai action with event context",
				regex:
					/\b(openai|codex|claude|gemini|copilot|ai|agent)\b[\s\S]{0,500}\$\{\{\s*github\.event\./gi,
			},
		],
		source: "builtin",
	},
	{
		slug: "container-or-iac-exposure",
		description: "Container or infrastructure config with public exposure or weak runtime defaults.",
		noise: "normal",
		include: [".tf", ".yml", ".yaml", "Dockerfile", ".dockerfile"],
		patterns: [
			{ label: "root user", regex: /^\s*USER\s+root\s*$/gim },
			{ label: "public ingress", regex: /0\.0\.0\.0\/0|::\/0/g },
			{ label: "wildcard iam", regex: /\b(Action|Resource)\s*=\s*["']\*["']/g },
			{ label: "latest tag", regex: /\bimage\s*[:=]\s*["']?[^'"\s:]+:latest\b/g },
		],
		source: "builtin",
	},
];

interface CandidateScanWorkState {
	scannedAt: string;
	candidates: CandidateMatch[];
	scannedFiles: number;
	candidateFiles: number;
	matchers: NativeMatcher[];
	recordsDir: string;
	writeFileRecords: boolean;
}

function beginCandidateScan(cwd: string, options: CandidateScanOptions): CandidateScanWorkState {
	const matchers = [...BUILTIN_MATCHERS, ...loadCustomMatchers(cwd)];
	const recordsDir = join(cwd, FILE_RECORDS_DIR);
	const writeFileRecords = options.writeFileRecords ?? shouldWriteFileRecords();
	if (writeFileRecords) mkdirSync(recordsDir, { recursive: true });
	return {
		scannedAt: new Date().toISOString(),
		candidates: [],
		scannedFiles: 0,
		candidateFiles: 0,
		matchers,
		recordsDir,
		writeFileRecords,
	};
}

function scanCandidateFile(cwd: string, state: CandidateScanWorkState, filePath: string): void {
	let raw: Buffer;
	try {
		raw = readFileSync(filePath);
	} catch {
		return;
	}
	if (raw.length > MAX_FILE_BYTES || raw.includes(0)) return;
	const relPath = normalizePath(relative(cwd, filePath));
	const content = raw.toString("utf8");
	const matches = matchFile(relPath, content, state.matchers);
	const riskScore = scoreFile(relPath, matches);
	const record: FileCandidateRecord = {
		filePath: relPath,
		sha256: createHash("sha256").update(raw).digest("hex"),
		lastScannedAt: state.scannedAt,
		status: matches.length > 0 ? "candidate" : "clean",
		candidateCount: matches.length,
		riskScore,
		candidates: matches,
	};
	if (state.writeFileRecords) writeJson(fileRecordPath(cwd, relPath), record);
	state.scannedFiles++;
	if (matches.length > 0) {
		state.candidateFiles++;
		state.candidates.push(...matches);
	}
}

function finishCandidateScan(cwd: string, state: CandidateScanWorkState): CandidateScanResult {
	state.candidates.sort(candidateSort);
	const candidatesPath = join(cwd, CANDIDATE_JSONL_PATH);
	mkdirSync(dirname(candidatesPath), { recursive: true });
	writeFileSync(
		candidatesPath,
		state.candidates.map((candidate) => JSON.stringify(candidate)).join("\n") +
			(state.candidates.length > 0 ? "\n" : ""),
	);

	const summaryPath = join(cwd, CANDIDATE_SUMMARY_PATH);
	writeFileSync(
		summaryPath,
		buildCandidateSummary({
			scannedFiles: state.scannedFiles,
			candidateFiles: state.candidateFiles,
			candidates: state.candidates,
			writeFileRecords: state.writeFileRecords,
		}),
	);

	return {
		scannedFiles: state.scannedFiles,
		candidateFiles: state.candidateFiles,
		candidateCount: state.candidates.length,
		candidatesPath,
		summaryPath,
		fileRecordsDir: state.recordsDir,
		fileRecordsWritten: state.writeFileRecords,
	};
}

export function runCandidateScan(
	cwd: string,
	options: CandidateScanOptions = {},
): CandidateScanResult {
	const state = beginCandidateScan(cwd, options);
	for (const filePath of walkCandidateFiles(cwd)) {
		if (state.scannedFiles >= MAX_FILES_TO_SCAN) break;
		scanCandidateFile(cwd, state, filePath);
	}
	return finishCandidateScan(cwd, state);
}

export async function runCandidateScanAsync(
	cwd: string,
	options: CandidateScanOptions = {},
): Promise<CandidateScanResult> {
	const state = beginCandidateScan(cwd, options);
	const yieldEveryFiles = Math.max(1, options.yieldEveryFiles ?? DEFAULT_ASYNC_YIELD_EVERY_FILES);
	let visitedFiles = 0;
	for await (const filePath of walkCandidateFilesAsync(cwd, options)) {
		if (options.signal?.aborted) throw options.signal.reason ?? new Error("Aborted");
		if (state.scannedFiles >= MAX_FILES_TO_SCAN) break;
		scanCandidateFile(cwd, state, filePath);
		visitedFiles++;
		if (visitedFiles % yieldEveryFiles === 0) {
			await yieldToEventLoop(options.signal);
		}
	}
	return finishCandidateScan(cwd, state);
}

export function candidateSummaryPath(cwd: string): string {
	return join(cwd, CANDIDATE_SUMMARY_PATH);
}

export function candidatesJsonlPath(cwd: string): string {
	return join(cwd, CANDIDATE_JSONL_PATH);
}

export function fileRecordsDir(cwd: string): string {
	return join(cwd, FILE_RECORDS_DIR);
}

export function readCandidateScores(cwd: string): Map<string, number> {
	const path = candidatesJsonlPath(cwd);
	const scores = new Map<string, number>();
	if (!existsSync(path)) return scores;
	for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
		const trimmed = line.trim();
		if (!trimmed) continue;
		try {
			const candidate = JSON.parse(trimmed) as CandidateMatch;
			const previous = scores.get(candidate.filePath) ?? 0;
			scores.set(candidate.filePath, previous + Math.max(1, candidate.score));
		} catch {}
	}
	return scores;
}

function* walkCandidateFiles(cwd: string): Generator<string> {
	function* walk(dir: string): Generator<string> {
		let entries: string[];
		try {
			entries = readdirSync(dir);
		} catch {
			return;
		}
		for (const entry of entries) {
			if (SKIP_DIRS.has(entry)) continue;
			if (entry.startsWith(".") && entry !== ".github" && !entry.startsWith(".env")) continue;
			const full = join(dir, entry);
			let st: ReturnType<typeof statSync>;
			try {
				st = statSync(full);
			} catch {
				continue;
			}
			if (st.isDirectory()) {
				yield* walk(full);
				continue;
			}
			if (!st.isFile()) continue;
			const rel = normalizePath(relative(cwd, full));
			if (isCandidateFile(rel)) yield full;
		}
	}
	yield* walk(cwd);
}

async function* walkCandidateFilesAsync(
	cwd: string,
	options: CandidateScanOptions,
): AsyncGenerator<string> {
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

	async function* walk(dir: string): AsyncGenerator<string> {
		if (options.signal?.aborted) throw options.signal.reason ?? new Error("Aborted");
		let entries: string[];
		try {
			entries = readdirSync(dir);
		} catch {
			return;
		}
		for (const entry of entries) {
			await maybeYield();
			if (options.signal?.aborted) throw options.signal.reason ?? new Error("Aborted");
			if (SKIP_DIRS.has(entry)) continue;
			if (entry.startsWith(".") && entry !== ".github" && !entry.startsWith(".env")) continue;
			const full = join(dir, entry);
			let st: ReturnType<typeof statSync>;
			try {
				st = statSync(full);
			} catch {
				continue;
			}
			if (st.isDirectory()) {
				yield* walk(full);
				continue;
			}
			if (!st.isFile()) continue;
			const rel = normalizePath(relative(cwd, full));
			if (isCandidateFile(rel)) yield full;
		}
	}

	yield* walk(cwd);
}

function isCandidateFile(relPath: string): boolean {
	const lower = relPath.toLowerCase();
	const base = lower.split("/").pop() ?? lower;
	if (SPECIAL_FILENAMES.has(base)) return true;
	if (lower.includes("/.github/workflows/")) return true;
	const ext = extname(base);
	return SOURCE_EXTENSIONS.has(ext);
}

function matchFile(relPath: string, content: string, matchers: NativeMatcher[]): CandidateMatch[] {
	const out: CandidateMatch[] = [];
	const lineStarts = buildLineStarts(content);
	for (const matcher of matchers) {
		if (!matcherApplies(matcher, relPath)) continue;
		let count = 0;
		for (const pattern of matcher.patterns) {
			const regex = withGlobal(pattern.regex);
			regex.lastIndex = 0;
			let match = regex.exec(content);
			while (match !== null) {
				const index = match.index;
				const line = lineNumberAt(lineStarts, index);
				const candidate: CandidateMatch = {
					slug: matcher.slug,
					description: matcher.description,
					noise: matcher.noise,
					filePath: relPath,
					line,
					snippet: extractLine(content, lineStarts, line),
					matchedPattern: pattern.label,
					score: scoreCandidate(relPath, matcher.noise, pattern.label),
					source: matcher.source,
				};
				out.push(candidate);
				count++;
				if (count >= MAX_MATCHES_PER_MATCHER_PER_FILE) break;
				if (match[0].length === 0) regex.lastIndex++;
				match = regex.exec(content);
			}
			if (count >= MAX_MATCHES_PER_MATCHER_PER_FILE) break;
		}
	}
	out.sort(candidateSort);
	return out;
}

function matcherApplies(matcher: NativeMatcher, relPath: string): boolean {
	const lower = relPath.toLowerCase();
	const include = matcher.include ?? [];
	const pathIncludes = matcher.pathIncludes ?? [];
	const includeMatches =
		include.length === 0 ||
		include.some((token) => {
			const normalized = token.toLowerCase();
			if (normalized.startsWith(".")) return lower.endsWith(normalized);
			if (normalized.includes("/")) return lower.includes(normalizePath(normalized));
			return (lower.split("/").pop() ?? lower) === normalized;
		});
	const pathMatches =
		pathIncludes.length === 0 ||
		pathIncludes.some((token) => lower.includes(normalizePath(token.toLowerCase())));
	return includeMatches && pathMatches;
}

function scoreCandidate(relPath: string, noise: CandidateNoise, patternLabel: string): number {
	let score = NOISE_SCORE[noise];
	const lower = relPath.toLowerCase();
	for (const hint of PATH_RISK_HINTS) {
		if (lower.includes(hint)) score += 8;
	}
	if (/signature|secret|private|command|eval|redirect/i.test(patternLabel)) score += 10;
	return score;
}

function scoreFile(relPath: string, matches: CandidateMatch[]): number {
	if (matches.length === 0) return 0;
	const top = matches
		.map((m) => m.score)
		.sort((a, b) => b - a)
		.slice(0, 5)
		.reduce((sum, score) => sum + score, 0);
	const diversity = new Set(matches.map((m) => m.slug)).size * 12;
	const lower = relPath.toLowerCase();
	const pathBonus = PATH_RISK_HINTS.some((hint) => lower.includes(hint)) ? 20 : 0;
	return top + diversity + pathBonus;
}

function candidateSort(a: CandidateMatch, b: CandidateMatch): number {
	if (b.score !== a.score) return b.score - a.score;
	const file = a.filePath.localeCompare(b.filePath);
	if (file !== 0) return file;
	return a.line - b.line;
}

function buildCandidateSummary(input: {
	scannedFiles: number;
	candidateFiles: number;
	candidates: CandidateMatch[];
	writeFileRecords: boolean;
}): string {
	const lines: string[] = [];
	lines.push("# Candidate Scan");
	lines.push("");
	lines.push(`Generated by piolium at ${new Date().toISOString()}`);
	lines.push("");
	lines.push("## Totals");
	lines.push("");
	lines.push(`- Files scanned: ${input.scannedFiles}`);
	lines.push(`- Candidate files: ${input.candidateFiles}`);
	lines.push(`- Candidate matches: ${input.candidates.length}`);
	lines.push(
		`- Per-file records: ${input.writeFileRecords ? `written to \`${FILE_RECORDS_DIR}/\`` : `disabled (set ${FILE_RECORDS_ENV}=1 to enable)`}`,
	);
	lines.push("");

	const bySlug = new Map<string, { count: number; maxScore: number; description: string }>();
	for (const candidate of input.candidates) {
		const current = bySlug.get(candidate.slug);
		if (current) {
			current.count++;
			current.maxScore = Math.max(current.maxScore, candidate.score);
		} else {
			bySlug.set(candidate.slug, {
				count: 1,
				maxScore: candidate.score,
				description: candidate.description,
			});
		}
	}
	lines.push("## Candidate Classes");
	lines.push("");
	if (bySlug.size === 0) {
		lines.push("(none)");
	} else {
		for (const [slug, info] of [...bySlug.entries()].sort(
			(a, b) => b[1].maxScore - a[1].maxScore || b[1].count - a[1].count,
		)) {
			lines.push(
				`- ${slug}: ${info.count} match(es), max score ${info.maxScore}. ${info.description}`,
			);
		}
	}
	lines.push("");

	const byFile = new Map<string, { count: number; score: number }>();
	for (const candidate of input.candidates) {
		const current = byFile.get(candidate.filePath) ?? { count: 0, score: 0 };
		current.count++;
		current.score += candidate.score;
		byFile.set(candidate.filePath, current);
	}
	lines.push("## Top Files");
	lines.push("");
	const topFiles = [...byFile.entries()]
		.sort((a, b) => b[1].score - a[1].score || b[1].count - a[1].count)
		.slice(0, 40);
	if (topFiles.length === 0) {
		lines.push("(none)");
	} else {
		for (const [filePath, info] of topFiles) {
			lines.push(`- \`${filePath}\`: score ${info.score}, ${info.count} match(es)`);
		}
	}
	lines.push("");

	lines.push("## Highest-Ranked Matches");
	lines.push("");
	const topMatches = input.candidates.slice(0, 80);
	if (topMatches.length === 0) {
		lines.push("(none)");
	} else {
		for (const candidate of topMatches) {
			lines.push(
				`- ${candidate.slug} (${candidate.noise}, score ${candidate.score}) at \`${candidate.filePath}:${candidate.line}\` - ${candidate.snippet}`,
			);
		}
	}
	lines.push("");
	lines.push("## Custom Matchers");
	lines.push("");
	lines.push(
		"Project matchers can be added at `piolium/matchers.json`, `piolium/custom-matchers.json`, or `.piolium-matchers.json`.",
	);
	return `${lines.join("\n")}\n`;
}

function loadCustomMatchers(cwd: string): NativeMatcher[] {
	const paths = [
		join(cwd, "piolium", "matchers.json"),
		join(cwd, "piolium", "custom-matchers.json"),
		join(cwd, ".piolium-matchers.json"),
	];
	const out: NativeMatcher[] = [];
	for (const path of paths) {
		if (!existsSync(path)) continue;
		let config: CustomMatcherConfig;
		try {
			config = JSON.parse(readFileSync(path, "utf8")) as CustomMatcherConfig;
		} catch (err) {
			console.warn(
				`[piolium] Ignoring custom matcher file ${path}: invalid JSON (${err instanceof Error ? err.message : String(err)}).`,
			);
			continue;
		}
		for (const custom of config.matchers ?? []) {
			if (!custom.slug || !custom.regex) continue;
			const slug = slugify(custom.slug);
			if (!slug) continue;
			const noise = normalizeNoise(custom.noise);
			try {
				const flags = normalizeRegexFlags(custom.flags);
				out.push({
					slug,
					description: custom.description ?? `Custom matcher ${slug}.`,
					noise,
					...(custom.include ? { include: custom.include } : {}),
					...(custom.pathIncludes ? { pathIncludes: custom.pathIncludes } : {}),
					patterns: [
						{
							label: custom.label ?? slug,
							regex: new RegExp(custom.regex, flags),
						},
					],
					source: "custom",
				});
			} catch (err) {
				console.warn(
					`[piolium] Skipping custom matcher "${slug}" in ${path}: invalid regex (${err instanceof Error ? err.message : String(err)}).`,
				);
			}
		}
	}
	return out;
}

function normalizeNoise(value: unknown): CandidateNoise {
	return value === "precise" || value === "normal" || value === "noisy" ? value : "normal";
}

function normalizeRegexFlags(flags: string | undefined): string {
	const raw = flags ?? "g";
	const unique = [...new Set(raw.split(""))].filter((flag) => /^[dgimsuvy]$/.test(flag)).join("");
	return unique.includes("g") ? unique : `${unique}g`;
}

function withGlobal(regex: RegExp): RegExp {
	const flags = regex.flags.includes("g") ? regex.flags : `${regex.flags}g`;
	return new RegExp(regex.source, flags);
}

function buildLineStarts(content: string): number[] {
	const starts = [0];
	for (let i = 0; i < content.length; i++) {
		if (content.charCodeAt(i) === 10) starts.push(i + 1);
	}
	return starts;
}

function lineNumberAt(lineStarts: number[], index: number): number {
	let lo = 0;
	let hi = lineStarts.length - 1;
	while (lo <= hi) {
		const mid = Math.floor((lo + hi) / 2);
		const start = lineStarts[mid] ?? 0;
		const next = lineStarts[mid + 1] ?? Number.POSITIVE_INFINITY;
		if (index >= start && index < next) return mid + 1;
		if (index < start) hi = mid - 1;
		else lo = mid + 1;
	}
	return 1;
}

function extractLine(content: string, lineStarts: number[], line: number): string {
	const start = lineStarts[line - 1] ?? 0;
	const end = lineStarts[line] !== undefined ? lineStarts[line] - 1 : content.length;
	return content.slice(start, end).trim().replace(/\s+/g, " ").slice(0, 220);
}

function writeJson(path: string, value: unknown): void {
	mkdirSync(dirname(path), { recursive: true });
	writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function shouldWriteFileRecords(): boolean {
	const value = process.env[FILE_RECORDS_ENV]?.trim().toLowerCase();
	return value === "1" || value === "true" || value === "yes" || value === "on";
}

function fileRecordPath(cwd: string, relPath: string): string {
	const normalized = normalizePath(relPath)
		.split("/")
		.filter((part) => part && part !== "." && part !== "..")
		.join("/");
	return join(cwd, FILE_RECORDS_DIR, `${normalized}.json`);
}

function normalizePath(path: string): string {
	return path.split(sep).join("/");
}

function slugify(value: string): string {
	return value
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "-")
		.replace(/^-+|-+$/g, "")
		.slice(0, 80);
}
