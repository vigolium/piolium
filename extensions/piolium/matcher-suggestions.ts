import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, extname, join } from "node:path";
import { splitFrontmatter } from "./agents.ts";
import { listFindingDirs } from "./findings.ts";
import {
	collectCandidateWords,
	collectExistingMatcherSlugs,
	mergeMatcherConfig,
} from "./matcher-utils.ts";

export interface MatcherSuggestion {
	slug: string;
	description: string;
	noise: "normal";
	include: string[];
	pathIncludes?: string[];
	regex: string;
	flags: "gi";
	label: string;
	originFinding: string;
}

export interface MatcherLearnResult {
	suggestions: MatcherSuggestion[];
	suggestionsPath: string;
	appliedPath?: string;
	lines: string[];
}

export function runMatcherLearn(
	cwd: string,
	options: { apply?: boolean } = {},
): MatcherLearnResult {
	const suggestions = buildMatcherSuggestions(cwd);
	const suggestionsPath = join(cwd, "piolium", "attack-surface", "matcher-suggestions.json");
	mkdirSync(dirname(suggestionsPath), { recursive: true });
	writeFileSync(
		suggestionsPath,
		`${JSON.stringify({ generated_at: new Date().toISOString(), matchers: suggestions }, null, 2)}\n`,
	);

	let appliedPath: string | undefined;
	if (options.apply && suggestions.length > 0) {
		appliedPath = join(cwd, "piolium", "matchers.json");
		const merged = mergeMatcherConfig(appliedPath, suggestions);
		mkdirSync(dirname(appliedPath), { recursive: true });
		writeFileSync(appliedPath, `${JSON.stringify(merged, null, 2)}\n`);
	}

	return {
		suggestions,
		suggestionsPath,
		...(appliedPath ? { appliedPath } : {}),
		lines: [
			`Suggestions: ${suggestions.length}`,
			`Output:      ${suggestionsPath}`,
			...(appliedPath ? [`Applied to:  ${appliedPath}`] : []),
			"",
			...suggestions
				.slice(0, 30)
				.map((suggestion) => `- ${suggestion.slug}: ${suggestion.description}`),
			...(suggestions.length > 30 ? [`... ${suggestions.length - 30} more`] : []),
		],
	};
}

function buildMatcherSuggestions(cwd: string): MatcherSuggestion[] {
	const existingSlugs = collectExistingMatcherSlugs([
		join(cwd, "piolium", "matchers.json"),
		join(cwd, "piolium", "custom-matchers.json"),
		join(cwd, ".piolium-matchers.json"),
	]);
	const suggestions: MatcherSuggestion[] = [];
	for (const finding of listFindingDirs(cwd)) {
		const draftPath = join(finding.path, "draft.md");
		if (!existsSync(draftPath)) continue;
		const raw = readFileSync(draftPath, "utf8");
		const { frontmatter, body } = splitFrontmatter(raw);
		const title =
			stringValue(frontmatter.title) ??
			stringValue(frontmatter.name) ??
			body.match(/^#\s+(.+)$/m)?.[1]?.trim() ??
			finding.slug;
		const words = collectCandidateWords(
			`${finding.slug} ${title} ${stringValue(frontmatter.class) ?? ""}`,
		);
		if (words.length === 0) continue;
		const files = collectFiles(frontmatter, body);
		const include = collectExtensions(files);
		const pathIncludes = collectPathHints(files);
		const slug = uniqueSlug(`learned-${finding.slug}`, existingSlugs);
		existingSlugs.add(slug);
		suggestions.push({
			slug,
			description: `Suggested matcher from finding ${finding.id}-${finding.slug}.`,
			noise: "normal",
			include:
				include.length > 0
					? include
					: [".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".rb", ".java", ".php"],
			...(pathIncludes.length > 0 ? { pathIncludes } : {}),
			regex: `\\b(${words.map(escapeRegex).join("|")})\\b`,
			flags: "gi",
			label: "learned finding keyword",
			originFinding: `${finding.id}-${finding.slug}`,
		});
	}
	return suggestions;
}

function collectFiles(frontmatter: Record<string, unknown>, body: string): string[] {
	const files = new Set<string>();
	for (const value of Object.values(frontmatter)) {
		if (typeof value === "string") addFile(files, value);
		else if (Array.isArray(value)) {
			for (const item of value) {
				if (typeof item === "string") addFile(files, item);
			}
		}
	}
	for (const match of body.matchAll(
		/([A-Za-z0-9_./-]+\.(?:ts|tsx|js|jsx|py|go|rs|rb|java|kt|swift|c|h|cpp|cc|hpp|cs|php|scala|clj|sh|sql|lua|tf|ya?ml))(?:[:#]\d+)?/g,
	)) {
		if (match[1]) addFile(files, match[1]);
	}
	return [...files].sort();
}

function addFile(files: Set<string>, value: string): void {
	const cleaned = value.replace(/[:#]\d+(?::\d+)?$/, "").trim();
	if (!cleaned || cleaned.startsWith("http")) return;
	if (
		/\.(ts|tsx|js|jsx|py|go|rs|rb|java|kt|swift|c|h|cpp|cc|hpp|cs|php|scala|clj|sh|sql|lua|tf|ya?ml)$/i.test(
			cleaned,
		)
	) {
		files.add(cleaned);
	}
}

function collectExtensions(files: string[]): string[] {
	const exts = [...new Set(files.map((file) => extname(file).toLowerCase()).filter(Boolean))];
	return exts.slice(0, 8);
}

function collectPathHints(files: string[]): string[] {
	const hints = new Set<string>();
	for (const file of files) {
		for (const part of file.toLowerCase().split("/")) {
			if (
				[
					"admin",
					"auth",
					"api",
					"route",
					"routes",
					"handler",
					"handlers",
					"controller",
					"upload",
					"webhook",
					"payment",
					"billing",
					"permission",
					"policy",
				].includes(part)
			) {
				hints.add(part);
			}
		}
	}
	return [...hints].slice(0, 8);
}

function uniqueSlug(base: string, seen: Set<string>): string {
	const normalized = base
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "-")
		.replace(/^-+|-+$/g, "")
		.slice(0, 70);
	let candidate = normalized || "learned-finding";
	let index = 2;
	while (seen.has(candidate)) {
		candidate = `${normalized}-${index}`;
		index++;
	}
	return candidate;
}

function stringValue(value: unknown): string | undefined {
	return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

function escapeRegex(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
