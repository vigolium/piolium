import { existsSync, readFileSync } from "node:fs";

export interface JsonMatcher {
	slug: string;
	description?: string;
	noise?: string;
	include?: string[];
	pathIncludes?: string[];
	regex: string;
	flags?: string;
	label?: string;
	originFinding?: string;
}

export interface MatcherConfig {
	matchers: JsonMatcher[];
}

const STOP_WORDS = new Set([
	"the",
	"and",
	"for",
	"with",
	"from",
	"into",
	"that",
	"this",
	"when",
	"where",
	"finding",
	"issue",
	"bug",
	"vulnerability",
	"allows",
	"allow",
	"using",
	"missing",
	"unsafe",
	"weak",
]);

export function collectCandidateWords(input: string): string[] {
	const words = input
		.toLowerCase()
		.split(/[^a-z0-9]+/)
		.map((word) => word.trim())
		.filter((word) => word.length >= 4 && !STOP_WORDS.has(word));
	return [...new Set(words)].slice(0, 8);
}

export function collectExistingMatcherSlugs(paths: string[]): Set<string> {
	const slugs = new Set<string>();
	for (const path of paths) {
		if (!existsSync(path)) continue;
		try {
			const config = JSON.parse(readFileSync(path, "utf8")) as Partial<MatcherConfig>;
			for (const matcher of config.matchers ?? []) {
				if (typeof matcher.slug === "string") slugs.add(matcher.slug);
			}
		} catch {}
	}
	return slugs;
}

export function mergeMatcherConfig(path: string, suggestions: JsonMatcher[]): MatcherConfig {
	let existing: MatcherConfig = { matchers: [] };
	if (existsSync(path)) {
		try {
			const parsed = JSON.parse(readFileSync(path, "utf8")) as Partial<MatcherConfig>;
			existing = { matchers: Array.isArray(parsed.matchers) ? parsed.matchers : [] };
		} catch {
			existing = { matchers: [] };
		}
	}
	const seen = new Set(existing.matchers.map((matcher) => matcher.slug));
	const merged = [...existing.matchers];
	for (const suggestion of suggestions) {
		if (seen.has(suggestion.slug)) continue;
		seen.add(suggestion.slug);
		merged.push(suggestion);
	}
	return { matchers: merged };
}
