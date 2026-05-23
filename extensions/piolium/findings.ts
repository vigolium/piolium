/**
 * Helpers for working with `piolium/findings-draft/` and
 * `piolium/findings/<id>-<slug>/`.
 *
 * The on-disk layout is a stable contract so artifact files stay portable
 * across runs and interoperating tooling. Promotion (draft → finding
 * directory) happens after Review Chamber phases when the orchestrator
 * decides which drafts have survived dedup / FP elimination.
 */

import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { parse as parseYaml, stringify as stringifyYaml } from "./_vendor/yaml.bundle.mjs";
import { splitFrontmatter } from "./agents.ts";

export interface FindingDraft {
	path: string;
	id: string;
	slug: string;
	severity: "critical" | "high" | "medium" | "low" | "info";
	phase?: string;
	status?: string;
	verdict?: string;
	body: string;
	frontmatter: Record<string, unknown>;
}

export interface FindingDir {
	id: string;
	slug: string;
	path: string;
	hasReport: boolean;
	hasPoc: boolean;
	hasEvidence: boolean;
}

export function findingsDraftDir(cwd: string): string {
	return join(cwd, "piolium", "findings-draft");
}

export function findingsDir(cwd: string): string {
	return join(cwd, "piolium", "findings");
}

const SEVERITIES = new Set<FindingDraft["severity"]>(["critical", "high", "medium", "low", "info"]);

function normalizeSeverity(value: unknown): FindingDraft["severity"] {
	if (typeof value !== "string") return "info";
	const lower = value.toLowerCase().trim() as FindingDraft["severity"];
	return SEVERITIES.has(lower) ? lower : "info";
}

export function listDraftFindings(cwd: string, prefix?: string): FindingDraft[] {
	const dir = findingsDraftDir(cwd);
	if (!existsSync(dir)) return [];
	const out: FindingDraft[] = [];
	for (const entry of readdirSync(dir).sort()) {
		if (!entry.endsWith(".md")) continue;
		if (prefix && !entry.startsWith(prefix)) continue;
		const path = join(dir, entry);
		try {
			const raw = readFileSync(path, "utf8");
			const { frontmatter, body } = splitFrontmatter(raw);
			const id =
				typeof frontmatter.id === "string"
					? frontmatter.id
					: (basename(entry, ".md").split("-")[0] ?? basename(entry, ".md"));
			const slug =
				typeof frontmatter.slug === "string"
					? frontmatter.slug
					: basename(entry, ".md").replace(/^[a-z0-9]+-\d+-?/i, "");
			out.push({
				path,
				id,
				slug,
				severity: normalizeSeverity(frontmatter.severity),
				...(typeof frontmatter.phase === "string" ? { phase: frontmatter.phase } : {}),
				...(typeof frontmatter.status === "string" ? { status: frontmatter.status } : {}),
				...(typeof frontmatter.verdict === "string" ? { verdict: frontmatter.verdict } : {}),
				body,
				frontmatter,
			});
		} catch {
			// skip malformed files
		}
	}
	return out;
}

// Match `<id>-<slug>` directory names. Ordered alternatives (longest-first):
//   FP-<phase>-<seq>  (e.g. FP-p8-001-…)
//   <phase>-<seq>     (e.g. p8-001-…, q1-002-…)
//   FP-<sev><n>       (e.g. FP-H1-…)
//   <sev><n>          (e.g. C1-…, H1-…, M1-…)
//   <seq>             (legacy bare-numeric ids)
const FINDING_DIR_RE = /^((?:FP-)?[A-Za-z0-9]+-\d+|(?:FP-)?[A-Za-z]+\d+|\d+)-(.+)$/;

export function parseFindingDirName(entry: string): { id: string; slug: string } {
	const m = entry.match(FINDING_DIR_RE);
	if (m?.[1] && m?.[2]) return { id: m[1], slug: m[2] };
	const parts = entry.split("-");
	return parts.length > 1
		? { id: parts.slice(0, -1).join("-"), slug: parts[parts.length - 1] ?? entry }
		: { id: entry, slug: entry };
}

export function listFindingDirs(cwd: string): FindingDir[] {
	const root = findingsDir(cwd);
	if (!existsSync(root)) return [];
	const out: FindingDir[] = [];
	for (const entry of readdirSync(root).sort()) {
		const path = join(root, entry);
		if (!statSync(path).isDirectory()) continue;
		const { id, slug } = parseFindingDirName(entry);
		out.push({
			id,
			slug,
			path,
			hasReport: existsSync(join(path, "report.md")),
			hasPoc: readdirSync(path).some((f) => f.startsWith("poc.")),
			hasEvidence: existsSync(join(path, "evidence")),
		});
	}
	return out;
}

/**
 * Promote a draft into a finding directory. Idempotent — calling twice with
 * the same draft is a no-op once the finding dir exists. Returns the
 * finding dir path.
 */
export function promoteDraftToFinding(cwd: string, draft: FindingDraft): string {
	const dirName = `${draft.id}-${draft.slug}`;
	const dir = join(findingsDir(cwd), dirName);
	if (existsSync(dir)) return dir;
	mkdirSync(dir, { recursive: true });
	const out: Record<string, unknown> = { ...draft.frontmatter };
	out.id = draft.id;
	out.slug = draft.slug;
	out.severity = draft.severity;
	const draftPath = join(dir, "draft.md");
	const yaml = stringifyYaml(out, { lineWidth: 0 }).trimEnd();
	writeFileSync(draftPath, `---\n${yaml}\n---\n\n${draft.body.trimStart()}`);
	return dir;
}

export interface PromotionResult {
	promoted: string[]; // finding dir paths
	skipped: string[]; // already-existing finding dir paths
}

/**
 * Promote every draft in `piolium/findings-draft/` matching `prefix` to a
 * finding directory. Returns the list of dirs written and the list of dirs
 * that were already present.
 */
export function promoteDraftsByPrefix(cwd: string, prefix: string): PromotionResult {
	const drafts = listDraftFindings(cwd, prefix);
	const promoted: string[] = [];
	const skipped: string[] = [];
	for (const draft of drafts) {
		if (isRejectedDraft(draft) || draft.severity === "low" || draft.severity === "info") continue;
		const dirName = `${draft.id}-${draft.slug}`;
		const dirPath = join(findingsDir(cwd), dirName);
		const existed = existsSync(dirPath);
		promoteDraftToFinding(cwd, draft);
		if (existed) skipped.push(dirPath);
		else promoted.push(dirPath);
	}
	return { promoted, skipped };
}

export interface ConsolidationEntry {
	/** New severity-prefixed id assigned during consolidation, e.g. "C1", "H1", "M1". */
	id: string;
	slug: string;
	severity: "critical" | "high" | "medium";
	/** Original draft id from frontmatter, e.g. "q2-001", "p8-003". */
	originalId: string;
	/** Phase id from the draft frontmatter, when present. */
	phase?: string;
	/** Path to the source draft file in `piolium/findings-draft/`. */
	sourcePath: string;
	/** Path to the created finding directory under `piolium/findings/`. */
	findingDir: string;
}

export interface ConsolidationDropped {
	originalId: string;
	severity: FindingDraft["severity"];
	sourcePath: string;
	reason: "below-threshold" | "rejected";
	status?: string;
}

export interface ConsolidationResult {
	promoted: ConsolidationEntry[];
	dropped: ConsolidationDropped[];
}

const SEVERITY_RANK: Record<FindingDraft["severity"], number> = {
	critical: 0,
	high: 1,
	medium: 2,
	low: 3,
	info: 4,
};

const SEVERITY_LETTER = { critical: "C", high: "H", medium: "M" } as const;

const REJECTED_VALUES = new Set([
	"rejected",
	"rejected-fp",
	"false-positive",
	"false_positive",
	"fp",
	"invalid",
	"not-valid",
	"not_valid",
	"noise",
	"non-security",
	"non_security",
]);

export function isRejectedDraft(draft: FindingDraft): boolean {
	const values = [
		draft.status,
		draft.verdict,
		draft.frontmatter.outcome,
		draft.frontmatter.decision,
		draft.frontmatter.fp_status,
		draft.frontmatter.confirm_status,
		draft.frontmatter["Confirm-Status"],
	];
	return values.some((value) => {
		if (typeof value !== "string") return false;
		const normalized = value.toLowerCase().trim();
		return REJECTED_VALUES.has(normalized) || normalized.includes("false-positive");
	});
}

export function isPromotableDraft(draft: FindingDraft): boolean {
	return !isRejectedDraft(draft) && draft.severity !== "low" && draft.severity !== "info";
}

/**
 * Promote drafts matching any of `prefixes` into severity-prefixed finding
 * directories. Drafts with severity below "medium" are dropped (not
 * promoted) by convention. Returns a
 * manifest of the promotions and drops, suitable for serializing as a
 * consolidation manifest.
 *
 * IDs are assigned deterministically: drafts are stable-sorted by
 * (severity, source path), then numbered C1.. / H1.. / M1.. per severity.
 *
 * If a finding directory with the same `<id>-<slug>` name already exists,
 * the existing directory is reused (idempotent for re-runs / resume).
 */
export function consolidateDrafts(cwd: string, prefixes: string[]): ConsolidationResult {
	const seen = new Set<string>();
	const drafts: FindingDraft[] = [];
	for (const prefix of prefixes) {
		for (const draft of listDraftFindings(cwd, prefix)) {
			if (seen.has(draft.path)) continue;
			seen.add(draft.path);
			drafts.push(draft);
		}
	}
	drafts.sort((a, b) => {
		const sa = SEVERITY_RANK[a.severity];
		const sb = SEVERITY_RANK[b.severity];
		if (sa !== sb) return sa - sb;
		return a.path.localeCompare(b.path);
	});

	const counters: Record<"critical" | "high" | "medium", number> = {
		critical: 0,
		high: 0,
		medium: 0,
	};
	const promoted: ConsolidationEntry[] = [];
	const dropped: ConsolidationDropped[] = [];
	for (const draft of drafts) {
		if (isRejectedDraft(draft)) {
			dropped.push({
				originalId: draft.id,
				severity: draft.severity,
				sourcePath: draft.path,
				reason: "rejected",
				...((draft.status ?? draft.verdict) ? { status: draft.status ?? draft.verdict } : {}),
			});
			continue;
		}
		if (draft.severity === "low" || draft.severity === "info") {
			dropped.push({
				originalId: draft.id,
				severity: draft.severity,
				sourcePath: draft.path,
				reason: "below-threshold",
			});
			continue;
		}
		counters[draft.severity] += 1;
		const newId = `${SEVERITY_LETTER[draft.severity]}${counters[draft.severity]}`;
		const promotedDraft: FindingDraft = {
			...draft,
			id: newId,
			frontmatter: {
				...draft.frontmatter,
				original_id: draft.id,
				...(draft.phase ? { phase: draft.phase } : {}),
			},
		};
		const findingDir = promoteDraftToFinding(cwd, promotedDraft);
		mkdirSync(join(findingDir, "evidence"), { recursive: true });
		promoted.push({
			id: newId,
			slug: draft.slug,
			severity: draft.severity,
			originalId: draft.id,
			...(draft.phase ? { phase: draft.phase } : {}),
			sourcePath: draft.path,
			findingDir,
		});
	}
	return { promoted, dropped };
}

export interface FindingFrontmatter {
	id: string;
	slug: string;
	severity: FindingDraft["severity"];
	[k: string]: unknown;
}

export function readFindingFrontmatter(findingDir: string): FindingFrontmatter | undefined {
	const draft = join(findingDir, "draft.md");
	if (!existsSync(draft)) return undefined;
	let frontmatter: Record<string, unknown>;
	try {
		({ frontmatter } = splitFrontmatter(readFileSync(draft, "utf8")));
	} catch {
		return undefined;
	}
	const id = typeof frontmatter.id === "string" ? frontmatter.id : "";
	const slug = typeof frontmatter.slug === "string" ? frontmatter.slug : "";
	if (!id || !slug) return undefined;
	return {
		...frontmatter,
		id,
		slug,
		severity: normalizeSeverity(frontmatter.severity),
	};
}

/** Re-export for callers that already imported via this module. */
export { parseYaml, stringifyYaml };
