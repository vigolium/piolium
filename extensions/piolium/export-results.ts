import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, extname, isAbsolute, join, relative, resolve } from "node:path";
import { splitFrontmatter } from "./agents.ts";
import { type FindingDraft, listFindingDirs, readFindingFrontmatter } from "./findings.ts";

export type ExportFormat = "json" | "md-dir";

export interface ExportOptions {
	format?: ExportFormat;
	outPath?: string;
	minSeverity?: FindingDraft["severity"];
	onlySeverity?: FindingDraft["severity"][];
	confirmedOnly?: boolean;
	excludeFp?: boolean;
	since?: string;
	requireOwner?: boolean;
}

export interface ExportedFinding {
	id: string;
	slug: string;
	title: string;
	severity: FindingDraft["severity"];
	status?: string;
	confirmStatus?: string;
	owners: string[];
	labels: string[];
	files: string[];
	findingDir: string;
	draftPath?: string;
	reportPath?: string;
	updatedAt: string;
	frontmatter: Record<string, unknown>;
}

export interface ExportResult {
	findings: ExportedFinding[];
	outPath: string;
	format: ExportFormat;
	lines: string[];
}

interface CodeownerRule {
	pattern: string;
	owners: string[];
}

const SEVERITY_ORDER: Record<FindingDraft["severity"], number> = {
	critical: 0,
	high: 1,
	medium: 2,
	low: 3,
	info: 4,
};

const CODEOWNER_PATHS = ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"];

export function runExport(cwd: string, options: ExportOptions = {}): ExportResult {
	const format = options.format ?? "json";
	const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
	const outPath = resolveOutputPath(
		cwd,
		options.outPath ??
			join("piolium", "exports", `findings-${timestamp}${format === "json" ? ".json" : ""}`),
	);
	const owners = loadCodeowners(cwd);
	const sinceMs = options.since ? Date.parse(options.since) : undefined;
	const findings = listFindingDirs(cwd)
		.map((dir) => readExportedFinding(cwd, dir.path, owners))
		.filter((finding): finding is ExportedFinding => !!finding)
		.filter((finding) => includeFinding(finding, options, sinceMs))
		.sort((a, b) => {
			const sev = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
			if (sev !== 0) return sev;
			return a.id.localeCompare(b.id, undefined, { numeric: true });
		});

	if (format === "json") {
		mkdirSync(dirname(outPath), { recursive: true });
		writeFileSync(
			outPath,
			`${JSON.stringify({ generated_at: new Date().toISOString(), findings }, null, 2)}\n`,
		);
	} else {
		mkdirSync(outPath, { recursive: true });
		for (const finding of findings) {
			writeFileSync(
				join(outPath, `${safeName(`${finding.id}-${finding.slug}`)}.md`),
				renderMarkdownExport(finding),
			);
		}
	}

	return {
		findings,
		outPath,
		format,
		lines: [
			`Directory: ${cwd}`,
			`Format:    ${format}`,
			`Findings:  ${findings.length}`,
			`Output:    ${outPath}`,
			"",
			...findings.slice(0, 30).map((finding) => {
				const ownerText = finding.owners.length > 0 ? ` owners=${finding.owners.join(",")}` : "";
				return `- ${finding.id} ${finding.severity} ${finding.title}${ownerText}`;
			}),
			...(findings.length > 30 ? [`... ${findings.length - 30} more`] : []),
		],
	};
}

export function normalizeExportSeverity(
	value: string | undefined,
): FindingDraft["severity"] | undefined {
	if (!value) return undefined;
	const lower = value.toLowerCase().trim();
	if (
		lower === "critical" ||
		lower === "high" ||
		lower === "medium" ||
		lower === "low" ||
		lower === "info"
	) {
		return lower;
	}
	return undefined;
}

function readExportedFinding(
	cwd: string,
	findingDir: string,
	codeowners: CodeownerRule[],
): ExportedFinding | undefined {
	const frontmatter = readFindingFrontmatter(findingDir);
	if (!frontmatter) return undefined;
	const draftPath = join(findingDir, "draft.md");
	const reportPath = join(findingDir, "report.md");
	const draftRaw = existsSync(draftPath) ? readFileSync(draftPath, "utf8") : "";
	const reportRaw = existsSync(reportPath) ? readFileSync(reportPath, "utf8") : "";
	const combined = `${draftRaw}\n${reportRaw}`;
	const title = readTitle(frontmatter, combined) ?? frontmatter.slug;
	const files = collectFindingFiles(cwd, frontmatter, combined);
	const owners = resolveOwners(files, codeowners);
	const status = readOptionalString(frontmatter.status) ?? readOptionalString(frontmatter.verdict);
	const confirmStatus = readConfirmStatus(combined);
	const updatedAt = new Date(maxMtime([draftPath, reportPath, findingDir])).toISOString();
	const labels = [
		`severity:${frontmatter.severity}`,
		...owners.map((owner) => `owner:${owner.replace(/^@/, "")}`),
		...(confirmStatus ? [`confirm:${confirmStatus}`] : []),
	];
	return {
		id: frontmatter.id,
		slug: frontmatter.slug,
		title,
		severity: frontmatter.severity,
		...(status ? { status } : {}),
		...(confirmStatus ? { confirmStatus } : {}),
		owners,
		labels,
		files,
		findingDir,
		...(existsSync(draftPath) ? { draftPath } : {}),
		...(existsSync(reportPath) ? { reportPath } : {}),
		updatedAt,
		frontmatter,
	};
}

function includeFinding(
	finding: ExportedFinding,
	options: ExportOptions,
	sinceMs: number | undefined,
): boolean {
	if (
		options.onlySeverity &&
		options.onlySeverity.length > 0 &&
		!options.onlySeverity.includes(finding.severity)
	) {
		return false;
	}
	if (
		options.minSeverity &&
		SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[options.minSeverity]
	) {
		return false;
	}
	if (options.confirmedOnly && !isConfirmed(finding.confirmStatus)) return false;
	if (options.excludeFp && isFalsePositiveLike(finding)) return false;
	if (options.requireOwner && finding.owners.length === 0) return false;
	if (sinceMs !== undefined && !Number.isNaN(sinceMs) && Date.parse(finding.updatedAt) < sinceMs) {
		return false;
	}
	return true;
}

function isConfirmed(confirmStatus: string | undefined): boolean {
	return (
		confirmStatus === "confirmed-live" ||
		confirmStatus === "confirmed-test" ||
		confirmStatus === "confirmed"
	);
}

function isFalsePositiveLike(finding: ExportedFinding): boolean {
	const id = finding.id.toLowerCase();
	const status = `${finding.status ?? ""} ${finding.confirmStatus ?? ""}`.toLowerCase();
	return (
		id.startsWith("fp-") ||
		status.includes("false-positive") ||
		status.includes("rejected") ||
		status === "fp" ||
		status.includes("invalid")
	);
}

function readTitle(frontmatter: Record<string, unknown>, content: string): string | undefined {
	const fmTitle =
		readOptionalString(frontmatter.title) ??
		readOptionalString(frontmatter.name) ??
		readOptionalString(frontmatter.summary);
	if (fmTitle) return fmTitle;
	const heading = content.match(/^#\s+(.+)$/m)?.[1]?.trim();
	if (heading) return heading;
	return undefined;
}

function readConfirmStatus(content: string): string | undefined {
	return content
		.match(/^Confirm-Status:\s*([^\n\r]+)/im)?.[1]
		?.trim()
		.toLowerCase();
}

function collectFindingFiles(
	cwd: string,
	frontmatter: Record<string, unknown>,
	content: string,
): string[] {
	const files = new Set<string>();
	for (const key of ["file", "path", "location", "source", "sink"]) {
		addFileValue(cwd, files, frontmatter[key]);
	}
	for (const value of Object.values(frontmatter)) {
		if (Array.isArray(value)) {
			for (const item of value) addFileValue(cwd, files, item);
		}
	}
	for (const match of content.matchAll(
		/(?:`|\b)([A-Za-z0-9_./-]+\.(?:ts|tsx|js|jsx|py|go|rs|rb|java|kt|swift|c|h|cpp|cc|hpp|cs|php|scala|clj|sh|sql|lua|tf|ya?ml))(?:[:#]\d+)?`?/g,
	)) {
		addFileValue(cwd, files, match[1]);
	}
	return [...files].sort();
}

function addFileValue(cwd: string, files: Set<string>, value: unknown): void {
	if (typeof value !== "string") return;
	const cleaned = value
		.replace(/^file:\/\//, "")
		.replace(/[:#]\d+(?::\d+)?$/, "")
		.trim();
	if (!cleaned || /^https?:\/\//.test(cleaned)) return;
	const abs = isAbsolute(cleaned) ? cleaned : resolve(cwd, cleaned);
	if (!abs.startsWith(resolve(cwd))) return;
	if (!existsSync(abs)) return;
	const rel = relative(cwd, abs).split("\\").join("/");
	if (!rel.startsWith("piolium/")) files.add(rel);
}

function loadCodeowners(cwd: string): CodeownerRule[] {
	const rules: CodeownerRule[] = [];
	for (const path of CODEOWNER_PATHS.map((p) => join(cwd, p))) {
		if (!existsSync(path)) continue;
		for (const rawLine of readFileSync(path, "utf8").split(/\r?\n/)) {
			const line = rawLine.replace(/\s+#.*$/, "").trim();
			if (!line || line.startsWith("#")) continue;
			const parts = line.split(/\s+/);
			const pattern = parts.shift();
			if (!pattern || parts.length === 0) continue;
			rules.push({ pattern, owners: parts });
		}
	}
	return rules;
}

function resolveOwners(files: string[], rules: CodeownerRule[]): string[] {
	const owners = new Set<string>();
	for (const file of files) {
		let matched: string[] | undefined;
		for (const rule of rules) {
			if (codeownerMatches(rule.pattern, file)) matched = rule.owners;
		}
		for (const owner of matched ?? []) owners.add(owner);
	}
	return [...owners].sort();
}

export function codeownerMatches(pattern: string, filePath: string): boolean {
	let pat = pattern.trim();
	if (!pat || pat.startsWith("#")) return false;
	pat = pat.replace(/^!/, "");
	const file = filePath.split("\\").join("/");
	if (pat.endsWith("/")) {
		const prefix = pat.replace(/^\/+/, "");
		return file.startsWith(prefix);
	}
	const anchored = pat.startsWith("/");
	pat = pat.replace(/^\/+/, "");
	if (!anchored && !pat.includes("/")) {
		return file.split("/").some((part) => minimatchSegment(pat, part));
	}
	if (anchored) return wildcardRegex(pat).test(file);
	return wildcardRegex(pat).test(file) || wildcardRegex(`**/${pat}`).test(file);
}

function minimatchSegment(pattern: string, segment: string): boolean {
	return wildcardRegex(pattern).test(segment);
}

function wildcardRegex(pattern: string): RegExp {
	const escaped = pattern
		.split("**")
		.map((part) => part.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*"))
		.join(".*");
	return new RegExp(`^${escaped}$`);
}

function renderMarkdownExport(finding: ExportedFinding): string {
	const lines: string[] = [];
	lines.push("---");
	lines.push(`id: ${finding.id}`);
	lines.push(`slug: ${finding.slug}`);
	lines.push(`severity: ${finding.severity}`);
	if (finding.status) lines.push(`status: ${finding.status}`);
	if (finding.confirmStatus) lines.push(`confirm_status: ${finding.confirmStatus}`);
	if (finding.owners.length > 0) lines.push(`owners: [${finding.owners.join(", ")}]`);
	lines.push("---");
	lines.push("");
	lines.push(`# ${finding.title}`);
	lines.push("");
	lines.push(`- Directory: \`${finding.findingDir}\``);
	if (finding.files.length > 0)
		lines.push(`- Files: ${finding.files.map((file) => `\`${file}\``).join(", ")}`);
	if (finding.labels.length > 0) lines.push(`- Labels: ${finding.labels.join(", ")}`);
	lines.push("");
	if (finding.reportPath && existsSync(finding.reportPath)) {
		lines.push(readFileSync(finding.reportPath, "utf8").trimEnd());
	} else if (finding.draftPath && existsSync(finding.draftPath)) {
		const { body } = splitFrontmatter(readFileSync(finding.draftPath, "utf8"));
		lines.push(body.trimEnd());
	}
	lines.push("");
	return lines.join("\n");
}

function resolveOutputPath(cwd: string, outPath: string): string {
	return isAbsolute(outPath) ? outPath : resolve(cwd, outPath);
}

function maxMtime(paths: string[]): number {
	let max = 0;
	for (const path of paths) {
		try {
			max = Math.max(max, statSync(path).mtimeMs);
		} catch {}
	}
	return max || Date.now();
}

function readOptionalString(value: unknown): string | undefined {
	return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

function safeName(value: string): string {
	const ext = extname(value);
	const base = ext ? basename(value, ext) : value;
	return base.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "finding";
}
