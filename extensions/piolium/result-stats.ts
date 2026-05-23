import { basename } from "node:path";
import { latestAudit, readAuditState } from "./audit-state.ts";
import { listDraftFindings, listFindingDirs, readFindingFrontmatter } from "./findings.ts";

type Severity = "critical" | "high" | "medium" | "low" | "info";

interface FindingCounts {
	total: number;
	critical: number;
	high: number;
	medium: number;
	low: number;
	info: number;
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

function emptyCounts(): FindingCounts {
	return {
		total: 0,
		critical: 0,
		high: 0,
		medium: 0,
		low: 0,
		info: 0,
	};
}

function increment(counts: FindingCounts, severity: Severity): void {
	counts.total += 1;
	counts[severity] += 1;
}

function severityFromId(value: string): Severity {
	const normalized = value.replace(/^FP-/i, "").trim();
	if (/^C\d+/i.test(normalized)) return "critical";
	if (/^H\d+/i.test(normalized)) return "high";
	if (/^M\d+/i.test(normalized)) return "medium";
	if (/^L\d+/i.test(normalized)) return "low";
	if (/^I\d+/i.test(normalized)) return "info";
	return "info";
}

function countFindings(cwd: string): FindingCounts {
	const counts = emptyCounts();
	const dirs = listFindingDirs(cwd);
	if (dirs.length > 0) {
		for (const dir of dirs) {
			const dirName = basename(dir.path);
			if (dirName.startsWith("FP-")) continue;
			increment(counts, readFindingFrontmatter(dir.path)?.severity ?? severityFromId(dir.id));
		}
		return counts;
	}

	for (const draft of listDraftFindings(cwd)) {
		increment(counts, draft.severity);
	}
	return counts;
}

function parseTime(value: string | null | undefined): number | undefined {
	if (!value) return undefined;
	const ms = Date.parse(value);
	return Number.isFinite(ms) ? ms : undefined;
}

function formatDuration(ms: number): string {
	const totalSeconds = Math.max(0, Math.floor(ms / 1000));
	const hours = Math.floor(totalSeconds / 3600);
	const minutes = Math.floor((totalSeconds % 3600) / 60);
	const seconds = totalSeconds % 60;
	if (hours > 0)
		return `${hours}h ${String(minutes).padStart(2, "0")}m ${String(seconds).padStart(2, "0")}s`;
	if (minutes > 0) return `${minutes}m ${String(seconds).padStart(2, "0")}s`;
	return `${seconds}s`;
}

function severitySummary(counts: FindingCounts): string {
	return SEVERITIES.map((severity) => `${severity} ${counts[severity]}`).join(" | ");
}

export function buildAuditResultStatsLines(
	cwd: string,
	auditId?: string,
	options: { nowMs?: number } = {},
): string[] {
	const state = readAuditState(cwd).state;
	const audit = auditId
		? state?.audits.find((candidate) => candidate.audit_id === auditId)
		: state
			? latestAudit(state)
			: undefined;
	const startedAt = parseTime(audit?.started_at);
	const completedAt = parseTime(audit?.completed_at) ?? options.nowMs ?? Date.now();
	const duration = startedAt === undefined ? "unknown" : formatDuration(completedAt - startedAt);
	const counts = countFindings(cwd);

	return [
		"Stats:",
		`  Audit duration: ${duration}`,
		`  Total findings: ${counts.total}`,
		`  Severity: ${severitySummary(counts)}`,
	];
}
