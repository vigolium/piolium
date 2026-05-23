/**
 * On-disk model for `piolium/audit-state.json`.
 *
 * Snake-case keys are an intentional, persisted on-disk contract — they are
 * what prior runs (and any interoperating tooling) read back when resuming or
 * reporting an audit. Don't camelCase them.
 *
 * Writes go through `withFileMutationQueue` (process-local serialization) +
 * temp-file-rename (atomic on POSIX). The combination prevents both
 * intra-process write-write races and partially-written files on crash.
 */

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { withFileMutationQueue } from "@earendil-works/pi-coding-agent";
import { phasesFor } from "./modes.ts";
import { formatPhaseDetailLabel } from "./phase-labels.ts";

export type AuditMode =
	| "lite"
	| "balanced"
	| "deep"
	| "diff"
	| "confirm"
	| "revisit"
	| "merge"
	| "longshot"
	| "reinvest";
export type RunStatus = "pending" | "in_progress" | "complete" | "failed";
export type PhaseStatus = "pending" | "in_progress" | "complete" | "failed" | "skipped";

export interface PhaseState {
	status: PhaseStatus;
	started_at?: string;
	completed_at?: string;
	error?: string;
	artifacts?: string[];
	attempt?: number;
	max_attempts?: number;
	retry_backoff_ms?: number;
	next_retry_at?: string;
	last_error?: string;
	heartbeat_at?: string;
	last_event_at?: string;
	last_tool?: string;
	last_tool_summary?: string;
	run_id?: string;
}

export interface AuditRunState {
	audit_id: string;
	commit?: string | null;
	branch?: string;
	repository?: string;
	history_available?: boolean;
	mode: AuditMode;
	model?: string;
	agent_sdk?: string;
	started_at: string;
	completed_at?: string | null;
	status: RunStatus;
	phases: Record<string, PhaseState>;
}

export interface AuditStateFile {
	audits: AuditRunState[];
	merge_metadata?: Record<string, unknown>;
	confirmation?: Record<string, unknown>;
}

export interface ReadAuditStateResult {
	path: string;
	exists: boolean;
	state?: AuditStateFile;
	parseError?: string;
}

export function getAuditStatePath(cwd: string): string {
	return join(cwd, "piolium", "audit-state.json");
}

export function readAuditState(cwd: string): ReadAuditStateResult {
	const path = getAuditStatePath(cwd);
	if (!existsSync(path)) {
		return { path, exists: false };
	}
	try {
		const raw = readFileSync(path, "utf8");
		const parsed = JSON.parse(raw) as unknown;
		if (!isAuditStateFile(parsed)) {
			return {
				path,
				exists: true,
				parseError:
					"File is valid JSON but does not match expected audit-state shape (missing `audits` array).",
			};
		}
		return { path, exists: true, state: parsed };
	} catch (err) {
		return {
			path,
			exists: true,
			parseError: err instanceof Error ? err.message : String(err),
		};
	}
}

function isAuditStateFile(value: unknown): value is AuditStateFile {
	if (typeof value !== "object" || value === null) return false;
	const v = value as Record<string, unknown>;
	return Array.isArray(v.audits);
}

/**
 * Atomically replace the state file. Callers should always go through
 * `mutateAuditState` rather than calling this directly so concurrent
 * mutations within the same process serialize correctly.
 */
function writeAuditStateRaw(path: string, state: AuditStateFile): void {
	mkdirSync(dirname(path), { recursive: true });
	const tmp = `${path}.tmp-${process.pid}-${Date.now()}`;
	const json = `${JSON.stringify(state, null, "\t")}\n`;
	writeFileSync(tmp, json);
	renameSync(tmp, path);
}

/**
 * Read-modify-write the audit-state file under the file mutation queue.
 * The transformer receives the current state (or a fresh empty file if none
 * exists) and returns the new state. Returning `undefined` aborts the write
 * (no-op transformer).
 */
export async function mutateAuditState(
	cwd: string,
	transform: (state: AuditStateFile) => AuditStateFile | undefined,
): Promise<AuditStateFile> {
	const path = getAuditStatePath(cwd);
	return withFileMutationQueue(path, async () => {
		const current = readAuditStateOrEmpty(path);
		const next = transform(current);
		if (!next) return current;
		writeAuditStateRaw(path, next);
		return next;
	});
}

function readAuditStateOrEmpty(path: string): AuditStateFile {
	if (!existsSync(path)) return { audits: [] };
	const raw = readFileSync(path, "utf8");
	if (raw.trim() === "") return { audits: [] };
	try {
		const parsed = JSON.parse(raw) as unknown;
		if (isAuditStateFile(parsed)) return parsed;
	} catch {
		// fall through to the corrupt-file backup below.
	}
	// The file exists with non-empty content that won't parse or doesn't match
	// the expected shape. Audit state is expensive and resumable, so never let
	// the caller overwrite it blind: move the corrupt file aside first, then
	// return empty so a fresh file is written alongside the preserved backup.
	backupCorruptStateFile(path);
	return { audits: [] };
}

/**
 * Move a corrupt state file to `audit-state.json.corrupt-<timestamp>` so a
 * subsequent write doesn't destroy whatever audit history it held. Best-effort:
 * if the rename fails we leave the file in place rather than risk losing it.
 */
function backupCorruptStateFile(path: string): void {
	const stamp = new Date().toISOString().replace(/[:.]/g, "-");
	let backup = `${path}.corrupt-${stamp}`;
	for (let n = 1; existsSync(backup); n++) backup = `${path}.corrupt-${stamp}-${n}`;
	try {
		renameSync(path, backup);
	} catch {
		// Leave the original untouched if it can't be moved.
	}
}

/** Most recent audit by `started_at` (ISO timestamps sort lexically). */
export function latestAudit(state: AuditStateFile): AuditRunState | undefined {
	if (state.audits.length === 0) return undefined;
	return [...state.audits].sort((a, b) => (a.started_at < b.started_at ? 1 : -1))[0];
}

/**
 * Most recent resumable audit across all modes. Preference order: an
 * `in_progress` run (process killed mid-phase) outranks a `failed` run
 * (orderly terminal state) because the former is more likely a transient
 * outage. `complete` audits are never returned.
 *
 * Ties are broken by `started_at` (most recent first).
 */
export function latestResumableAudit(state: AuditStateFile): AuditRunState | undefined {
	const sorted = [...state.audits].sort((a, b) => (a.started_at < b.started_at ? 1 : -1));
	return (
		sorted.find((a) => a.status === "in_progress") ??
		sorted.find((a) => a.status === "failed") ??
		undefined
	);
}

export interface InitAuditOptions {
	mode: AuditMode;
	model?: string;
	agent_sdk?: string;
	commit?: string | null;
	branch?: string;
	repository?: string;
	history_available?: boolean;
	/** Override the phase list (otherwise derived from mode). */
	phases?: readonly string[];
}

/**
 * Append a new audit run to the state file. Returns the appended run with a
 * fresh ISO timestamp `audit_id`.
 */
export async function initAudit(cwd: string, options: InitAuditOptions): Promise<AuditRunState> {
	const startedAt = new Date().toISOString();
	const phases: Record<string, PhaseState> = {};
	const phaseList = options.phases ?? phasesFor(options.mode);
	for (const name of phaseList) phases[name] = { status: "pending" };

	const run: AuditRunState = {
		audit_id: startedAt,
		mode: options.mode,
		started_at: startedAt,
		completed_at: null,
		status: "in_progress",
		phases,
		...(options.model !== undefined && { model: options.model }),
		...(options.agent_sdk !== undefined && { agent_sdk: options.agent_sdk }),
		...(options.commit !== undefined && { commit: options.commit }),
		...(options.branch !== undefined && { branch: options.branch }),
		...(options.repository !== undefined && { repository: options.repository }),
		...(options.history_available !== undefined && { history_available: options.history_available }),
	};

	await mutateAuditState(cwd, (state) => ({ ...state, audits: [...state.audits, run] }));
	return run;
}

export interface PhaseUpdate {
	status: PhaseStatus;
	error?: string;
	artifacts?: string[];
	attempt?: number;
	max_attempts?: number;
	retry_backoff_ms?: number | null;
	next_retry_at?: string | null;
	last_error?: string | null;
	heartbeat_at?: string | null;
	last_event_at?: string | null;
	last_tool?: string | null;
	last_tool_summary?: string | null;
	run_id?: string | null;
}

/**
 * Update a single phase on the named audit. Auto-stamps `started_at` on
 * transitions into `in_progress` and `completed_at` on terminal states.
 * Returns the updated audit, or `undefined` if the audit_id wasn't found.
 */
export async function setPhaseStatus(
	cwd: string,
	auditId: string,
	phase: string,
	update: PhaseUpdate,
): Promise<AuditRunState | undefined> {
	let updated: AuditRunState | undefined;
	await mutateAuditState(cwd, (state) => {
		const idx = state.audits.findIndex((a) => a.audit_id === auditId);
		if (idx < 0) return undefined;
		const audit = state.audits[idx];
		if (!audit) return undefined;
		const prev = audit.phases[phase] ?? { status: "pending" as const };
		const now = new Date().toISOString();
		const next: PhaseState = {
			...prev,
			status: update.status,
			...(update.error !== undefined && { error: update.error }),
			...(update.artifacts !== undefined && { artifacts: update.artifacts }),
			...(update.attempt !== undefined && { attempt: update.attempt }),
			...(update.max_attempts !== undefined && { max_attempts: update.max_attempts }),
		};
		if (update.retry_backoff_ms !== undefined) {
			if (update.retry_backoff_ms === null) next.retry_backoff_ms = undefined;
			else next.retry_backoff_ms = update.retry_backoff_ms;
		}
		if (update.next_retry_at !== undefined) {
			if (update.next_retry_at === null) next.next_retry_at = undefined;
			else next.next_retry_at = update.next_retry_at;
		}
		if (update.last_error !== undefined) {
			if (update.last_error === null) next.last_error = undefined;
			else next.last_error = update.last_error;
		}
		if (update.heartbeat_at !== undefined) {
			if (update.heartbeat_at === null) next.heartbeat_at = undefined;
			else next.heartbeat_at = update.heartbeat_at;
		}
		if (update.last_event_at !== undefined) {
			if (update.last_event_at === null) next.last_event_at = undefined;
			else next.last_event_at = update.last_event_at;
		}
		if (update.last_tool !== undefined) {
			if (update.last_tool === null) next.last_tool = undefined;
			else next.last_tool = update.last_tool;
		}
		if (update.last_tool_summary !== undefined) {
			if (update.last_tool_summary === null) next.last_tool_summary = undefined;
			else next.last_tool_summary = update.last_tool_summary;
		}
		if (update.run_id !== undefined) {
			if (update.run_id === null) next.run_id = undefined;
			else next.run_id = update.run_id;
		}
		if (update.status === "in_progress" && !next.started_at) next.started_at = now;
		if (update.status === "in_progress") next.completed_at = undefined;
		if (update.status === "complete") {
			next.error = undefined;
			next.artifacts = undefined;
			next.retry_backoff_ms = undefined;
			next.next_retry_at = undefined;
			next.last_error = undefined;
			next.heartbeat_at = undefined;
			next.last_event_at = undefined;
			next.last_tool = undefined;
			next.last_tool_summary = undefined;
			next.run_id = undefined;
		}
		if (update.status === "complete" || update.status === "failed" || update.status === "skipped") {
			if (!next.started_at) next.started_at = now;
			next.completed_at = now;
		}
		const phases = { ...audit.phases, [phase]: next };
		const newAudit: AuditRunState = { ...audit, phases };
		updated = newAudit;
		const audits = [...state.audits];
		audits[idx] = newAudit;
		return { ...state, audits };
	});
	return updated;
}

/**
 * Wrapper around `setPhaseStatus` that also mirrors the disk write onto the
 * caller's in-memory `AuditRunState`. Use this from orchestrators that hold
 * an `audit` object across multiple phase transitions — otherwise their copy
 * goes stale the moment any phase completes, and downstream prerequisite
 * checks (e.g. `ensurePrereqs`) read "pending" for already-completed phases.
 */
export async function applyPhaseStatus(
	cwd: string,
	audit: AuditRunState,
	phase: string,
	update: PhaseUpdate,
): Promise<void> {
	const updated = await setPhaseStatus(cwd, audit.audit_id, phase, update);
	if (!updated) return;
	const fresh = updated.phases[phase];
	if (fresh) audit.phases[phase] = fresh;
}

/** Mark an audit run as complete or failed. */
export async function markAuditStatus(
	cwd: string,
	auditId: string,
	status: RunStatus,
): Promise<AuditRunState | undefined> {
	let updated: AuditRunState | undefined;
	await mutateAuditState(cwd, (state) => {
		const idx = state.audits.findIndex((a) => a.audit_id === auditId);
		if (idx < 0) return undefined;
		const audit = state.audits[idx];
		if (!audit) return undefined;
		const completedAt =
			status === "complete" || status === "failed" ? new Date().toISOString() : audit.completed_at;
		const newAudit: AuditRunState = {
			...audit,
			status,
			completed_at: completedAt ?? null,
		};
		updated = newAudit;
		const audits = [...state.audits];
		audits[idx] = newAudit;
		return { ...state, audits };
	});
	return updated;
}

export interface PhaseTally {
	total: number;
	complete: number;
	in_progress: number;
	pending: number;
	failed: number;
	skipped: number;
}

export function tallyPhases(audit: AuditRunState): PhaseTally {
	const tally: PhaseTally = {
		total: 0,
		complete: 0,
		in_progress: 0,
		pending: 0,
		failed: 0,
		skipped: 0,
	};
	for (const phase of Object.values(audit.phases)) {
		tally.total++;
		tally[phase.status]++;
	}
	return tally;
}

function compactDetail(text: string, max = 220): string {
	const collapsed = text.replace(/\s+/g, " ").trim();
	if (collapsed.length <= max) return collapsed;
	return `${collapsed.slice(0, max - 1)}…`;
}

function equivalentDetail(left: string | undefined, right: string | undefined): boolean {
	if (!left || !right) return false;
	return left.replace(/\s+/g, " ").trim() === right.replace(/\s+/g, " ").trim();
}

export function formatPhaseDetailLines(
	phaseEntries: Array<[string, PhaseState]>,
	options: {
		markers?: boolean;
		labelFor?: (name: string, index: number, total: number) => string;
	} = {},
): string[] {
	const lines: string[] = [];
	const displayNames = phaseEntries.map(([name], index) =>
		options.labelFor ? options.labelFor(name, index, phaseEntries.length) : name,
	);
	const displayWidth = Math.max(8, ...displayNames.map((name) => name.length));
	for (const [index, [name, phase]] of phaseEntries.entries()) {
		const displayName = displayNames[index] ?? name;
		const marker = options.markers ? `${phaseMarker(phase.status)} ` : "";
		const primaryError = phase.error ?? phase.last_error;
		let line = `  ${marker}${displayName.padEnd(displayWidth)} ${phase.status}`;
		if (primaryError) line += ` — ${compactDetail(primaryError)}`;
		lines.push(line);

		if (phase.status === "failed") {
			if (phase.attempt !== undefined && phase.max_attempts !== undefined) {
				lines.push(`    attempts: ${phase.attempt}/${phase.max_attempts}`);
			}
			if (phase.last_error && !equivalentDetail(phase.last_error, primaryError)) {
				lines.push(`    last error: ${compactDetail(phase.last_error)}`);
			}
			if (phase.artifacts?.length) {
				lines.push(`    artifacts: ${phase.artifacts.map((a) => compactDetail(a, 120)).join(", ")}`);
			}
		} else if (phase.status === "in_progress" && phase.next_retry_at) {
			lines.push(`    next retry: ${phase.next_retry_at}`);
			if (phase.last_error) lines.push(`    last error: ${compactDetail(phase.last_error)}`);
		} else if (phase.status === "in_progress" && phase.heartbeat_at) {
			lines.push(`    heartbeat: ${phase.heartbeat_at}`);
			if (phase.last_event_at) lines.push(`    last event: ${phase.last_event_at}`);
			if (phase.last_tool) {
				lines.push(
					`    last tool: ${compactDetail(
						`${phase.last_tool}${phase.last_tool_summary ? ` ${phase.last_tool_summary}` : ""}`,
						160,
					)}`,
				);
			}
		}
	}
	return lines;
}

/**
 * Format a run + phases as displayable lines for `/piolium-status`.
 * Pure function — no UI deps so it's easy to unit-test later.
 */
export function formatAuditStatus(state: AuditStateFile): string[] {
	const lines: string[] = [];
	if (state.audits.length === 0) {
		lines.push("No audits recorded yet in piolium/audit-state.json.");
		return lines;
	}

	const audit = latestAudit(state);
	if (!audit) {
		lines.push("No audits recorded yet in piolium/audit-state.json.");
		return lines;
	}

	const tally = tallyPhases(audit);
	lines.push(`Audit:     ${audit.audit_id}`);
	lines.push(`Mode:      ${audit.mode}`);
	lines.push(`Status:    ${audit.status}`);
	lines.push(`Started:   ${audit.started_at}`);
	if (audit.completed_at) lines.push(`Completed: ${audit.completed_at}`);
	if (audit.commit) lines.push(`Commit:    ${audit.commit}`);
	if (audit.branch) lines.push(`Branch:    ${audit.branch}`);
	if (audit.repository) lines.push(`Repo:      ${audit.repository}`);
	if (audit.model) lines.push(`Model:     ${audit.model}`);
	if (audit.agent_sdk) lines.push(`SDK:       ${audit.agent_sdk}`);
	lines.push("");
	lines.push(
		`Phases:    ${tally.complete}/${tally.total} complete · ${tally.in_progress} running · ${tally.pending} pending · ${tally.failed} failed · ${tally.skipped} skipped`,
	);

	const phaseEntries = Object.entries(audit.phases);
	if (phaseEntries.length > 0) {
		lines.push("");
		lines.push("Phase detail:");
		lines.push(
			...formatPhaseDetailLines(phaseEntries, {
				markers: true,
				labelFor: formatPhaseDetailLabel,
			}),
		);
	}

	if (state.audits.length > 1) {
		lines.push("");
		lines.push(`(${state.audits.length} audits in history; showing latest only.)`);
	}
	return lines;
}

function phaseMarker(status: PhaseStatus): string {
	switch (status) {
		case "complete":
			return "✓";
		case "in_progress":
			return "…";
		case "failed":
			return "✗";
		case "skipped":
			return "↷";
		default:
			return "·";
	}
}
