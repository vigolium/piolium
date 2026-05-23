/**
 * piolium extension entry point.
 *
 * Registers the `/piolium-*` slash commands. M0/M1/M2 ship:
 *   - /piolium-status — read-only state inspector
 *   - /piolium-smoke  — runs a tiny inline agent end-to-end via the runner
 *                      so operators can verify their Pi setup before kicking
 *                      off a real audit
 *   - /piolium-lite   — stub; real impl in M3
 *
 * Pi loads this file via jiti at runtime (see `pi.extensions` in
 * package.json). The default export runs once per session.
 */

import { randomUUID } from "node:crypto";
import type {
	AgentSessionEvent,
	ExtensionAPI,
	ExtensionCommandContext,
	ExtensionUIContext,
} from "@earendil-works/pi-coding-agent";
import { Container, Text } from "@earendil-works/pi-tui";
import { AgentRunError, type AgentRuntimeModel, runAgent } from "./agent-runner.ts";
import type { AgentDefinition } from "./agents.ts";
import {
	type AuditMode,
	type PhaseState,
	formatAuditStatus,
	formatPhaseDetailLines,
	getAuditStatePath,
	latestAudit,
	latestResumableAudit,
	readAuditState,
	tallyPhases,
} from "./audit-state.ts";
import {
	parsePioliumCommandArgs,
	readOptionValue,
	readRepeatedOptionValues,
} from "./command-target.ts";
import { type PioliumConsoleStream, createPioliumConsoleStream } from "./console-stream.ts";
import { type ExportFormat, normalizeExportSeverity, runExport } from "./export-results.ts";
import {
	PHASE_HEARTBEAT_UI_COLOR,
	type PhaseHeartbeat,
	formatPhaseHeartbeat,
	formatPhaseHeartbeatStatusLine,
} from "./heartbeat.ts";
import { PIOLIUM_STARTUP_HINT, buildPioliumHelpLines } from "./help.ts";
import { runMatcherLearn } from "./matcher-suggestions.ts";
import { phasesFor } from "./modes.ts";
import { runBalancedAudit } from "./modes/balanced.ts";
import { bootstrapResultsOnlyConfirm } from "./modes/confirm-bootstrap.ts";
import { runConfirmAudit } from "./modes/confirm.ts";
import { runDeepAudit } from "./modes/deep.ts";
import { runDiffAudit } from "./modes/diff.ts";
import { runLiteAudit } from "./modes/lite.ts";
import { runLongshotAudit } from "./modes/longshot.ts";
import { runMergeAudit } from "./modes/merge.ts";
import { runReinvestAudit } from "./modes/reinvest.ts";
import { runRevisitAudit } from "./modes/revisit.ts";
import { formatPhaseDetailLabel } from "./phase-labels.ts";
import { extractStatusPhase, renderPhaseStatusList } from "./phase-status-strip.ts";
import { PioliumPromptPrefixEditor, shouldUsePioliumPromptPrefix } from "./prompt-prefix-editor.ts";
import { registerAnthropicVertex } from "./providers/anthropic-vertex.ts";
import { buildAuditResultStatsLines } from "./result-stats.ts";
import { readNonNegativeIntEnv, readPositiveIntEnv, runWithRetry } from "./retry.ts";

const PIOLIUM_STREAM = "piolium-stream";
const FLAG_DIR = "plm-dir";
const FLAG_SINCE = "plm-since";
const FLAG_COMMIT_MAX = "plm-scan-limit";
const FLAG_COMMIT_SINCE = "plm-scan-since";
const COMMAND_RESULT_DIALOG_HINT = "Esc returns to chat";
const COMMAND_RESULT_DISMISS_HINT = "Press Esc to return to chat.";
const AUDIT_STATE_PROGRESS_POLL_MS = readPositiveIntEnv("PIOLIUM_AUDIT_STATE_POLL_MS", 5000);
const AUDIT_STATE_PROGRESS_REPEAT_MS = readPositiveIntEnv("PIOLIUM_AUDIT_STATE_REPEAT_MS", 30_000);
const INITIAL_UI_PAINT_DELAY_MS = 160;
const PREPARING_SPINNER_INTERVAL_MS = readPositiveIntEnv(
	"PIOLIUM_PREPARING_SPINNER_INTERVAL_MS",
	80,
);
const PREPARING_SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

export const FLAG_ENV_MAPPINGS = [
	{
		flag: FLAG_COMMIT_MAX,
		env: "PIOLIUM_COMMIT_SCAN_LIMIT",
		description: "Commit archaeology max commits",
	},
	{
		flag: FLAG_COMMIT_SINCE,
		env: "PIOLIUM_COMMIT_SCAN_SINCE",
		description: "Commit archaeology git --since window",
	},
	{
		flag: "plm-file-records",
		env: "PIOLIUM_FILE_RECORDS",
		description: "Set 1/true to write piolium/file-records per-file scan records (default off)",
	},
	{
		flag: "plm-phase-retries",
		env: "PIOLIUM_PHASE_MAX_RETRIES",
		description: "Agent phase retries after the first attempt (default: 5)",
	},
	{
		flag: "plm-phase-backoff",
		env: "PIOLIUM_PHASE_BACKOFF_BASE_MS",
		description: "Agent phase retry base backoff in ms (default: 5000)",
	},
	{
		flag: "plm-phase-backoff-max",
		env: "PIOLIUM_PHASE_BACKOFF_MAX_MS",
		description: "Agent phase retry max backoff in ms (default: 120000)",
	},
	{
		flag: "plm-lite-retries",
		env: "PIOLIUM_LITE_PHASE_MAX_RETRIES",
		description: "Lite deterministic phase retries after the first attempt (default: phase retries)",
	},
	{
		flag: "plm-lite-backoff",
		env: "PIOLIUM_LITE_PHASE_BACKOFF_BASE_MS",
		description: "Lite deterministic phase retry base backoff in ms (default: phase backoff)",
	},
	{
		flag: "plm-lite-backoff-max",
		env: "PIOLIUM_LITE_PHASE_BACKOFF_MAX_MS",
		description: "Lite deterministic phase retry max backoff in ms (default: phase max backoff)",
	},
	{
		flag: "plm-command-retries",
		env: "PIOLIUM_COMMAND_MAX_RETRIES",
		description: "Top-level /piolium-* command retries after the first attempt (default: 3)",
	},
	{
		flag: "plm-command-backoff",
		env: "PIOLIUM_COMMAND_BACKOFF_BASE_MS",
		description: "Top-level command retry base backoff in ms (default: 5000)",
	},
	{
		flag: "plm-command-backoff-max",
		env: "PIOLIUM_COMMAND_BACKOFF_MAX_MS",
		description: "Top-level command retry max backoff in ms (default: 120000)",
	},
	{
		flag: "plm-longshot-limit",
		env: "PIOLIUM_LONGSHOT_LIMIT",
		description: "Longshot max files to hunt (default: 1000)",
	},
	{
		flag: "plm-longshot-timeout",
		env: "PIOLIUM_LONGSHOT_TIMEOUT_MS",
		description: "Longshot per-file kill timer in ms (default: 21600000 / 6h)",
	},
	{
		flag: "plm-longshot-langs",
		env: "PIOLIUM_LONGSHOT_LANGS",
		description:
			"Longshot language allowlist (comma-list, e.g. python,go); default auto-detects dominant",
	},
	{
		flag: "plm-longshot-include-tests",
		env: "PIOLIUM_LONGSHOT_INCLUDE_TESTS",
		description: "Set 1/true to include test files in longshot enumeration (default off)",
	},
] as const;

function agentRuntimeFromCommandContext(
	pi: ExtensionAPI,
	ctx: ExtensionCommandContext,
): AgentRuntimeModel {
	const thinkingLevel = readParentThinkingLevel(pi);
	return {
		...(ctx.model ? { model: ctx.model } : {}),
		modelRegistry: ctx.modelRegistry,
		...(thinkingLevel ? { thinkingLevel } : {}),
	};
}

function readParentThinkingLevel(
	pi: ExtensionAPI,
): ReturnType<ExtensionAPI["getThinkingLevel"]> | undefined {
	try {
		return pi.getThinkingLevel();
	} catch {
		// Extension actions throw before runner.initialize(); guard so
		// non-interactive flows that call commands very early still work.
		return undefined;
	}
}

interface CommandUi {
	notify: (text: string, level: "info" | "warning" | "error") => void;
	setStatus: (key: string, text?: string) => void;
}

interface PhaseStripContext {
	cwd: string;
	ui: ExtensionUIContext;
}

interface PhaseStripCommandUi extends CommandUi {
	onPhaseHeartbeat: (phase: string, heartbeat?: PhaseHeartbeat) => void;
	clearStatus: () => void;
}

class CommandFailedStatus<T> extends Error {
	constructor(
		label: string,
		public readonly result: T,
	) {
		super(`${label} returned failed status`);
		this.name = "CommandFailedStatus";
	}
}

function hasFailedStatus(value: unknown): value is { status: "failed" } {
	return (
		!!value &&
		typeof value === "object" &&
		"status" in value &&
		(value as { status?: unknown }).status === "failed"
	);
}

type CommandPhaseStatus = "complete" | "failed" | "skipped";

interface AuditStateConsoleProgress {
	line: string;
	signature: string;
}

function formatCommandPhaseLines(
	cwd: string,
	auditId: string,
	phases: Record<string, CommandPhaseStatus>,
): string[] {
	const state = readAuditState(cwd).state;
	const audit = state?.audits.find((a) => a.audit_id === auditId);
	const entries: Array<[string, PhaseState]> = Object.entries(phases).map(([name, status]) => [
		name,
		audit?.phases[name] ?? { status },
	]);
	return formatPhaseDetailLines(entries, { labelFor: formatPhaseDetailLabel });
}

function formatConsolePhaseLabel(phase: string, phases: readonly string[]): string {
	const index = phases.indexOf(phase);
	if (index < 0) return phase;
	return formatPhaseDetailLabel(phase, index, phases.length);
}

function formatAuditStateConsoleActivity(
	phaseStates: Record<string, PhaseState>,
	activePhases: readonly string[],
): string | undefined {
	for (const phase of activePhases) {
		const state = phaseStates[phase];
		if (!state) continue;
		if (state.next_retry_at) return `${phase} retrying at ${state.next_retry_at}`;
		if (state.last_tool) {
			return `${phase} last tool ${compactLine(
				`${state.last_tool}${state.last_tool_summary ? ` ${state.last_tool_summary}` : ""}`,
				120,
			)}`;
		}
		if (state.last_event_at) return `${phase} last event ${state.last_event_at}`;
		if (state.heartbeat_at) return `${phase} heartbeat ${state.heartbeat_at}`;
		if (state.error) return `${phase} ${compactLine(state.error, 120)}`;
	}
	return undefined;
}

function formatAuditStateConsoleProgress(
	cwd: string,
	phases: readonly string[],
	currentPhase: string | undefined,
): AuditStateConsoleProgress {
	const relPath = "./piolium/audit-state.json";
	const result = readAuditState(cwd);
	if (!result.exists) {
		return {
			line: `audit-state: waiting for ${relPath}`,
			signature: "missing",
		};
	}
	if (result.parseError) {
		return {
			line: `audit-state: cannot parse ${relPath}: ${compactLine(result.parseError, 140)}`,
			signature: `parse:${result.parseError}`,
		};
	}
	const audit = result.state ? latestAudit(result.state) : undefined;
	if (!audit) {
		return {
			line: `audit-state: ${relPath} has no audits yet`,
			signature: "empty",
		};
	}

	const tally = tallyPhases(audit);
	const activePhases = phases.filter((phase) => audit.phases[phase]?.status === "in_progress");
	const fallbackCurrent =
		currentPhase && phases.includes(currentPhase) && audit.status === "in_progress"
			? [currentPhase]
			: [];
	const displayActivePhases = activePhases.length > 0 ? activePhases : fallbackCurrent;
	const activeText =
		displayActivePhases.length > 0
			? `running ${displayActivePhases.map((phase) => formatConsolePhaseLabel(phase, phases)).join(", ")}`
			: audit.status;
	const activity = formatAuditStateConsoleActivity(audit.phases, displayActivePhases);
	const counts = `${tally.complete}/${tally.total} complete, ${tally.pending} pending, ${tally.failed} failed, ${tally.skipped} skipped`;
	const line = `audit-state: ${audit.mode} ${audit.status}; ${activeText}; ${counts}${activity ? `; ${activity}` : ""}`;
	return {
		line,
		signature: line,
	};
}

function createPhaseStripCommandUi(
	ctx: PhaseStripContext,
	statusKey: string,
	phases: readonly string[],
	options: { initialPhase?: string; consoleStream?: PioliumConsoleStream } = {},
): PhaseStripCommandUi {
	let currentPhase = options.initialPhase;
	let hasPhaseActivity = false;
	let preparingMessage: string | undefined;
	const heartbeats = new Map<string, PhaseHeartbeat>();
	const lastConsoleHeartbeatAt = new Map<string, number>();
	const widgetKey = `${statusKey}-phase-list`;
	let lastConsoleStatusText: string | undefined;
	let lastAuditProgressSignature: string | undefined;
	let lastAuditProgressAt = 0;
	let auditProgressTimer: ReturnType<typeof setInterval> | undefined;
	let preparingSpinnerTimer: ReturnType<typeof setInterval> | undefined;
	let preparingSpinnerFrame = 0;

	const emitAuditStateProgress = (force = false): void => {
		if (!options.consoleStream?.enabled) return;
		const progress = formatAuditStateConsoleProgress(ctx.cwd, phases, currentPhase);
		const now = Date.now();
		if (
			force ||
			progress.signature !== lastAuditProgressSignature ||
			now - lastAuditProgressAt >= AUDIT_STATE_PROGRESS_REPEAT_MS
		) {
			options.consoleStream.writeLine(`[${statusKey}] ${progress.line}`);
			lastAuditProgressSignature = progress.signature;
			lastAuditProgressAt = now;
		}
	};

	if (options.consoleStream?.enabled) {
		options.consoleStream.writeLine(`[${statusKey}] target: ${ctx.cwd}`);
		options.consoleStream.writeLine(
			`[${statusKey}] watching ./piolium/audit-state.json (${getAuditStatePath(ctx.cwd)})`,
		);
		emitAuditStateProgress(true);
		auditProgressTimer = setInterval(emitAuditStateProgress, AUDIT_STATE_PROGRESS_POLL_MS);
		(auditProgressTimer as { unref?: () => void }).unref?.();
	}

	const emitConsoleStatus = (text?: string): void => {
		if (!text || !options.consoleStream?.enabled || text === lastConsoleStatusText) return;
		lastConsoleStatusText = text;
		options.consoleStream.writeLine(`[${statusKey}] ${compactLine(text, 160)}`);
	};

	const render = (text?: string): void => {
		const phaseFromText = extractStatusPhase(text, phases);
		if (phaseFromText) {
			currentPhase = phaseFromText;
			hasPhaseActivity = true;
			preparingMessage = undefined;
		} else if (text && !hasPhaseActivity) {
			preparingMessage = formatPreparingStatusMessage(text);
		} else if (hasPhaseActivity) {
			preparingMessage = undefined;
		}

		if (preparingMessage && !preparingSpinnerTimer) {
			preparingSpinnerTimer = setInterval(() => {
				preparingSpinnerFrame = (preparingSpinnerFrame + 1) % PREPARING_SPINNER_FRAMES.length;
				render();
			}, PREPARING_SPINNER_INTERVAL_MS);
			(preparingSpinnerTimer as { unref?: () => void }).unref?.();
		} else if (!preparingMessage && preparingSpinnerTimer) {
			clearInterval(preparingSpinnerTimer);
			preparingSpinnerTimer = undefined;
			preparingSpinnerFrame = 0;
		}

		const state = readAuditState(ctx.cwd).state;
		const audit = state ? latestAudit(state) : undefined;
		const phaseStates =
			hasPhaseActivity || audit?.status === "in_progress" ? (audit?.phases ?? {}) : {};
		const lines = renderPhaseStatusList(phases, phaseStates, currentPhase, ctx.ui.theme);
		const heartbeatLines = phases
			.map((phase) => heartbeats.get(phase))
			.filter((heartbeat): heartbeat is PhaseHeartbeat => !!heartbeat)
			.map((heartbeat) =>
				ctx.ui.theme.fg(PHASE_HEARTBEAT_UI_COLOR, `  ${formatPhaseHeartbeatStatusLine(heartbeat)}`),
			);
		ctx.ui.setStatus(statusKey, undefined);
		ctx.ui.setWidget(
			widgetKey,
			(_tui, theme) => {
				const container = new Container();
				if (preparingMessage) {
					const frame =
						PREPARING_SPINNER_FRAMES[preparingSpinnerFrame % PREPARING_SPINNER_FRAMES.length] ?? "●";
					container.addChild(
						new Text(`${theme.fg("accent", frame)} ${theme.fg("muted", preparingMessage)}`, 1, 0),
					);
				}
				for (const line of lines) {
					container.addChild(new Text(line, 1, 0));
				}
				for (const line of heartbeatLines) {
					container.addChild(new Text(line, 1, 0));
				}
				return container;
			},
			{ placement: "belowEditor" },
		);
	};

	return {
		notify: (text, level) => {
			options.consoleStream?.writeLine(`${level.toUpperCase()}: ${text}`);
			ctx.ui.notify(text, level);
		},
		setStatus: (key, text) => {
			if (key !== statusKey) {
				ctx.ui.setStatus(key, text);
				return;
			}
			// Phase runners clear their status after every phase. Keep the full
			// phase strip mounted until the command handler itself finishes.
			emitConsoleStatus(text);
			render(text);
		},
		onPhaseHeartbeat: (phase, heartbeat) => {
			if (heartbeat) {
				heartbeats.set(phase, heartbeat);
				const lastConsoleAt = lastConsoleHeartbeatAt.get(phase) ?? 0;
				if (lastConsoleAt === 0 || heartbeat.nowMs - lastConsoleAt >= 30_000) {
					lastConsoleHeartbeatAt.set(phase, heartbeat.nowMs);
					options.consoleStream?.writeLine(
						`[${phase}] ... ${formatPhaseHeartbeat(heartbeat, {
							includePhase: false,
						})}`,
					);
				}
			} else {
				heartbeats.delete(phase);
				lastConsoleHeartbeatAt.delete(phase);
			}
			if (heartbeat) {
				currentPhase = phase;
				hasPhaseActivity = true;
			}
			render();
		},
		clearStatus: () => {
			if (auditProgressTimer) clearInterval(auditProgressTimer);
			auditProgressTimer = undefined;
			if (preparingSpinnerTimer) clearInterval(preparingSpinnerTimer);
			preparingSpinnerTimer = undefined;
			ctx.ui.setStatus(statusKey, undefined);
			ctx.ui.setWidget(widgetKey, undefined);
		},
	};
}

async function runCommandWithRetry<T>(
	label: string,
	statusKey: string,
	ui: CommandUi,
	operation: (attempt: number, maxAttempts: number) => Promise<T>,
	options: { retryFailedStatus?: boolean } = {},
): Promise<T> {
	let lastFailedResult: T | undefined;
	try {
		return await runWithRetry(
			async (attempt, maxAttempts) => {
				if (maxAttempts > 1) {
					ui.setStatus(statusKey, `● ${label} (${attempt}/${maxAttempts})`);
				}
				const result = await operation(attempt, maxAttempts);
				if ((options.retryFailedStatus ?? true) && hasFailedStatus(result)) {
					lastFailedResult = result;
					throw new CommandFailedStatus(label, result);
				}
				return result;
			},
			{
				maxRetries: readNonNegativeIntEnv("PIOLIUM_COMMAND_MAX_RETRIES", 3),
				backoffBaseMs: readPositiveIntEnv("PIOLIUM_COMMAND_BACKOFF_BASE_MS", 5000),
				backoffMaxMs: readPositiveIntEnv("PIOLIUM_COMMAND_BACKOFF_MAX_MS", 120_000),
				onRetry: (info) => {
					ui.notify(
						`${label} attempt ${info.attempt}/${info.maxAttempts} failed; retrying in ${Math.ceil(info.backoffMs / 1000)}s.`,
						"warning",
					);
					ui.setStatus(statusKey, `● ${label} retrying in ${Math.ceil(info.backoffMs / 1000)}s`);
				},
			},
		);
	} catch (err) {
		if (err instanceof CommandFailedStatus && lastFailedResult !== undefined) {
			return lastFailedResult;
		}
		throw err;
	}
}

function summarizeArgs(args: unknown): string {
	if (!args || typeof args !== "object") return "";
	const obj = args as Record<string, unknown>;
	const pickKey = ["file_path", "path", "command", "pattern", "query", "url"].find(
		(k) => typeof obj[k] === "string",
	);
	if (pickKey) {
		const value = String(obj[pickKey]);
		return value.length > 120 ? `${value.slice(0, 117)}…` : value;
	}
	const json = JSON.stringify(obj);
	return json.length > 120 ? `${json.slice(0, 117)}…` : json;
}

function extractAssistantText(content: unknown): string {
	if (typeof content === "string") return content;
	if (!Array.isArray(content)) return "";
	return content
		.filter((c) => c && typeof c === "object" && (c as { type?: string }).type === "text")
		.map((c) => (c as { text?: string }).text ?? "")
		.join("");
}

function summarizeToolResult(result: unknown): string {
	if (result == null) return "";
	if (typeof result === "string") return result;
	if (typeof result === "number" || typeof result === "boolean") return String(result);
	if (Array.isArray(result)) {
		return result
			.map((item) => {
				if (typeof item === "string") return item;
				if (item && typeof item === "object" && "text" in (item as Record<string, unknown>)) {
					return String((item as { text?: unknown }).text ?? "");
				}
				return JSON.stringify(item);
			})
			.join("\n");
	}
	if (typeof result !== "object") return "";
	const obj = result as Record<string, unknown>;
	// MCP CallToolResult shape: { content: [{ type: "text", text: "..." }, ...] }
	if (Array.isArray(obj.content)) {
		const unwrapped = summarizeToolResult(obj.content);
		if (unwrapped) return unwrapped;
	}
	const preferKey = ["stdout", "output", "text", "content", "result"].find(
		(k) => typeof obj[k] === "string" && (obj[k] as string).length > 0,
	);
	if (preferKey) return obj[preferKey] as string;
	try {
		return JSON.stringify(obj);
	} catch {
		return "";
	}
}

function compactLine(text: string, max: number): string {
	const collapsed = text.replace(/\s+/g, " ").trim();
	if (collapsed.length <= max) return collapsed;
	return `${collapsed.slice(0, max - 1)}…`;
}

function formatPreparingStatusMessage(text: string): string {
	const stripped = text.replace(/^●\s*/, "").trim();
	return stripped || "preparing";
}

async function allowInitialUiPaint(): Promise<void> {
	await new Promise<void>((resolve) => setTimeout(resolve, INITIAL_UI_PAINT_DELAY_MS));
}

async function showCommandResult(
	ctx: { ui: { select: (title: string, lines: string[]) => Promise<unknown> } },
	consoleStream: PioliumConsoleStream,
	title: string,
	lines: string[],
	options: { footerLines?: string[] } = {},
): Promise<void> {
	const displayLines = withCommandResultDismissHint(lines, options.footerLines);
	consoleStream.writeBlock(title, displayLines);
	await ctx.ui.select(`${title} (${COMMAND_RESULT_DIALOG_HINT})`, displayLines);
}

function withCommandResultDismissHint(
	lines: readonly string[],
	footerLines: readonly string[] = [],
): string[] {
	if (lines.includes(COMMAND_RESULT_DISMISS_HINT)) return [...lines];
	const displayLines = [...lines];
	if (footerLines.length > 0) {
		if (displayLines.length > 0 && displayLines.at(-1) !== "") displayLines.push("");
		displayLines.push(...footerLines);
	}
	if (displayLines.length > 0 && displayLines.at(-1) !== "") displayLines.push("");
	displayLines.push(COMMAND_RESULT_DISMISS_HINT);
	return displayLines;
}

function notifyCommandError(
	ctx: { ui: { notify: (text: string, level: "error") => void } },
	consoleStream: PioliumConsoleStream,
	message: string,
): void {
	consoleStream.writeLine(`ERROR: ${message}`);
	ctx.ui.notify(message, "error");
}

function parseCommandTargetOrNotify(
	args: string,
	ctx: { cwd: string; ui: { notify: (text: string, level: "error") => void } },
	consoleStream: PioliumConsoleStream,
	pi: ExtensionAPI,
): ReturnType<typeof parsePioliumCommandArgs> | undefined {
	const parsed = parsePioliumCommandArgs(args, ctx.cwd, {
		defaultTarget: readPiFlagString(pi, FLAG_DIR),
	});
	if (parsed.error) {
		notifyCommandError(ctx, consoleStream, parsed.error);
		return undefined;
	}
	applyPioliumProcessFlagEnv(pi);
	return parsed;
}

function registerPioliumFlags(pi: ExtensionAPI): void {
	pi.registerFlag(FLAG_DIR, {
		description: "Default target directory for /piolium-* commands",
		type: "string",
	});
	pi.registerFlag(FLAG_SINCE, {
		description: "Default base commit for /piolium-diff",
		type: "string",
	});
	for (const spec of FLAG_ENV_MAPPINGS) {
		pi.registerFlag(spec.flag, {
			description: spec.description,
			type: "string",
		});
	}
}

function readPiFlagString(pi: ExtensionAPI, name: string): string | undefined {
	const value = pi.getFlag(name);
	if (typeof value !== "string") return undefined;
	const trimmed = value.trim();
	return trimmed.length > 0 ? trimmed : undefined;
}

function applyPioliumProcessFlagEnv(pi: ExtensionAPI): void {
	for (const spec of FLAG_ENV_MAPPINGS) {
		const value = readPiFlagString(pi, spec.flag);
		if (value) process.env[spec.env] = value;
	}
}

export function normalizeExportFormat(value: string | undefined): ExportFormat | undefined {
	if (!value || value === "json") return "json";
	if (value === "md-dir") return "md-dir";
	return undefined;
}

export function parseSeverityList(
	value: string | undefined,
): Array<NonNullable<ReturnType<typeof normalizeExportSeverity>>> | undefined {
	if (!value) return [];
	const severities: Array<NonNullable<ReturnType<typeof normalizeExportSeverity>>> = [];
	for (const part of value.split(/[,\s]+/).filter(Boolean)) {
		const severity = normalizeExportSeverity(part);
		if (!severity) return undefined;
		severities.push(severity);
	}
	return severities;
}

type StreamLineKind = "tool-start" | "tool-end" | "tool-error" | "assistant";

interface StreamLineDetails {
	kind: StreamLineKind;
	phase: string;
	toolName?: string;
	body?: string;
}

function makeAgentEventForwarder(pi: ExtensionAPI, consoleStream: PioliumConsoleStream) {
	const send = (details: StreamLineDetails, fallback: string) => {
		consoleStream.writeLine(fallback);
		pi.sendMessage<StreamLineDetails>({
			customType: PIOLIUM_STREAM,
			content: fallback,
			display: true,
			details,
		});
	};

	return (phase: string, event: AgentSessionEvent): void => {
		switch (event.type) {
			case "tool_execution_start": {
				const body = summarizeArgs(event.args);
				send(
					{ kind: "tool-start", phase, toolName: event.toolName, body },
					`[${phase}] → ${event.toolName}${body ? `  ${body}` : ""}`,
				);
				return;
			}
			case "tool_execution_end": {
				const body = compactLine(summarizeToolResult(event.result), 200);
				const kind: StreamLineKind = event.isError ? "tool-error" : "tool-end";
				const marker = event.isError ? "✗" : "←";
				send(
					{ kind, phase, toolName: event.toolName, body },
					`[${phase}] ${marker} ${event.toolName}${body ? `  ${body}` : ""}`,
				);
				return;
			}
			case "message_end": {
				const message = event.message as { role?: string; content?: unknown };
				if (message.role !== "assistant") return;
				const text = extractAssistantText(message.content).trim();
				if (!text) return;
				const head = compactLine(text, 240);
				send({ kind: "assistant", phase, body: head }, `[${phase}] ${head}`);
				return;
			}
		}
	};
}

/** Inline smoke-test agent. Hardcoded so the importer can wipe `agents/` without breaking it. */
const SMOKE_AGENT: AgentDefinition = {
	name: "piolium-smoke",
	description: "Piolium smoke test agent. Confirms the runner harness boots end-to-end.",
	systemPrompt: [
		"You are the piolium smoke test agent.",
		"When the user gives you a task, reply with a single short paragraph that:",
		"  1. confirms you received the task,",
		"  2. echoes the first 60 characters of the task verbatim,",
		"  3. announces 'piolium runner OK'.",
		"Do not call any tools. Do not perform any work beyond replying.",
	].join("\n"),
	allowedTools: [],
	skills: [],
	sourcePath: "<inline:piolium-smoke>",
};

export default function pioliumExtension(pi: ExtensionAPI) {
	registerPioliumFlags(pi);
	registerAnthropicVertex(pi);

	pi.on("session_start", async (_event, ctx) => {
		if (!ctx.hasUI) return;
		ctx.ui.notify(PIOLIUM_STARTUP_HINT, "info");
		if (shouldUsePioliumPromptPrefix(ctx.ui.theme)) {
			ctx.ui.setEditorComponent(
				(tui, theme, keybindings) => new PioliumPromptPrefixEditor(tui, theme, keybindings),
			);
		}
	});

	pi.registerMessageRenderer<StreamLineDetails>(PIOLIUM_STREAM, (message, _options, theme) => {
		const details = message.details;
		if (!details || typeof details !== "object") {
			const fallback = typeof message.content === "string" ? message.content : "";
			return new Text(theme.fg("muted", fallback), 0, 0);
		}
		const { kind, phase, toolName, body } = details;
		// Indent end/error lines so they visually nest under the matching start line.
		// The pad width matches the "[phase] " prefix on start lines.
		const phaseTag = theme.fg("accent", `[${phase}]`);
		const indent = " ".repeat(phase.length + 3);
		let line: string;
		switch (kind) {
			case "tool-start": {
				const arrow = theme.fg("muted", "→");
				const name = theme.fg("toolTitle", theme.bold(toolName ?? ""));
				const args = body ? ` ${theme.fg("muted", body)}` : "";
				line = `${phaseTag} ${arrow} ${name}${args}`;
				break;
			}
			case "tool-end": {
				const arrow = theme.fg("success", "←");
				const result = body ? ` ${theme.fg("dim", body)}` : ` ${theme.fg("dim", "(ok)")}`;
				line = `${indent}${arrow}${result}`;
				break;
			}
			case "tool-error": {
				const marker = theme.fg("error", "✗");
				const result = body ? ` ${theme.fg("error", body)}` : ` ${theme.fg("error", "failed")}`;
				line = `${indent}${marker}${result}`;
				break;
			}
			case "assistant":
				line = `${phaseTag} ${theme.fg("muted", body ?? "")}`;
				break;
			default:
				line = typeof message.content === "string" ? theme.fg("muted", message.content) : "";
		}
		return new Text(line, 0, 0);
	});

	const consoleStream = createPioliumConsoleStream();
	const onAgentEvent = makeAgentEventForwarder(pi, consoleStream);

	pi.registerCommand("piolium-help", {
		description: "Show piolium commands, CLI flags, and examples.",
		handler: async (_args, ctx) => {
			await showCommandResult(ctx, consoleStream, "Piolium — Help", buildPioliumHelpLines());
		},
	});

	pi.registerCommand("piolium-status", {
		description: "Show piolium audit progress for the current directory.",
		handler: async (args, ctx) => {
			const command = parseCommandTargetOrNotify(args, ctx, consoleStream, pi);
			if (!command) return;
			await runCommandWithRetry(
				"piolium-status",
				"piolium-status",
				ctx.ui,
				async () => {
					const result = readAuditState(command.cwd);
					if (!result.exists) {
						ctx.ui.notify(
							`No audit state at ${result.path}. Run /piolium-lite, /piolium-balanced, or /piolium-deep to start.`,
							"info",
						);
						return;
					}
					if (result.parseError) {
						ctx.ui.notify(`Failed to parse ${result.path}: ${result.parseError}`, "error");
						return;
					}
					if (!result.state) {
						ctx.ui.notify(`No state returned from ${result.path}.`, "warning");
						return;
					}
					const lines = formatAuditStatus(result.state);
					await showCommandResult(ctx, consoleStream, "Piolium — Audit Status", lines);
				},
				{ retryFailedStatus: false },
			);
		},
	});

	pi.registerCommand("piolium-resume", {
		description:
			"Resume the most recent non-complete audit (in_progress > failed) without re-specifying the mode.",
		handler: async (args, ctx) => {
			const command = parseCommandTargetOrNotify(args, ctx, consoleStream, pi);
			if (!command) return;

			const stateResult = readAuditState(command.cwd);
			if (!stateResult.exists) {
				ctx.ui.notify(
					`No audit state at ${stateResult.path}. Run /piolium-lite, /piolium-balanced, or /piolium-deep to start.`,
					"info",
				);
				return;
			}
			if (stateResult.parseError || !stateResult.state) {
				notifyCommandError(
					ctx,
					consoleStream,
					`Failed to parse ${stateResult.path}: ${stateResult.parseError ?? "no state returned"}`,
				);
				return;
			}

			const audit = latestResumableAudit(stateResult.state);
			if (!audit) {
				ctx.ui.notify(
					stateResult.state.audits.length === 0
						? `No audits recorded in ${stateResult.path} yet — start one with /piolium-lite, /piolium-balanced, or /piolium-deep.`
						: `Every audit in ${stateResult.path} is already complete; nothing to resume.`,
					"info",
				);
				return;
			}

			const mode = audit.mode;
			if (mode === "diff" || mode === "merge") {
				notifyCommandError(
					ctx,
					consoleStream,
					`Mode ${mode} doesn't support /piolium-resume — re-run /piolium-${mode} directly with its required arguments.`,
				);
				return;
			}

			const completed = Object.values(audit.phases).filter((p) => p.status === "complete").length;
			const total = Object.keys(audit.phases).length;
			ctx.ui.notify(
				`[resume] audit ${audit.audit_id} mode=${mode} status=${audit.status} (${completed}/${total} phases complete)`,
				"info",
			);

			const phases = phasesFor(mode);
			const initialPhase = phases[0];
			if (!initialPhase) {
				notifyCommandError(ctx, consoleStream, `Mode ${mode} has no phases; cannot resume.`);
				return;
			}
			const commandKey = `piolium-${mode}`;
			const phaseUi = createPhaseStripCommandUi({ cwd: command.cwd, ui: ctx.ui }, commandKey, phases, {
				initialPhase,
				consoleStream,
			});
			phaseUi.setStatus(commandKey, `● resuming ${mode} audit`);
			await allowInitialUiPaint();

			const runnerUi = {
				notify: phaseUi.notify,
				setStatus: phaseUi.setStatus,
				onAgentEvent,
				onPhaseHeartbeat: phaseUi.onPhaseHeartbeat,
			};
			const baseOpts = {
				cwd: command.cwd,
				forceFresh: false as const,
				agentRuntime: agentRuntimeFromCommandContext(pi, ctx),
				ui: runnerUi,
			};

			try {
				const dispatched = await runCommandWithRetry(commandKey, commandKey, phaseUi, async () => {
					switch (mode) {
						case "lite": {
							const r = await runLiteAudit(baseOpts);
							return {
								auditId: r.auditId,
								extraLines: [`Recon report: ${r.summaryPath}`],
								phases: r.phases,
								status: r.status,
							};
						}
						case "balanced": {
							const r = await runBalancedAudit(baseOpts);
							return {
								auditId: r.auditId,
								extraLines: [],
								phases: r.phases,
								status: r.status,
							};
						}
						case "deep": {
							const r = await runDeepAudit(baseOpts);
							return {
								auditId: r.auditId,
								extraLines: [],
								phases: r.phases,
								status: r.status,
							};
						}
						case "confirm": {
							const r = await runConfirmAudit(baseOpts);
							return {
								auditId: r.auditId,
								extraLines: [],
								phases: r.phases,
								status: r.status,
							};
						}
						case "revisit": {
							const r = await runRevisitAudit(baseOpts);
							return {
								auditId: r.auditId,
								extraLines: [],
								phases: r.phases,
								status: r.status,
							};
						}
						case "longshot": {
							const r = await runLongshotAudit(baseOpts);
							return {
								auditId: r.auditId,
								extraLines: [
									`Files hunted:    ${r.targetsCompleted}/${r.targetsTotal}`,
									`Files failed:    ${r.targetsFailed}`,
								],
								phases: r.phases,
								status: r.status,
								footerExtras: [`Targets file: ${r.targetsPath}`, `Summary:      ${r.summaryPath}`],
							};
						}
						case "reinvest": {
							const r = await runReinvestAudit(baseOpts);
							return {
								auditId: r.auditId,
								extraLines: [
									`Findings reinvested: ${r.reinvestedCount}`,
									`Flipped to DISPROVED: ${r.flippedCount}`,
									`Mixed / uncertain:   ${r.uncertainCount}`,
								],
								phases: r.phases,
								status: r.status,
								footerExtras: [`Report: ${r.reportPath}`],
							};
						}
					}
				});

				if (!dispatched) return;
				const phaseLines = formatCommandPhaseLines(command.cwd, dispatched.auditId, dispatched.phases);
				await showCommandResult(
					ctx,
					consoleStream,
					`Piolium — Resume (${mode})`,
					[
						`Directory: ${command.cwd}`,
						`Audit:  ${dispatched.auditId}`,
						`Status: ${dispatched.status}`,
						...dispatched.extraLines,
						"",
						"Phases:",
						...phaseLines,
						...(dispatched.footerExtras ? ["", ...dispatched.footerExtras] : []),
					],
					{
						footerLines: buildAuditResultStatsLines(command.cwd, dispatched.auditId),
					},
				);
			} catch (err) {
				notifyCommandError(
					ctx,
					consoleStream,
					`Resume threw: ${err instanceof Error ? err.message : String(err)}`,
				);
			} finally {
				phaseUi.clearStatus();
			}
		},
	});

	pi.registerCommand("piolium-export", {
		description:
			"Export finalized findings with severity, confirmation, false-positive, since, and owner filters.",
		handler: async (args, ctx) => {
			const command = parseCommandTargetOrNotify(args, ctx, consoleStream, pi);
			if (!command) return;
			await runCommandWithRetry(
				"piolium-export",
				"piolium-export",
				ctx.ui,
				async () => {
					const formatToken = readOptionValue(command.tokens, "--format");
					const format = normalizeExportFormat(formatToken);
					if (!format) {
						notifyCommandError(ctx, consoleStream, "Invalid --format. Use json or md-dir.");
						return;
					}
					const minSeverityToken = readOptionValue(command.tokens, "--min-severity");
					const minSeverity = normalizeExportSeverity(minSeverityToken);
					if (minSeverityToken && !minSeverity) {
						notifyCommandError(ctx, consoleStream, "Invalid --min-severity.");
						return;
					}
					const onlySeverityToken = readOptionValue(command.tokens, "--only-severity");
					const onlySeverity = parseSeverityList(onlySeverityToken);
					if (onlySeverityToken && !onlySeverity) {
						notifyCommandError(ctx, consoleStream, "Invalid --only-severity.");
						return;
					}
					const result = runExport(command.cwd, {
						format,
						...(readOptionValue(command.tokens, "--out")
							? { outPath: readOptionValue(command.tokens, "--out") }
							: {}),
						...(minSeverity ? { minSeverity } : {}),
						...(onlySeverity && onlySeverity.length > 0 ? { onlySeverity } : {}),
						confirmedOnly: command.tokens.includes("--confirmed-only"),
						excludeFp: command.tokens.includes("--exclude-fp"),
						...(readOptionValue(command.tokens, "--since")
							? { since: readOptionValue(command.tokens, "--since") }
							: {}),
						requireOwner: command.tokens.includes("--require-owner"),
					});
					await showCommandResult(ctx, consoleStream, "Piolium — Export", result.lines);
				},
				{ retryFailedStatus: false },
			);
		},
	});

	pi.registerCommand("piolium-learn", {
		description:
			"Generate project-local candidate matcher suggestions from finalized findings. Pass --apply to merge them into piolium/matchers.json.",
		handler: async (args, ctx) => {
			const command = parseCommandTargetOrNotify(args, ctx, consoleStream, pi);
			if (!command) return;
			await runCommandWithRetry(
				"piolium-learn",
				"piolium-learn",
				ctx.ui,
				async () => {
					const result = runMatcherLearn(command.cwd, { apply: command.tokens.includes("--apply") });
					await showCommandResult(ctx, consoleStream, "Piolium — Learn Matchers", result.lines);
				},
				{ retryFailedStatus: false },
			);
		},
	});

	pi.registerCommand("piolium-smoke", {
		description: "Run a tiny inline agent end-to-end to verify the piolium runner works.",
		handler: async (args, ctx) => {
			const command = parseCommandTargetOrNotify(args, ctx, consoleStream, pi);
			if (!command) return;
			const task =
				command.args.trim().length > 0
					? command.args.trim()
					: "Hello from piolium. Please confirm the runner is working.";
			ctx.ui.setStatus("piolium-smoke", "● running smoke agent");
			try {
				await runCommandWithRetry(
					"piolium-smoke",
					"piolium-smoke",
					ctx.ui,
					async (attempt) => {
						const runId = `smoke-${new Date().toISOString().replace(/[:.]/g, "-")}-a${attempt}-${randomUUID().slice(0, 8)}`;
						const result = await runAgent({
							agent: SMOKE_AGENT,
							task,
							runId,
							runtime: { cwd: command.cwd, mode: "lite", phase: "smoke" },
							...agentRuntimeFromCommandContext(pi, ctx),
						});
						ctx.ui.setStatus("piolium-smoke", undefined);
						const lines = [
							`Run id:     ${runId}`,
							`Duration:   ${result.durationMs}ms`,
							`Stop:       ${result.stopReason ?? "(none)"}`,
							`Transcript: ${result.transcriptPath}`,
							`Result:     ${result.resultPath}`,
							"",
							"--- final text ---",
							result.text || "(no output)",
						];
						await showCommandResult(ctx, consoleStream, "Piolium — Smoke", lines);
					},
					{ retryFailedStatus: false },
				);
			} catch (err) {
				ctx.ui.setStatus("piolium-smoke", undefined);
				if (err instanceof AgentRunError) {
					notifyCommandError(
						ctx,
						consoleStream,
						`Smoke agent failed: ${err.message}. Transcript: ${err.result.transcriptPath}`,
					);
				} else {
					notifyCommandError(
						ctx,
						consoleStream,
						`Smoke agent failed: ${err instanceof Error ? err.message : String(err)}`,
					);
				}
			}
		},
	});

	pi.registerCommand("piolium-lite", {
		description: "Run the lite audit pipeline (Q0 recon → Q1 secrets + Q2 fast SAST → Q3 cleanup).",
		handler: async (args, ctx) => {
			const command = parseCommandTargetOrNotify(args, ctx, consoleStream, pi);
			if (!command) return;
			const fresh = command.tokens.includes("--fresh");
			const phaseUi = createPhaseStripCommandUi(
				{ cwd: command.cwd, ui: ctx.ui },
				"piolium-lite",
				phasesFor("lite"),
				{
					initialPhase: "Q0",
					consoleStream,
				},
			);
			phaseUi.setStatus("piolium-lite", "● starting lite audit");
			await allowInitialUiPaint();
			try {
				const result = await runCommandWithRetry("piolium-lite", "piolium-lite", phaseUi, async () =>
					runLiteAudit({
						cwd: command.cwd,
						forceFresh: fresh,
						agentRuntime: agentRuntimeFromCommandContext(pi, ctx),
						ui: {
							notify: phaseUi.notify,
							setStatus: phaseUi.setStatus,
							onAgentEvent,
							onPhaseHeartbeat: phaseUi.onPhaseHeartbeat,
						},
					}),
				);
				const phaseLines = formatCommandPhaseLines(command.cwd, result.auditId, result.phases);
				await showCommandResult(
					ctx,
					consoleStream,
					"Piolium — Lite Audit",
					[
						`Directory: ${command.cwd}`,
						`Audit:  ${result.auditId}`,
						`Status: ${result.status}`,
						"",
						"Phases:",
						...phaseLines,
						"",
						`Recon report: ${result.summaryPath}`,
					],
					{
						footerLines: buildAuditResultStatsLines(command.cwd, result.auditId),
					},
				);
			} catch (err) {
				notifyCommandError(
					ctx,
					consoleStream,
					`Lite audit threw: ${err instanceof Error ? err.message : String(err)}`,
				);
			} finally {
				phaseUi.clearStatus();
			}
		},
	});

	pi.registerCommand("piolium-deep", {
		description:
			"Run the deep audit pipeline as 17 ordered stages with clear names. Pass an internal phase id (e.g. P5) to rerun a single stage.",
		handler: async (args, ctx) => {
			const command = parseCommandTargetOrNotify(args, ctx, consoleStream, pi);
			if (!command) return;
			const tokens = command.tokens;
			const fresh = tokens.includes("--fresh");
			const deepPhases = phasesFor("deep");
			const phaseTokens = tokens.filter((t) => /^P[0-9]+[A-Za-z]?[a-z]?$/.test(t));
			const invalidPhaseTokens = phaseTokens.filter((t) => !deepPhases.includes(t));
			if (invalidPhaseTokens.length > 0) {
				notifyCommandError(
					ctx,
					consoleStream,
					`Unknown deep phase ${invalidPhaseTokens.join(", ")}. Valid phases: ${deepPhases.join(", ")}`,
				);
				return;
			}
			const only = phaseTokens;
			const phaseUi = createPhaseStripCommandUi(
				{ cwd: command.cwd, ui: ctx.ui },
				"piolium-deep",
				deepPhases,
				{
					initialPhase: only[0] ?? "P1",
					consoleStream,
				},
			);
			phaseUi.setStatus("piolium-deep", "● starting deep audit");
			await allowInitialUiPaint();
			try {
				const result = await runCommandWithRetry("piolium-deep", "piolium-deep", phaseUi, async () =>
					runDeepAudit({
						cwd: command.cwd,
						forceFresh: fresh,
						agentRuntime: agentRuntimeFromCommandContext(pi, ctx),
						...(only.length > 0 ? { only } : {}),
						ui: {
							notify: phaseUi.notify,
							setStatus: phaseUi.setStatus,
							onAgentEvent,
							onPhaseHeartbeat: phaseUi.onPhaseHeartbeat,
						},
					}),
				);
				const phaseLines = formatCommandPhaseLines(command.cwd, result.auditId, result.phases);
				await showCommandResult(
					ctx,
					consoleStream,
					"Piolium — Deep Audit",
					[
						`Directory: ${command.cwd}`,
						`Audit:  ${result.auditId}`,
						`Status: ${result.status}`,
						...(only.length > 0 ? [`Phases requested: ${only.join(", ")}`] : []),
						"",
						"Phases:",
						...phaseLines,
					],
					{
						footerLines: buildAuditResultStatsLines(command.cwd, result.auditId),
					},
				);
			} catch (err) {
				notifyCommandError(
					ctx,
					consoleStream,
					`Deep audit threw: ${err instanceof Error ? err.message : String(err)}`,
				);
			} finally {
				phaseUi.clearStatus();
			}
		},
	});

	pi.registerCommand("piolium-confirm", {
		description:
			"Run the confirmation pass over an existing audit (V1-V7). Pass a remote URL to skip local provisioning. If cwd has only the piolium/ results folder, the source repo is auto-cloned into a sibling <repo>-confirm/ directory; pass --repo <url> to override the inferred clone URL.",
		handler: async (args, ctx) => {
			const command = parseCommandTargetOrNotify(args, ctx, consoleStream, pi);
			if (!command) return;
			const tokens = command.tokens;
			const fresh = tokens.includes("--fresh");
			const repoOverride = readOptionValue(tokens, "--repo");
			const target = tokens.find((t) => /^https?:\/\//.test(t) && t !== repoOverride);

			let effectiveCwd = command.cwd;
			try {
				const bootstrap = bootstrapResultsOnlyConfirm({
					cwd: command.cwd,
					...(repoOverride ? { repoOverride } : {}),
					notify: (text, level) => ctx.ui.notify(text, level ?? "info"),
				});
				effectiveCwd = bootstrap.cwd;
				if (bootstrap.bootstrapped && bootstrap.cloneDir) {
					consoleStream.writeLine(
						`Confirm bootstrap: cloned ${bootstrap.cloneUrl} → ${bootstrap.cloneDir}`,
					);
				}
			} catch (err) {
				notifyCommandError(
					ctx,
					consoleStream,
					`Confirm bootstrap failed: ${err instanceof Error ? err.message : String(err)}`,
				);
				return;
			}

			const phaseUi = createPhaseStripCommandUi(
				{ cwd: effectiveCwd, ui: ctx.ui },
				"piolium-confirm",
				phasesFor("confirm"),
				{
					initialPhase: "V1",
					consoleStream,
				},
			);
			phaseUi.setStatus("piolium-confirm", "● starting confirm pass");
			await allowInitialUiPaint();
			try {
				const result = await runCommandWithRetry(
					"piolium-confirm",
					"piolium-confirm",
					phaseUi,
					async () =>
						runConfirmAudit({
							cwd: effectiveCwd,
							forceFresh: fresh,
							agentRuntime: agentRuntimeFromCommandContext(pi, ctx),
							...(target ? { target } : {}),
							ui: {
								notify: phaseUi.notify,
								setStatus: phaseUi.setStatus,
								onAgentEvent,
								onPhaseHeartbeat: phaseUi.onPhaseHeartbeat,
							},
						}),
				);
				const phaseLines = formatCommandPhaseLines(effectiveCwd, result.auditId, result.phases);
				await showCommandResult(
					ctx,
					consoleStream,
					"Piolium — Confirm",
					[
						`Directory: ${effectiveCwd}`,
						`Audit:  ${result.auditId}`,
						`Status: ${result.status}`,
						"",
						"Phases:",
						...phaseLines,
					],
					{
						footerLines: buildAuditResultStatsLines(effectiveCwd, result.auditId),
					},
				);
			} catch (err) {
				notifyCommandError(
					ctx,
					consoleStream,
					`Confirm threw: ${err instanceof Error ? err.message : String(err)}`,
				);
			} finally {
				phaseUi.clearStatus();
			}
		},
	});

	pi.registerCommand("piolium-diff", {
		description:
			"Re-audit only files changed since the last completed audit. Pass `--since=<sha>` to override the prior commit.",
		handler: async (args, ctx) => {
			const command = parseCommandTargetOrNotify(args, ctx, consoleStream, pi);
			if (!command) return;
			const since =
				readOptionValue(command.tokens, "--since") ??
				readOptionValue(command.tokens, "--plm-since") ??
				readPiFlagString(pi, FLAG_SINCE);
			ctx.ui.setStatus("piolium-diff", "● starting diff");
			await allowInitialUiPaint();
			try {
				const result = await runCommandWithRetry("piolium-diff", "piolium-diff", ctx.ui, async () =>
					runDiffAudit({
						cwd: command.cwd,
						agentRuntime: agentRuntimeFromCommandContext(pi, ctx),
						...(since ? { since } : {}),
						ui: {
							notify: (text, level) => ctx.ui.notify(text, level),
							setStatus: (key, text) => ctx.ui.setStatus(key, text),
							onAgentEvent,
						},
					}),
				);
				await showCommandResult(
					ctx,
					consoleStream,
					"Piolium — Diff",
					[
						`Directory:     ${command.cwd}`,
						`Status:        ${result.status}`,
						`Prior commit:  ${result.priorCommit ?? "(none)"}`,
						`Changed files: ${result.changedFiles.length}`,
						...result.changedFiles.slice(0, 30).map((f) => `  - ${f}`),
						...(result.changedFiles.length > 30 ? [`  ... ${result.changedFiles.length - 30} more`] : []),
					],
					{
						footerLines: result.auditId
							? buildAuditResultStatsLines(command.cwd, result.auditId)
							: undefined,
					},
				);
			} catch (err) {
				ctx.ui.setStatus("piolium-diff", undefined);
				notifyCommandError(
					ctx,
					consoleStream,
					`Diff threw: ${err instanceof Error ? err.message : String(err)}`,
				);
			}
		},
	});

	pi.registerCommand("piolium-revisit", {
		description:
			"Second-pass re-audit with anti-anchoring prompts (R0 intent corpus → R5 → ... → R11c).",
		handler: async (args, ctx) => {
			const command = parseCommandTargetOrNotify(args, ctx, consoleStream, pi);
			if (!command) return;
			const fresh = command.tokens.includes("--fresh");
			const phaseUi = createPhaseStripCommandUi(
				{ cwd: command.cwd, ui: ctx.ui },
				"piolium-revisit",
				phasesFor("revisit"),
				{
					initialPhase: "R0",
					consoleStream,
				},
			);
			phaseUi.setStatus("piolium-revisit", "● starting revisit");
			await allowInitialUiPaint();
			try {
				const result = await runCommandWithRetry(
					"piolium-revisit",
					"piolium-revisit",
					phaseUi,
					async () =>
						runRevisitAudit({
							cwd: command.cwd,
							forceFresh: fresh,
							agentRuntime: agentRuntimeFromCommandContext(pi, ctx),
							ui: {
								notify: phaseUi.notify,
								setStatus: phaseUi.setStatus,
								onAgentEvent,
								onPhaseHeartbeat: phaseUi.onPhaseHeartbeat,
							},
						}),
				);
				const phaseLines = formatCommandPhaseLines(command.cwd, result.auditId, result.phases);
				await showCommandResult(
					ctx,
					consoleStream,
					"Piolium — Revisit",
					[
						`Directory: ${command.cwd}`,
						`Audit:  ${result.auditId}`,
						`Status: ${result.status}`,
						"",
						"Phases:",
						...phaseLines,
					],
					{
						footerLines: buildAuditResultStatsLines(command.cwd, result.auditId),
					},
				);
			} catch (err) {
				notifyCommandError(
					ctx,
					consoleStream,
					`Revisit threw: ${err instanceof Error ? err.message : String(err)}`,
				);
			} finally {
				phaseUi.clearStatus();
			}
		},
	});

	pi.registerCommand("piolium-merge", {
		description:
			"Merge multiple piolium/ result trees into one canonical output. Usage: /piolium-merge --dir=<path> --dir=<path> [...]",
		handler: async (args, ctx) => {
			const command = parseCommandTargetOrNotify(args, ctx, consoleStream, pi);
			if (!command) return;
			const dirs = readRepeatedOptionValues(command.tokens, "--dir");
			if (dirs.length < 2) {
				ctx.ui.notify("Need at least two --dir arguments pointing at piolium/ trees.", "warning");
				return;
			}
			const phaseUi = createPhaseStripCommandUi(
				{ cwd: command.cwd, ui: ctx.ui },
				"piolium-merge",
				phasesFor("merge"),
				{
					initialPhase: "M1",
					consoleStream,
				},
			);
			phaseUi.setStatus("piolium-merge", "● starting merge");
			await allowInitialUiPaint();
			try {
				const result = await runCommandWithRetry("piolium-merge", "piolium-merge", phaseUi, async () =>
					runMergeAudit({
						cwd: command.cwd,
						sources: dirs,
						agentRuntime: agentRuntimeFromCommandContext(pi, ctx),
						ui: {
							notify: phaseUi.notify,
							setStatus: phaseUi.setStatus,
							onAgentEvent,
							onPhaseHeartbeat: phaseUi.onPhaseHeartbeat,
						},
					}),
				);
				await showCommandResult(
					ctx,
					consoleStream,
					"Piolium — Merge",
					[
						`Directory: ${command.cwd}`,
						`Audit:  ${result.auditId}`,
						`Status: ${result.status}`,
						`Merged finding dirs: ${result.mergedFindings.length}`,
					],
					{
						footerLines: buildAuditResultStatsLines(command.cwd, result.auditId),
					},
				);
			} catch (err) {
				notifyCommandError(
					ctx,
					consoleStream,
					`Merge threw: ${err instanceof Error ? err.message : String(err)}`,
				);
			} finally {
				phaseUi.clearStatus();
			}
		},
	});

	pi.registerCommand("piolium-balanced", {
		description:
			"Run the balanced audit pipeline (L1 → L2 → [L3 + L4] → L5 → L6 → L6b → L6c → L7 cleanup).",
		handler: async (args, ctx) => {
			const command = parseCommandTargetOrNotify(args, ctx, consoleStream, pi);
			if (!command) return;
			const fresh = command.tokens.includes("--fresh");
			const phaseUi = createPhaseStripCommandUi(
				{ cwd: command.cwd, ui: ctx.ui },
				"piolium-balanced",
				phasesFor("balanced"),
				{
					initialPhase: "L1",
					consoleStream,
				},
			);
			phaseUi.setStatus("piolium-balanced", "● starting balanced audit");
			await allowInitialUiPaint();
			try {
				const result = await runCommandWithRetry(
					"piolium-balanced",
					"piolium-balanced",
					phaseUi,
					async () =>
						runBalancedAudit({
							cwd: command.cwd,
							forceFresh: fresh,
							agentRuntime: agentRuntimeFromCommandContext(pi, ctx),
							ui: {
								notify: phaseUi.notify,
								setStatus: phaseUi.setStatus,
								onAgentEvent,
								onPhaseHeartbeat: phaseUi.onPhaseHeartbeat,
							},
						}),
				);
				const phaseLines = formatCommandPhaseLines(command.cwd, result.auditId, result.phases);
				await showCommandResult(
					ctx,
					consoleStream,
					"Piolium — Balanced Audit",
					[
						`Directory: ${command.cwd}`,
						`Audit:  ${result.auditId}`,
						`Status: ${result.status}`,
						"",
						"Phases:",
						...phaseLines,
					],
					{
						footerLines: buildAuditResultStatsLines(command.cwd, result.auditId),
					},
				);
			} catch (err) {
				notifyCommandError(
					ctx,
					consoleStream,
					`Balanced audit threw: ${err instanceof Error ? err.message : String(err)}`,
				);
			} finally {
				phaseUi.clearStatus();
			}
		},
	});

	pi.registerCommand("piolium-longshot", {
		description:
			"Hail-mary scan: enumerate every interesting source file, hunt each one in parallel, then aggregate (X1 → X2 → X3).",
		handler: async (args, ctx) => {
			const command = parseCommandTargetOrNotify(args, ctx, consoleStream, pi);
			if (!command) return;
			const tokens = command.tokens;
			const fresh = tokens.includes("--fresh");
			const includeTests = tokens.includes("--include-tests");
			const limitToken =
				readOptionValue(tokens, "--limit") ??
				readOptionValue(tokens, "--plm-longshot-limit") ??
				readPiFlagString(pi, "plm-longshot-limit");
			const timeoutToken =
				readOptionValue(tokens, "--timeout") ??
				readOptionValue(tokens, "--plm-longshot-timeout") ??
				readPiFlagString(pi, "plm-longshot-timeout");
			const langsToken =
				readOptionValue(tokens, "--langs") ??
				readOptionValue(tokens, "--plm-longshot-langs") ??
				readPiFlagString(pi, "plm-longshot-langs");
			const limit = limitToken ? Number.parseInt(limitToken, 10) : undefined;
			const perFileTimeoutMs = timeoutToken ? Number.parseInt(timeoutToken, 10) : undefined;
			const languages = langsToken
				? langsToken
						.split(/[,\s]+/)
						.map((s) => s.trim())
						.filter(Boolean)
				: undefined;
			const phaseUi = createPhaseStripCommandUi(
				{ cwd: command.cwd, ui: ctx.ui },
				"piolium-longshot",
				phasesFor("longshot"),
				{
					initialPhase: "X1",
					consoleStream,
				},
			);
			phaseUi.setStatus("piolium-longshot", "● starting longshot");
			await allowInitialUiPaint();
			try {
				const result = await runCommandWithRetry(
					"piolium-longshot",
					"piolium-longshot",
					phaseUi,
					async () =>
						runLongshotAudit({
							cwd: command.cwd,
							forceFresh: fresh,
							agentRuntime: agentRuntimeFromCommandContext(pi, ctx),
							...(limit && Number.isFinite(limit) && limit > 0 ? { limit } : {}),
							...(perFileTimeoutMs && Number.isFinite(perFileTimeoutMs) && perFileTimeoutMs > 0
								? { perFileTimeoutMs }
								: {}),
							...(languages && languages.length > 0 ? { languages } : {}),
							includeTests,
							ui: {
								notify: phaseUi.notify,
								setStatus: phaseUi.setStatus,
								onAgentEvent,
								onPhaseHeartbeat: phaseUi.onPhaseHeartbeat,
							},
						}),
				);
				const phaseLines = formatCommandPhaseLines(command.cwd, result.auditId, result.phases);
				await showCommandResult(
					ctx,
					consoleStream,
					"Piolium — Longshot",
					[
						`Directory: ${command.cwd}`,
						`Audit:  ${result.auditId}`,
						`Status: ${result.status}`,
						`Files hunted:    ${result.targetsCompleted}/${result.targetsTotal}`,
						`Files failed:    ${result.targetsFailed}`,
						"",
						"Phases:",
						...phaseLines,
						"",
						`Targets file: ${result.targetsPath}`,
						`Summary:      ${result.summaryPath}`,
					],
					{
						footerLines: buildAuditResultStatsLines(command.cwd, result.auditId),
					},
				);
			} catch (err) {
				notifyCommandError(
					ctx,
					consoleStream,
					`Longshot threw: ${err instanceof Error ? err.message : String(err)}`,
				);
			} finally {
				phaseUi.clearStatus();
			}
		},
	});

	pi.registerCommand("piolium-reinvest", {
		description:
			"Cross-agent re-verification of CRIT/HIGH findings (I1 enumerate → I2 wave-verifier fan-out → I3 consensus). Optional comma-separated finding-id list to scope the run.",
		handler: async (args, ctx) => {
			const command = parseCommandTargetOrNotify(args, ctx, consoleStream, pi);
			if (!command) return;
			const tokens = command.tokens;
			const fresh = tokens.includes("--fresh");
			const scopeToken = readOptionValue(tokens, "--scope") ?? readOptionValue(tokens, "--ids");
			const positionalScope = tokens.find((t) => /^[CH][0-9]+(,[CH][0-9]+)*$/i.test(t));
			const scopeRaw = scopeToken ?? positionalScope;
			const scope = scopeRaw
				? scopeRaw
						.split(",")
						.map((s) => s.trim())
						.filter(Boolean)
				: undefined;

			const phaseUi = createPhaseStripCommandUi(
				{ cwd: command.cwd, ui: ctx.ui },
				"piolium-reinvest",
				phasesFor("reinvest"),
				{
					initialPhase: "I1",
					consoleStream,
				},
			);
			phaseUi.setStatus("piolium-reinvest", "● starting reinvest");
			await allowInitialUiPaint();
			try {
				const result = await runCommandWithRetry(
					"piolium-reinvest",
					"piolium-reinvest",
					phaseUi,
					async () =>
						runReinvestAudit({
							cwd: command.cwd,
							forceFresh: fresh,
							agentRuntime: agentRuntimeFromCommandContext(pi, ctx),
							...(scope && scope.length > 0 ? { scope } : {}),
							ui: {
								notify: phaseUi.notify,
								setStatus: phaseUi.setStatus,
								onAgentEvent,
								onPhaseHeartbeat: phaseUi.onPhaseHeartbeat,
							},
						}),
				);
				const phaseLines = formatCommandPhaseLines(command.cwd, result.auditId, result.phases);
				await showCommandResult(
					ctx,
					consoleStream,
					"Piolium — Reinvest",
					[
						`Directory: ${command.cwd}`,
						`Audit:  ${result.auditId}`,
						`Status: ${result.status}`,
						`Findings reinvested: ${result.reinvestedCount}`,
						`Flipped to DISPROVED: ${result.flippedCount}`,
						`Mixed / uncertain:   ${result.uncertainCount}`,
						"",
						"Phases:",
						...phaseLines,
						"",
						`Report: ${result.reportPath}`,
					],
					{
						footerLines: buildAuditResultStatsLines(command.cwd, result.auditId),
					},
				);
			} catch (err) {
				notifyCommandError(
					ctx,
					consoleStream,
					`Reinvest threw: ${err instanceof Error ? err.message : String(err)}`,
				);
			} finally {
				phaseUi.clearStatus();
			}
		},
	});
}
