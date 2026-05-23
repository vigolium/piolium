import type { AgentSessionEvent } from "@earendil-works/pi-coding-agent";

export interface PhaseHeartbeat {
	phase: string;
	label: string;
	startedAtMs: number;
	lastEventAtMs: number;
	nowMs: number;
	lastToolName?: string;
	lastToolSummary?: string;
	lastAssistantSummary?: string;
	runId?: string;
}

export interface PhaseHeartbeatTracker {
	recordEvent(event: AgentSessionEvent): void;
	snapshot(nowMs?: number): PhaseHeartbeat;
}

export const DEFAULT_HEARTBEAT_INTERVAL_MS = 30_000;
export const DEFAULT_HEARTBEAT_QUIET_MS = 90_000;
export const DEFAULT_HEARTBEAT_STALLED_MS = 5 * 60_000;
export const PHASE_HEARTBEAT_UI_COLOR = "mdLink";

export function createPhaseHeartbeatTracker(options: {
	phase: string;
	label: string;
	runId?: string;
	nowMs?: number;
}): PhaseHeartbeatTracker {
	const startedAtMs = options.nowMs ?? Date.now();
	let lastEventAtMs = startedAtMs;
	let lastToolName: string | undefined;
	let lastToolSummary: string | undefined;
	let lastAssistantSummary: string | undefined;

	return {
		recordEvent(event) {
			lastEventAtMs = Date.now();
			if (event.type === "tool_execution_start") {
				const toolName = stringFromUnknown((event as { toolName?: unknown }).toolName);
				if (toolName) lastToolName = toolName;
				const summary = summarizeArgs((event as { args?: unknown }).args);
				lastToolSummary = summary || undefined;
			}
			if (event.type === "message_end") {
				const message = (event as { message?: unknown }).message;
				const text = extractAssistantText(
					message && typeof message === "object"
						? (message as { content?: unknown }).content
						: undefined,
				);
				lastAssistantSummary = compactLine(text, 80) || undefined;
			}
		},
		snapshot(nowMs = Date.now()) {
			return {
				phase: options.phase,
				label: options.label,
				startedAtMs,
				lastEventAtMs,
				nowMs,
				...(lastToolName ? { lastToolName } : {}),
				...(lastToolSummary ? { lastToolSummary } : {}),
				...(lastAssistantSummary ? { lastAssistantSummary } : {}),
				...(options.runId ? { runId: options.runId } : {}),
			};
		},
	};
}

export function formatPhaseHeartbeat(
	heartbeat: PhaseHeartbeat,
	options: {
		quietMs?: number;
		stalledMs?: number;
		nowMs?: number;
		includePhase?: boolean;
	} = {},
): string {
	const nowMs = options.nowMs ?? heartbeat.nowMs;
	const quietMs = options.quietMs ?? DEFAULT_HEARTBEAT_QUIET_MS;
	const stalledMs = options.stalledMs ?? DEFAULT_HEARTBEAT_STALLED_MS;
	const elapsedMs = Math.max(0, nowMs - heartbeat.startedAtMs);
	const idleMs = Math.max(0, nowMs - heartbeat.lastEventAtMs);
	const prefix = options.includePhase === false ? "" : `${heartbeat.phase} `;
	const status = idleMs >= stalledMs ? "may be stalled" : "running";
	const idle =
		idleMs >= quietMs
			? `quiet for ${formatDuration(idleMs)}`
			: `last output ${formatDuration(idleMs)} ago`;
	const tool = heartbeat.lastToolName
		? `last tool: ${compactLine(
				`${heartbeat.lastToolName}${heartbeat.lastToolSummary ? ` ${heartbeat.lastToolSummary}` : ""}`,
				90,
			)}`
		: heartbeat.lastAssistantSummary
			? `last note: ${heartbeat.lastAssistantSummary}`
			: "waiting for first event";
	return `${prefix}${status} ${formatDuration(elapsedMs)} · ${idle} · ${tool}`;
}

export function formatPhaseHeartbeatStatusLine(
	heartbeat: PhaseHeartbeat,
	options: Parameters<typeof formatPhaseHeartbeat>[1] = {},
): string {
	return `↳ health: ${formatPhaseHeartbeat(heartbeat, options)}`;
}

export function phaseHeartbeatColor(
	heartbeat: PhaseHeartbeat,
	options: { quietMs?: number; stalledMs?: number; nowMs?: number } = {},
): "warning" | "muted" | "dim" {
	const nowMs = options.nowMs ?? heartbeat.nowMs;
	const quietMs = options.quietMs ?? DEFAULT_HEARTBEAT_QUIET_MS;
	const stalledMs = options.stalledMs ?? DEFAULT_HEARTBEAT_STALLED_MS;
	const idleMs = Math.max(0, nowMs - heartbeat.lastEventAtMs);
	if (idleMs >= stalledMs) return "warning";
	if (idleMs >= quietMs) return "muted";
	return "dim";
}

export function heartbeatStateFields(heartbeat: PhaseHeartbeat): {
	heartbeat_at: string;
	last_event_at: string;
	last_tool: string | null;
	last_tool_summary: string | null;
	run_id: string | null;
} {
	return {
		heartbeat_at: new Date(heartbeat.nowMs).toISOString(),
		last_event_at: new Date(heartbeat.lastEventAtMs).toISOString(),
		last_tool: heartbeat.lastToolName ?? null,
		last_tool_summary: heartbeat.lastToolSummary ?? null,
		run_id: heartbeat.runId ?? null,
	};
}

function formatDuration(ms: number): string {
	const totalSeconds = Math.max(0, Math.floor(ms / 1000));
	const hours = Math.floor(totalSeconds / 3600);
	const minutes = Math.floor((totalSeconds % 3600) / 60);
	const seconds = totalSeconds % 60;
	if (hours > 0) {
		return `${hours}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
	}
	return `${minutes}:${String(seconds).padStart(2, "0")}`;
}

function summarizeArgs(args: unknown): string {
	if (!args || typeof args !== "object") return "";
	const obj = args as Record<string, unknown>;
	const pickKey = ["file_path", "path", "command", "pattern", "query", "url"].find(
		(k) => typeof obj[k] === "string",
	);
	if (pickKey) return compactLine(String(obj[pickKey]), 90);
	try {
		return compactLine(JSON.stringify(obj), 90);
	} catch {
		return "";
	}
}

function extractAssistantText(content: unknown): string {
	if (typeof content === "string") return content;
	if (!Array.isArray(content)) return "";
	return content
		.filter((c) => c && typeof c === "object" && (c as { type?: string }).type === "text")
		.map((c) => (c as { text?: unknown }).text)
		.filter((text): text is string => typeof text === "string")
		.join("");
}

function stringFromUnknown(value: unknown): string | undefined {
	return typeof value === "string" && value.length > 0 ? value : undefined;
}

function compactLine(text: string, max: number): string {
	const collapsed = text.replace(/\s+/g, " ").trim();
	if (collapsed.length <= max) return collapsed;
	return `${collapsed.slice(0, max - 1)}…`;
}
