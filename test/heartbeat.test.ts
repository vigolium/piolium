import type { AgentSessionEvent } from "@earendil-works/pi-coding-agent";
import { describe, expect, test } from "vitest";
import {
	PHASE_HEARTBEAT_UI_COLOR,
	createPhaseHeartbeatTracker,
	formatPhaseHeartbeat,
	formatPhaseHeartbeatStatusLine,
	heartbeatStateFields,
	phaseHeartbeatColor,
} from "../extensions/piolium/heartbeat.ts";

describe("heartbeat", () => {
	test("formats an active phase heartbeat", () => {
		const text = formatPhaseHeartbeat(
			{
				phase: "P1",
				label: "P1 advisory",
				startedAtMs: 0,
				lastEventAtMs: 12_000,
				nowMs: 42_000,
				lastToolName: "bash",
				lastToolSummary: "git log --oneline",
			},
			{ quietMs: 90_000, stalledMs: 300_000 },
		);

		expect(text).toBe("P1 running 0:42 · last output 0:30 ago · last tool: bash git log --oneline");
	});

	test("formats the UI heartbeat row with a distinct prefix and blue theme token", () => {
		const heartbeat = {
			phase: "P1",
			label: "P1 advisory",
			startedAtMs: 0,
			lastEventAtMs: 12_000,
			nowMs: 42_000,
			lastToolName: "bash",
			lastToolSummary: "git log --oneline",
		};

		expect(PHASE_HEARTBEAT_UI_COLOR).toBe("mdLink");
		expect(formatPhaseHeartbeatStatusLine(heartbeat, { quietMs: 90_000, stalledMs: 300_000 })).toBe(
			"↳ health: P1 running 0:42 · last output 0:30 ago · last tool: bash git log --oneline",
		);
	});

	test("escalates quiet heartbeats", () => {
		const heartbeat = {
			phase: "P4",
			label: "P4 SAST",
			startedAtMs: 0,
			lastEventAtMs: 20_000,
			nowMs: 220_000,
		};

		expect(formatPhaseHeartbeat(heartbeat, { quietMs: 90_000, stalledMs: 300_000 })).toBe(
			"P4 running 3:40 · quiet for 3:20 · waiting for first event",
		);
		expect(
			formatPhaseHeartbeat({ ...heartbeat, nowMs: 360_000 }, { quietMs: 90_000, stalledMs: 300_000 }),
		).toBe("P4 may be stalled 6:00 · quiet for 5:40 · waiting for first event");
		expect(phaseHeartbeatColor(heartbeat, { quietMs: 90_000, stalledMs: 300_000 })).toBe("muted");
		expect(
			phaseHeartbeatColor({ ...heartbeat, nowMs: 360_000 }, { quietMs: 90_000, stalledMs: 300_000 }),
		).toBe("warning");
	});

	test("tracks tool events and serializes state fields", () => {
		const tracker = createPhaseHeartbeatTracker({
			phase: "P1",
			label: "P1 advisory",
			runId: "run-1",
			nowMs: 1_000,
		});

		tracker.recordEvent({
			type: "tool_execution_start",
			toolName: "bash",
			args: { command: "curl -s https://api.osv.dev/v1/query" },
		} as unknown as AgentSessionEvent);

		const snapshot = tracker.snapshot(5_000);
		expect(snapshot.lastToolName).toBe("bash");
		expect(snapshot.lastToolSummary).toBe("curl -s https://api.osv.dev/v1/query");
		expect(heartbeatStateFields(snapshot)).toMatchObject({
			heartbeat_at: "1970-01-01T00:00:05.000Z",
			last_tool: "bash",
			last_tool_summary: "curl -s https://api.osv.dev/v1/query",
			run_id: "run-1",
		});
	});
});
