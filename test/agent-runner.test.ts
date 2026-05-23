import { describe, expect, it } from "vitest";
import { buildRuntimeHeader, compactTranscriptEvent } from "../extensions/piolium/agent-runner.ts";

describe("buildRuntimeHeader", () => {
	it("includes the audit cwd, mode, and phase when provided", () => {
		const header = buildRuntimeHeader({
			cwd: "/tmp/repo",
			mode: "deep",
			phase: "P5",
		});

		expect(header).toContain("- Target repository: /tmp/repo");
		expect(header).toContain("- Mode: deep");
		expect(header).toContain("- Phase: P5");
	});

	it("appends operator notes when given", () => {
		const header = buildRuntimeHeader({
			cwd: "/tmp/repo",
			mode: "lite",
			notes: ["git unavailable", "secrets pre-filtered"],
		});

		expect(header).toContain("Operator notes:");
		expect(header).toContain("- git unavailable");
		expect(header).toContain("- secrets pre-filtered");
	});

	it("drops bulky streaming partials from transcript update events", () => {
		const compacted = compactTranscriptEvent({
			type: "message_update",
			assistantMessageEvent: {
				type: "thinking_delta",
				delta: "hello",
				partial: {
					role: "assistant",
					content: [{ type: "thinking", thinkingSignature: "x".repeat(100) }],
				},
			},
			message: {
				role: "assistant",
				content: [{ type: "thinking", thinkingSignature: "y".repeat(100) }],
			},
		} as never);

		const json = JSON.stringify(compacted);
		expect(json).toContain("thinking_delta");
		expect(json).toContain("hello");
		expect(json).not.toContain("partial");
		expect(json).not.toContain("thinkingSignature");
		expect(json).not.toContain("yyyy");
	});
});
