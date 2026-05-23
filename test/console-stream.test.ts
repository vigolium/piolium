import { describe, expect, it } from "vitest";
import {
	createPioliumConsoleStream,
	isPiStreamingOutputMode,
	isPioliumConsoleStreamEnabled,
} from "../extensions/piolium/console-stream.ts";

describe("piolium console stream", () => {
	it("detects pi streaming output mode", () => {
		expect(isPiStreamingOutputMode(["pi", "-p", "/piolium-deep", "--mode", "streaming"])).toBe(true);
		expect(isPiStreamingOutputMode(["pi", "--mode=streaming", "-p", "/piolium-deep"])).toBe(true);
		expect(isPiStreamingOutputMode(["pi", "-p", "/piolium-deep"])).toBe(false);
		expect(isPiStreamingOutputMode(["pi", "--mode", "json", "-p", "/piolium-deep"])).toBe(false);
	});

	it("allows the standalone launcher to force mirrored console output", () => {
		expect(isPioliumConsoleStreamEnabled(["pi", "-p", "/piolium-deep"], {})).toBe(false);
		expect(
			isPioliumConsoleStreamEnabled(["pi", "-p", "/piolium-deep"], {
				PIOLIUM_CONSOLE_STREAM: "1",
			}),
		).toBe(true);
		expect(
			isPioliumConsoleStreamEnabled(["pi", "--mode", "streaming"], {
				PIOLIUM_CONSOLE_STREAM: "0",
			}),
		).toBe(false);
	});

	it("writes mirrored lines when console streaming is active", () => {
		const written: string[] = [];
		const stream = createPioliumConsoleStream({
			argv: ["pi", "-p", "/piolium-deep", "--mode", "streaming"],
			env: {},
			write: (text) => written.push(text),
		});

		stream.writeLine("[P4] running");
		stream.writeBlock("Done", ["Status: complete"]);

		expect(written.join("")).toBe("[P4] running\n\n=== Done ===\nStatus: complete\n");

		const disabled = createPioliumConsoleStream({
			argv: ["pi", "-p", "/piolium-deep"],
			env: {},
			write: (text) => written.push(text),
		});
		disabled.writeLine("hidden");
		expect(written.join("")).not.toContain("hidden");
	});
});
