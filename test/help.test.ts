import { describe, expect, it } from "vitest";
import { PIOLIUM_STARTUP_HINT, buildPioliumHelpLines } from "../extensions/piolium/help.ts";

describe("piolium help", () => {
	it("includes the startup hint target command", () => {
		expect(PIOLIUM_STARTUP_HINT).toContain("/piolium-help");
		expect(PIOLIUM_STARTUP_HINT).toContain("/piolium-balanced");
	});

	it("documents commands, CLI flags, and examples", () => {
		const text = buildPioliumHelpLines().join("\n");

		expect(text).toContain("/piolium-balanced [path] [--fresh]");
		expect(text).toContain("/piolium-deep [path] [--fresh] [P1..P17]");
		expect(text).toContain("--plm-dir <path>");
		expect(text).toContain("--plm-phase-retries <N>");
		expect(text).toContain("--plm-lite-backoff <ms>");
		expect(text).toContain("--plm-longshot-langs <csv>");
		expect(text).toContain("--plm-longshot-include-tests <true|false>");
		expect(text).toContain('pi --plm-dir /path/to/repo -p "/piolium-balanced --fresh"');
	});
});
