import { describe, expect, it } from "vitest";
import {
	extractStatusPhase,
	renderPhaseStatusList,
	renderPhaseStatusStrip,
} from "../extensions/piolium/phase-status-strip.ts";

const theme = {
	fg: (color: string, text: string) => `[${color}]${text}`,
};

describe("phase status strip", () => {
	it("extracts the current phase from status text", () => {
		expect(extractStatusPhase("● P4 SAST (1/3)", ["P1", "P4", "P5"])).toBe("P4");
		expect(extractStatusPhase("● piolium-deep retrying in 5s", ["P1", "P4"])).toBeUndefined();
	});

	it("renders colored tokens for each phase status", () => {
		const text = renderPhaseStatusStrip(
			["P1", "P2", "P3", "P4", "P5"],
			{
				P1: { status: "complete" },
				P2: { status: "failed" },
				P3: { status: "skipped" },
				P4: { status: "in_progress" },
			},
			"P5",
			theme,
		);

		expect(text).toBe("[success]✓P1 [error]✗P2 [warning]↷P3 [accent]●P4 [accent]●P5");
	});

	it("renders phase rows with labels", () => {
		const lines = renderPhaseStatusList(
			["P1", "P4", "P14"],
			{
				P1: { status: "complete" },
				P4: { status: "in_progress" },
			},
			"P14",
			theme,
		);

		expect(lines).toEqual([
			"[success]• ✓ P01. Intelligence & Dependency Risk",
			"[accent]• ● P02. Static Analysis & Triage",
			"[accent]• ● P03. Finding Report Drafting",
		]);
	});
});
