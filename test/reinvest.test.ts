import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { phasesFor } from "../extensions/piolium/modes.ts";
import { REINVEST_REPORT } from "../extensions/piolium/modes/reinvest.ts";

let cwd: string;

beforeEach(() => {
	cwd = mkdtempSync(join(tmpdir(), "piolium-reinvest-"));
});

afterEach(() => {
	rmSync(cwd, { recursive: true, force: true });
});

function writeFinding(name: string, body: string): string {
	const dir = join(cwd, "piolium", "findings", name);
	mkdirSync(dir, { recursive: true });
	writeFileSync(join(dir, "report.md"), body);
	return dir;
}

describe("reinvest mode registry", () => {
	it("registers I1, I2, I3 phases in order", () => {
		expect(phasesFor("reinvest")).toEqual(["I1", "I2", "I3"]);
	});

	it("exports a stable reinvest-report.md path", () => {
		expect(REINVEST_REPORT).toBe("piolium/reinvest-report.md");
	});
});

describe("reinvest preflight", () => {
	it("rejects when no audit-state.json exists", async () => {
		const { runReinvestAudit } = await import("../extensions/piolium/modes/reinvest.ts");
		await expect(runReinvestAudit({ cwd })).rejects.toThrow(/prior audit/);
	});

	it("rejects when no CRIT/HIGH finding directories exist", async () => {
		const stateDir = join(cwd, "piolium");
		mkdirSync(stateDir, { recursive: true });
		writeFileSync(
			join(stateDir, "audit-state.json"),
			JSON.stringify({
				audits: [
					{
						audit_id: "2026-05-13T00:00:00.000Z",
						mode: "deep",
						started_at: "2026-05-13T00:00:00.000Z",
						completed_at: "2026-05-13T00:30:00.000Z",
						status: "complete",
						phases: {},
					},
				],
			}),
		);
		// Only MEDIUM findings — should be excluded.
		writeFinding("M1-some-issue", "Title");

		const { runReinvestAudit } = await import("../extensions/piolium/modes/reinvest.ts");
		await expect(runReinvestAudit({ cwd })).rejects.toThrow(/CRITICAL or HIGH/);
	});
});
