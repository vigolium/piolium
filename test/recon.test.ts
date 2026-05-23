import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { reconReportPath, runRecon } from "../extensions/piolium/recon.ts";

let cwd: string;

beforeEach(() => {
	cwd = mkdtempSync(join(tmpdir(), "piolium-recon-"));
});

afterEach(() => {
	rmSync(cwd, { recursive: true, force: true });
});

describe("runRecon", () => {
	it("produces a report for a tiny no-git directory", () => {
		mkdirSync(join(cwd, "src"));
		writeFileSync(join(cwd, "package.json"), JSON.stringify({ name: "x" }));
		writeFileSync(join(cwd, "src", "a.ts"), "console.log(1);\n");
		writeFileSync(join(cwd, "src", "b.py"), "print(1)\n");
		const result = runRecon(cwd);
		expect(result.hasGit).toBe(false);
		expect(result.historyAvailable).toBe(false);
		expect(result.totalFiles).toBe(3);
		expect(result.languages.TypeScript).toBe(1);
		expect(result.languages.Python).toBe(1);
		expect(result.manifests).toContain("package.json");
		const report = readFileSync(result.reportPath, "utf8");
		expect(report).toContain("# Lite Recon — Q0");
		expect(report).toContain("Not a git repository");
		expect(report).toContain("TypeScript");
	});

	it("ignores skipped directories", () => {
		mkdirSync(join(cwd, "node_modules", "pkg"), { recursive: true });
		writeFileSync(join(cwd, "node_modules", "pkg", "ignored.js"), "x");
		mkdirSync(join(cwd, "src"));
		writeFileSync(join(cwd, "src", "real.ts"), "x");
		const result = runRecon(cwd);
		expect(result.totalFiles).toBe(1);
		expect(result.languages.JavaScript).toBeUndefined();
	});

	it("writes the report under piolium/attack-surface/", () => {
		runRecon(cwd);
		expect(readFileSync(reconReportPath(cwd), "utf8")).toContain("Lite Recon");
	});
});
