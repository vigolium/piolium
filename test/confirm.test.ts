import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { phasesFor } from "../extensions/piolium/modes.ts";
import {
	buildConfirmTask,
	cleanupConfirmArtifacts,
	findingCandidates,
	pocKindForDir,
	redactSecrets,
	renameFalsePositiveFindings,
} from "../extensions/piolium/modes/confirm.ts";

let cwd: string;

beforeEach(() => {
	cwd = mkdtempSync(join(tmpdir(), "piolium-confirm-"));
});

afterEach(() => {
	rmSync(cwd, { recursive: true, force: true });
});

function writeFinding(name: string, report: string): string {
	const dir = join(cwd, "piolium", "findings", name);
	mkdirSync(dir, { recursive: true });
	writeFileSync(join(dir, "report.md"), report);
	return dir;
}

describe("renameFalsePositiveFindings", () => {
	it("prefixes explicit false-positive finding directories", () => {
		writeFinding("H1-bad-auth", "Title\n\nConfirm-Status: false-positive\n");
		writeFinding("M1-real-bug", "Title\n\nConfirm-Status: confirmed-live\n");

		const renames = renameFalsePositiveFindings(cwd);

		expect(renames).toEqual(["H1-bad-auth -> FP-H1-bad-auth"]);
		expect(existsSync(join(cwd, "piolium", "findings", "FP-H1-bad-auth"))).toBe(true);
		expect(
			readFileSync(join(cwd, "piolium", "confirm-workspace", "false-positive-renames.json"), "utf8"),
		).toContain("FP-H1-bad-auth");
	});

	it("does not rename generic mentions of false positives", () => {
		writeFinding("H1-uncertain", "This was checked for false positives.\nConfirm-Status: blocked\n");

		expect(renameFalsePositiveFindings(cwd)).toEqual([]);
	});

	it("is idempotent for already-prefixed directories", () => {
		writeFinding("FP-H1-bad-auth", "Confirm-Status: false-positive\n");

		expect(renameFalsePositiveFindings(cwd)).toEqual([]);
	});
});

describe("confirm cleanup", () => {
	it("registers cleanup as the final confirm phase", () => {
		expect(phasesFor("confirm")).toEqual(["V1", "V1.5", "V2", "V3", "V4", "V5", "V6", "V7"]);
	});

	it("redacts common secret forms from text", () => {
		const input = [
			"Authorization: Bearer sk-proj-abcdefghijklmnopqrstuvwxyz123456",
			"password = supersecretvalue",
			"url=https://user:pass@example.test/path?api_key=abcdefghi",
			"token: github_pat_1234567890abcdefghijklmnopqrstuvwxyz",
		].join("\n");

		const out = redactSecrets(input).text;

		expect(out).not.toContain("sk-proj-abcdefghijklmnopqrstuvwxyz123456");
		expect(out).not.toContain("supersecretvalue");
		expect(out).not.toContain("user:pass");
		expect(out).not.toContain("abcdefghi");
		expect(out).not.toContain("github_pat_1234567890abcdefghijklmnopqrstuvwxyz");
		expect(out).toContain("[REDACTED:bearer]");
	});

	it("redacts generated artifacts and normalizes finding evidence folders", () => {
		const finding = writeFinding(
			"H1-leaky-auth",
			[
				"# Leaky auth",
				"",
				"Confirm-Status: confirmed-live",
				"Authorization: Bearer sk-proj-abcdefghijklmnopqrstuvwxyz123456",
			].join("\n"),
		);
		writeFileSync(
			join(cwd, "piolium", "confirmation-report.md"),
			"Access key: AKIAIOSFODNN7EXAMPLE\n",
		);
		mkdirSync(join(finding, "evidence"), { recursive: true });
		writeFileSync(
			join(finding, "evidence", "confirmed.log"),
			"token: github_pat_1234567890abcdefghijklmnopqrstuvwxyz\n",
		);
		mkdirSync(join(cwd, "piolium", "confirm-workspace"), { recursive: true });
		writeFileSync(
			join(cwd, "piolium", "confirm-workspace", "env-connection.json"),
			'{"access_token":"supersecretvalue","base_url":"https://user:pass@example.test/"}\n',
		);

		const result = cleanupConfirmArtifacts(cwd);

		expect(result.redactedFiles.map((f) => f.path).sort()).toEqual([
			"piolium/confirm-workspace/env-connection.json",
			"piolium/confirmation-report.md",
			"piolium/findings/H1-leaky-auth/evidence/confirmed.log",
			"piolium/findings/H1-leaky-auth/report.md",
		]);
		expect(existsSync(join(cwd, "piolium", "confirm-workspace", "cleanup-summary.json"))).toBe(true);
		expect(existsSync(join(finding, "evidence"))).toBe(true);
		const report = readFileSync(join(finding, "report.md"), "utf8");
		const evidence = readFileSync(join(finding, "evidence", "confirmed.log"), "utf8");
		const workspace = readFileSync(
			join(cwd, "piolium", "confirm-workspace", "env-connection.json"),
			"utf8",
		);
		expect(report).not.toContain("sk-proj-abcdefghijklmnopqrstuvwxyz123456");
		expect(evidence).not.toContain("github_pat_1234567890abcdefghijklmnopqrstuvwxyz");
		expect(workspace).not.toContain("supersecretvalue");
		expect(workspace).not.toContain("user:pass");
	});
});

function writeFile(name: string, file: string, content: string): string {
	const dir = join(cwd, "piolium", "findings", name);
	mkdirSync(dir, { recursive: true });
	writeFileSync(join(dir, file), content);
	return dir;
}

// findingCandidates only counts report.md > 500 bytes as a usable report.
const USABLE_REPORT = `# Finding\n\n${"x".repeat(600)}\n`;

describe("findingCandidates", () => {
	it("includes dirs with a usable report.md", () => {
		writeFile("C1-sqli", "report.md", USABLE_REPORT);
		const candidates = findingCandidates(cwd);
		expect(candidates.map((c) => c.name)).toEqual(["C1-sqli"]);
		expect(candidates[0]?.hasReport).toBe(true);
		expect(candidates[0]?.hasDraft).toBe(false);
	});

	it("includes draft-only dirs as repair candidates", () => {
		writeFile("H1-idor", "draft.md", "draft body");
		const candidates = findingCandidates(cwd);
		expect(candidates.map((c) => c.name)).toEqual(["H1-idor"]);
		expect(candidates[0]?.hasReport).toBe(false);
		expect(candidates[0]?.hasDraft).toBe(true);
	});

	it("treats a truncated report.md as needing repair when a draft exists", () => {
		const dir = writeFile("M1-xss", "report.md", "too short");
		writeFileSync(join(dir, "draft.md"), "draft body");
		const candidate = findingCandidates(cwd)[0];
		expect(candidate?.hasReport).toBe(false);
		expect(candidate?.hasDraft).toBe(true);
	});

	it("excludes dirs with neither a report nor a draft", () => {
		writeFile("C2-empty", "notes.txt", "nothing actionable");
		expect(findingCandidates(cwd)).toEqual([]);
	});

	it("returns [] when there is no findings directory", () => {
		expect(findingCandidates(cwd)).toEqual([]);
	});
});

describe("pocKindForDir", () => {
	it("classifies a runnable poc script", () => {
		const dir = writeFile("C1-sqli", "poc.py", "print('x')");
		expect(pocKindForDir(dir)).toBe("runnable");
	});

	it("classifies an exploit script as runnable", () => {
		const dir = writeFile("C1-sqli", "exploit.sh", "echo x");
		expect(pocKindForDir(dir)).toBe("runnable");
	});

	it("classifies a theoretical note", () => {
		const dir = writeFile("H1-idor", "poc.theoretical.md", "chain");
		expect(pocKindForDir(dir)).toBe("theoretical");
	});

	it("prefers a runnable script over a theoretical note", () => {
		const dir = writeFile("H1-idor", "poc.theoretical.md", "chain");
		writeFileSync(join(dir, "poc.js"), "console.log('x')");
		expect(pocKindForDir(dir)).toBe("runnable");
	});

	it("returns none when no PoC artifact exists", () => {
		const dir = writeFile("M1-weak", "report.md", USABLE_REPORT);
		expect(pocKindForDir(dir)).toBe("none");
	});
});

describe("buildConfirmTask routing", () => {
	it("V1 inventories both report and draft sources and records poc_kind", () => {
		const task = buildConfirmTask("V1", undefined);
		expect(task).toContain("poc_kind");
		expect(task).toContain("draft.md");
		expect(task).toContain("repair-summary.json");
	});

	it("V4 leaves theoretical / no-poc findings for V5 instead of executing them", () => {
		const task = buildConfirmTask("V4", undefined);
		expect(task).toContain("poc_kind: runnable");
		expect(task).toContain("no-poc");
		expect(task).toContain("Do NOT attempt to execute a `poc.theoretical.md`");
	});

	it("V5 treats theoretical findings as first-class candidates", () => {
		const task = buildConfirmTask("V5", undefined);
		expect(task).toContain("Theoretical findings");
		expect(task).toContain("first-class");
	});
});
