import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { phasesFor } from "../extensions/piolium/modes.ts";
import {
	cleanupConfirmArtifacts,
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
