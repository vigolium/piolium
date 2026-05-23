import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CANDIDATE_JSONL_PATH, runCandidateScan } from "../extensions/piolium/candidate-scan.ts";

let cwd: string;
const originalFileRecordsEnv = process.env.PIOLIUM_FILE_RECORDS;

beforeEach(() => {
	cwd = mkdtempSync(join(tmpdir(), "piolium-candidate-scan-"));
	Reflect.deleteProperty(process.env, "PIOLIUM_FILE_RECORDS");
});

afterEach(() => {
	rmSync(cwd, { recursive: true, force: true });
	if (originalFileRecordsEnv === undefined) {
		Reflect.deleteProperty(process.env, "PIOLIUM_FILE_RECORDS");
	} else {
		process.env.PIOLIUM_FILE_RECORDS = originalFileRecordsEnv;
	}
});

function write(path: string, content: string): void {
	const full = join(cwd, path);
	mkdirSync(join(full, ".."), { recursive: true });
	writeFileSync(full, content);
}

describe("runCandidateScan", () => {
	it("flags hidden control channels in request header handling", () => {
		write(
			"src/middleware.ts",
			[
				"export function middleware(request) {",
				"  const forwarded = request.headers.get('x-forwarded-for');",
				"  const internal = request.headers.get('x-internal-admin');",
				"  return forwarded || internal;",
				"}",
				"",
			].join("\n"),
		);

		const result = runCandidateScan(cwd);
		expect(result.candidateCount).toBeGreaterThan(0);
		expect(result.fileRecordsWritten).toBe(false);
		expect(existsSync(result.fileRecordsDir)).toBe(false);

		const jsonl = readFileSync(join(cwd, CANDIDATE_JSONL_PATH), "utf8")
			.trim()
			.split("\n")
			.map((line) => JSON.parse(line));
		const hidden = jsonl.filter((candidate) => candidate.slug === "hidden-control-channel");
		expect(hidden.length).toBeGreaterThan(0);
		expect(hidden.some((candidate) => candidate.filePath === "src/middleware.ts")).toBe(true);
	});

	it("writes per-file records only when explicitly enabled", () => {
		process.env.PIOLIUM_FILE_RECORDS = "true";
		write(
			"src/middleware.ts",
			[
				"export function middleware(request) {",
				"  return request.headers.get('x-forwarded-for');",
				"}",
				"",
			].join("\n"),
		);

		const result = runCandidateScan(cwd);

		expect(result.fileRecordsWritten).toBe(true);
		expect(existsSync(join(cwd, "piolium", "file-records", "src", "middleware.ts.json"))).toBe(true);
	});
});
