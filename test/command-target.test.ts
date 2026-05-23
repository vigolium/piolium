import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	parsePioliumCommandArgs,
	readOptionValue,
	readRepeatedOptionValues,
	tokenizeCommandArgs,
} from "../extensions/piolium/command-target.ts";

let tmpRoot: string;

beforeEach(() => {
	tmpRoot = mkdtempSync(join(tmpdir(), "piolium-command-"));
});

afterEach(() => {
	rmSync(tmpRoot, { recursive: true, force: true });
});

describe("piolium command target parsing", () => {
	it("consumes a leading target directory and leaves remaining args", () => {
		const target = join(tmpRoot, "repo");
		mkdirSync(target);

		const parsed = parsePioliumCommandArgs(`${target} --fresh P4`, tmpRoot);

		expect(parsed.error).toBeUndefined();
		expect(parsed.cwd).toBe(target);
		expect(parsed.targetCwd).toBe(target);
		expect(parsed.tokens).toEqual(["--fresh", "P4"]);
		expect(parsed.args).toBe("--fresh P4");
	});

	it("supports quoted relative directories", () => {
		const target = join(tmpRoot, "repo with spaces");
		mkdirSync(target);

		const parsed = parsePioliumCommandArgs('"repo with spaces" --fresh', tmpRoot);

		expect(parsed.cwd).toBe(target);
		expect(parsed.tokens).toEqual(["--fresh"]);
	});

	it("does not treat phase ids, urls, or flags as directories", () => {
		expect(parsePioliumCommandArgs("P5 --fresh", tmpRoot).tokens).toEqual(["P5", "--fresh"]);
		expect(parsePioliumCommandArgs("https://example.test --fresh", tmpRoot).tokens).toEqual([
			"https://example.test",
			"--fresh",
		]);
		expect(parsePioliumCommandArgs("--fresh", tmpRoot).tokens).toEqual(["--fresh"]);
	});

	it("returns an error for path-like missing directories", () => {
		const parsed = parsePioliumCommandArgs("./missing --fresh", tmpRoot);

		expect(parsed.error).toBe("./missing is not a readable directory.");
		expect(parsed.cwd).toBe(tmpRoot);
	});

	it("tokenizes quotes and reads option values", () => {
		const tokens = tokenizeCommandArgs('--since abc --dir "one two" --dir=three');

		expect(tokens).toEqual(["--since", "abc", "--dir", "one two", "--dir=three"]);
		expect(readOptionValue(tokens, "--since")).toBe("abc");
		expect(readRepeatedOptionValues(tokens, "--dir")).toEqual(["one two", "three"]);
	});

	it("uses a default target directory when no leading target is provided", () => {
		const target = join(tmpRoot, "repo");
		mkdirSync(target);

		const parsed = parsePioliumCommandArgs("--fresh", tmpRoot, { defaultTarget: target });

		expect(parsed.error).toBeUndefined();
		expect(parsed.cwd).toBe(target);
		expect(parsed.targetCwd).toBe(target);
		expect(parsed.tokens).toEqual(["--fresh"]);
	});

	it("lets a leading target directory override the default target", () => {
		const defaultTarget = join(tmpRoot, "default-repo");
		const explicitTarget = join(tmpRoot, "explicit-repo");
		mkdirSync(defaultTarget);
		mkdirSync(explicitTarget);

		const parsed = parsePioliumCommandArgs(`${explicitTarget} --fresh`, tmpRoot, {
			defaultTarget,
		});

		expect(parsed.error).toBeUndefined();
		expect(parsed.cwd).toBe(explicitTarget);
		expect(parsed.targetCwd).toBe(explicitTarget);
		expect(parsed.tokens).toEqual(["--fresh"]);
	});

	it("supports --plm-dir as a command-local target override", () => {
		const target = join(tmpRoot, "repo");
		mkdirSync(target);

		const parsed = parsePioliumCommandArgs("--plm-dir repo --fresh", tmpRoot);

		expect(parsed.error).toBeUndefined();
		expect(parsed.cwd).toBe(target);
		expect(parsed.targetCwd).toBe(target);
		expect(parsed.tokens).toEqual(["--plm-dir", "repo", "--fresh"]);
	});

	it("returns an error for an unreadable default target", () => {
		const parsed = parsePioliumCommandArgs("--fresh", tmpRoot, {
			defaultTarget: "missing",
		});

		expect(parsed.error).toBe("missing is not a readable directory.");
		expect(parsed.cwd).toBe(tmpRoot);
	});
});
