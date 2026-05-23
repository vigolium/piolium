import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	LONGSHOT_DEFAULT_LIMIT,
	LONGSHOT_MAX_FILE_BYTES,
	LONGSHOT_TARGETS_PATH,
	detectLanguages,
	enumerateTargets,
	expandExtensions,
	isGeneratedFile,
	isTestFile,
	mutateLongshotTargets,
	readLongshotTargets,
	scoreFile,
	updateTargetStatus,
	writeLongshotTargets,
} from "../extensions/piolium/longshot.ts";

let cwd: string;

beforeEach(() => {
	cwd = mkdtempSync(join(tmpdir(), "piolium-longshot-"));
});

afterEach(() => {
	rmSync(cwd, { recursive: true, force: true });
});

function write(path: string, content: string): void {
	const full = join(cwd, path);
	mkdirSync(join(full, ".."), { recursive: true });
	writeFileSync(full, content);
}

describe("longshot file classifiers", () => {
	it("flags Python and Go test files", () => {
		expect(isTestFile("pkg/foo/test_handler.py")).toBe(true);
		expect(isTestFile("pkg/foo/handler_test.py")).toBe(true);
		expect(isTestFile("internal/server/server_test.go")).toBe(true);
		expect(isTestFile("internal/server/server.go")).toBe(false);
	});

	it("flags JS/TS test and spec files", () => {
		expect(isTestFile("src/x.test.ts")).toBe(true);
		expect(isTestFile("src/x.spec.tsx")).toBe(true);
		expect(isTestFile("src/x.test.js")).toBe(true);
		expect(isTestFile("src/x.ts")).toBe(false);
	});

	it("flags Java/Kotlin/Scala test classes", () => {
		expect(isTestFile("src/main/java/FooTest.java")).toBe(true);
		expect(isTestFile("src/main/kotlin/FooSpec.kt")).toBe(true);
		expect(isTestFile("src/main/java/Foo.java")).toBe(false);
	});

	it("flags generated files", () => {
		expect(isGeneratedFile("api/v1/echo.pb.go")).toBe(true);
		expect(isGeneratedFile("api/v1/echo_pb2.py")).toBe(true);
		expect(isGeneratedFile("dist/bundle.min.js")).toBe(true);
		expect(isGeneratedFile("internal/foo_generated.go")).toBe(true);
		expect(isGeneratedFile("api/echo.go")).toBe(false);
	});
});

describe("expandExtensions / detectLanguages", () => {
	it("expands language names to file extensions", () => {
		const exts = expandExtensions(["Python", "Go"]);
		expect(exts.has(".py")).toBe(true);
		expect(exts.has(".go")).toBe(true);
		expect(exts.has(".ts")).toBe(false);
	});

	it("auto-detects dominant languages from file counts", () => {
		write("a.py", "print(1)");
		write("b.py", "print(2)");
		write("c.py", "print(3)");
		write("d.py", "print(4)");
		write("main.go", "package main");
		write("util.go", "package main");
		write("README.md", "hello");
		const langs = detectLanguages(cwd);
		expect(langs).toContain("Python");
		// Go is at 50% of Python's count -> above the 25% inclusion threshold.
		expect(langs).toContain("Go");
	});

	it("ignores skipped directories during detection", () => {
		write("node_modules/foo/index.js", "x");
		write("vendor/bar/baz.go", "package bar");
		write("real/main.py", "print(1)");
		const langs = detectLanguages(cwd);
		expect(langs).toEqual(["Python"]);
	});
});

describe("scoreFile", () => {
	it("rewards path segments associated with attack surface", () => {
		const baseline = scoreFile("pkg/foo/util.go", "package foo");
		const handler = scoreFile("internal/handlers/user.go", "package handlers");
		expect(handler).toBeGreaterThan(baseline);
	});

	it("rewards content with dangerous-looking tokens", () => {
		const inert = scoreFile("src/inert.py", "x = 1\n");
		const interesting = scoreFile(
			"src/interesting.py",
			"import subprocess\nsubprocess.run(cmd, shell=True)\n",
		);
		expect(interesting).toBeGreaterThan(inert);
	});

	it("returns zero for empty content with neutral path", () => {
		expect(scoreFile("pkg/foo/util.txt", "")).toBe(0);
	});
});

describe("enumerateTargets", () => {
	it("filters tests, generated files, and oversized files", () => {
		write("cmd/server/main.go", 'package main\nimport "net/http"\nhttp.HandleFunc("/x", h)\n');
		write("internal/server/server.go", "package server\nfunc h() {}\n");
		write("internal/server/server_test.go", "package server");
		write("api/v1/echo.pb.go", "// generated");
		// oversized
		write("internal/big.go", "x".repeat(LONGSHOT_MAX_FILE_BYTES + 10));
		const result = enumerateTargets({ cwd, languages: ["Go"], limit: 100 });

		const paths = result.targets.map((t) => t.path);
		expect(paths).toContain("cmd/server/main.go");
		expect(paths).toContain("internal/server/server.go");
		expect(paths).not.toContain("internal/server/server_test.go");
		expect(paths).not.toContain("api/v1/echo.pb.go");
		expect(paths).not.toContain("internal/big.go");
		expect(result.skipped_tests).toBeGreaterThanOrEqual(1);
		expect(result.skipped_generated).toBeGreaterThanOrEqual(1);
		expect(result.skipped_oversized).toBeGreaterThanOrEqual(1);
	});

	it("skips test directories entirely when includeTests is false", () => {
		write("src/handler.py", "def h(): pass");
		write("tests/test_handler.py", "def test_h(): pass");
		write("__tests__/setup.py", "x = 1");
		const result = enumerateTargets({ cwd, languages: ["Python"], limit: 100 });
		const paths = result.targets.map((t) => t.path);
		expect(paths).toContain("src/handler.py");
		expect(paths).not.toContain("tests/test_handler.py");
		expect(paths).not.toContain("__tests__/setup.py");
	});

	it("includes test files when includeTests is true", () => {
		write("src/handler.py", "def h(): pass");
		write("tests/test_handler.py", "def test_h(): pass");
		const result = enumerateTargets({
			cwd,
			languages: ["Python"],
			limit: 100,
			includeTests: true,
		});
		const paths = result.targets.map((t) => t.path);
		expect(paths).toContain("src/handler.py");
		expect(paths).toContain("tests/test_handler.py");
	});

	it("sorts by score descending and applies the limit", () => {
		// High-signal handler file
		write(
			"internal/handlers/user.go",
			'package handlers\nimport "os/exec"\nexec.Command(userInput).Run()\n',
		);
		// Low-signal pure data file
		write("pkg/types/user.go", "package types\ntype User struct {}\n");
		// Medium-signal middleware
		write(
			"internal/middleware/auth.go",
			'package middleware\nimport "crypto/sha1"\nh := sha1.New()\n',
		);

		const result = enumerateTargets({ cwd, languages: ["Go"], limit: 2 });
		expect(result.targets).toHaveLength(2);
		// Top score should be the handler
		expect(result.targets[0]?.path).toBe("internal/handlers/user.go");
		// Limit cuts off the lowest-score file
		expect(result.targets.map((t) => t.path)).not.toContain("pkg/types/user.go");
	});

	it("auto-detects languages when none provided", () => {
		write("src/main.py", "import os\nos.system('x')\n");
		write("src/util.py", "x = 1");
		write("README.md", "hello");
		const result = enumerateTargets({ cwd, limit: 100 });
		expect(result.languages).toContain("Python");
		expect(result.targets.every((t) => t.path.endsWith(".py"))).toBe(true);
	});

	it("uses default limit when none provided", () => {
		write("src/a.py", "x = 1");
		const result = enumerateTargets({ cwd, languages: ["Python"] });
		expect(result.limit).toBe(LONGSHOT_DEFAULT_LIMIT);
	});

	it("tags each target with stable sha8 derived from path", () => {
		write("src/foo.py", "x = 1");
		const a = enumerateTargets({ cwd, languages: ["Python"], limit: 10 });
		const b = enumerateTargets({ cwd, languages: ["Python"], limit: 10 });
		expect(a.targets[0]?.sha8).toBe(b.targets[0]?.sha8);
		expect(a.targets[0]?.sha8).toMatch(/^[0-9a-f]{8}$/);
	});
});

describe("targets sidecar I/O", () => {
	it("writes and reads back the targets file", () => {
		write("src/main.py", "import subprocess");
		const enumerated = enumerateTargets({ cwd, languages: ["Python"], limit: 10 });
		writeLongshotTargets(cwd, enumerated);
		const onDisk = readFileSync(join(cwd, LONGSHOT_TARGETS_PATH), "utf8");
		expect(onDisk).toContain('"path":');
		const parsed = readLongshotTargets(cwd);
		expect(parsed?.targets.map((t) => t.path)).toEqual(enumerated.targets.map((t) => t.path));
	});

	it("updates a single target's status atomically", async () => {
		write("src/a.py", "x = 1");
		write("src/b.py", "y = 2");
		const enumerated = enumerateTargets({ cwd, languages: ["Python"], limit: 10 });
		writeLongshotTargets(cwd, enumerated);
		const target = enumerated.targets[0];
		expect(target).toBeDefined();
		if (!target) return;

		await updateTargetStatus(cwd, target.path, {
			status: "in_progress",
			incrementAttempts: true,
		});
		await updateTargetStatus(cwd, target.path, {
			status: "complete",
			completed_at: "2026-05-01T00:00:00.000Z",
			draft_count: 2,
		});

		const reloaded = readLongshotTargets(cwd);
		const updated = reloaded?.targets.find((t) => t.path === target.path);
		expect(updated?.status).toBe("complete");
		expect(updated?.attempts).toBe(1);
		expect(updated?.draft_count).toBe(2);
		expect(updated?.completed_at).toBe("2026-05-01T00:00:00.000Z");

		// The other target is untouched.
		const other = reloaded?.targets.find((t) => t.path !== target.path);
		expect(other?.status).toBe("pending");
	});

	it("mutateLongshotTargets aborts the write when the transformer returns undefined", async () => {
		write("src/a.py", "x = 1");
		const enumerated = enumerateTargets({ cwd, languages: ["Python"], limit: 10 });
		writeLongshotTargets(cwd, enumerated);
		const before = readFileSync(join(cwd, LONGSHOT_TARGETS_PATH), "utf8");
		await mutateLongshotTargets(cwd, () => undefined);
		const after = readFileSync(join(cwd, LONGSHOT_TARGETS_PATH), "utf8");
		expect(after).toBe(before);
	});
});
