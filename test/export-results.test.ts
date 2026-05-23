import { describe, expect, it } from "vitest";
import { codeownerMatches, normalizeExportSeverity } from "../extensions/piolium/export-results.ts";

describe("codeownerMatches", () => {
	it("ignores blanks and comment lines", () => {
		expect(codeownerMatches("", "src/a.ts")).toBe(false);
		expect(codeownerMatches("   ", "src/a.ts")).toBe(false);
		expect(codeownerMatches("# owners go here", "src/a.ts")).toBe(false);
	});

	it("matches a bare filename glob against any path segment", () => {
		expect(codeownerMatches("*.ts", "src/app.ts")).toBe(true);
		expect(codeownerMatches("*.ts", "deep/nested/app.ts")).toBe(true);
		expect(codeownerMatches("*.ts", "src/app.py")).toBe(false);
	});

	it("treats a trailing slash as a directory prefix", () => {
		expect(codeownerMatches("/src/", "src/app.ts")).toBe(true);
		expect(codeownerMatches("src/", "src/deep/app.ts")).toBe(true);
		expect(codeownerMatches("/src/", "lib/app.ts")).toBe(false);
	});

	it("anchors patterns that start with a slash and does not cross directories on '*'", () => {
		expect(codeownerMatches("/docs/*.md", "docs/readme.md")).toBe(true);
		expect(codeownerMatches("/docs/*.md", "docs/sub/readme.md")).toBe(false);
		expect(codeownerMatches("/docs/*.md", "other/readme.md")).toBe(false);
	});

	it("expands '**' across directory boundaries", () => {
		expect(codeownerMatches("**/*.test.ts", "a/b/c.test.ts")).toBe(true);
		expect(codeownerMatches("apps/**/main.go", "apps/x/y/main.go")).toBe(true);
		expect(codeownerMatches("apps/**/main.go", "services/x/main.go")).toBe(false);
	});

	it("matches an un-anchored path pattern at root or any depth", () => {
		// has a slash, not anchored -> pat OR **/pat
		expect(codeownerMatches("src/app.ts", "src/app.ts")).toBe(true);
		expect(codeownerMatches("src/app.ts", "packages/x/src/app.ts")).toBe(true);
	});

	it("normalizes Windows path separators", () => {
		expect(codeownerMatches("/src/", "src\\app.ts")).toBe(true);
	});
});

describe("normalizeExportSeverity", () => {
	it("accepts the canonical levels case-insensitively", () => {
		expect(normalizeExportSeverity("CRITICAL")).toBe("critical");
		expect(normalizeExportSeverity(" High ")).toBe("high");
		expect(normalizeExportSeverity("info")).toBe("info");
	});

	it("rejects unknown levels and empty input", () => {
		expect(normalizeExportSeverity("bogus")).toBeUndefined();
		expect(normalizeExportSeverity(undefined)).toBeUndefined();
		expect(normalizeExportSeverity("")).toBeUndefined();
	});
});
