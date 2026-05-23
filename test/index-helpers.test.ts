import { describe, expect, it } from "vitest";
import {
	FLAG_ENV_MAPPINGS,
	normalizeExportFormat,
	parseSeverityList,
} from "../extensions/piolium/index.ts";

describe("normalizeExportFormat", () => {
	it("defaults missing/json to json", () => {
		expect(normalizeExportFormat(undefined)).toBe("json");
		expect(normalizeExportFormat("json")).toBe("json");
	});

	it("recognizes md-dir", () => {
		expect(normalizeExportFormat("md-dir")).toBe("md-dir");
	});

	it("returns undefined for unknown formats", () => {
		expect(normalizeExportFormat("xml")).toBeUndefined();
		expect(normalizeExportFormat("csv")).toBeUndefined();
	});
});

describe("parseSeverityList", () => {
	it("treats empty/undefined as 'no filter' ([])", () => {
		expect(parseSeverityList(undefined)).toEqual([]);
		expect(parseSeverityList("")).toEqual([]);
	});

	it("splits on commas and whitespace, lowercasing tokens", () => {
		expect(parseSeverityList("high,critical")).toEqual(["high", "critical"]);
		expect(parseSeverityList("HIGH critical")).toEqual(["high", "critical"]);
		expect(parseSeverityList("high, medium ,low")).toEqual(["high", "medium", "low"]);
	});

	it("returns undefined when any token is invalid", () => {
		expect(parseSeverityList("high,bogus")).toBeUndefined();
		expect(parseSeverityList("nope")).toBeUndefined();
	});
});

describe("FLAG_ENV_MAPPINGS", () => {
	it("mirrors each --plm-* flag to a PIOLIUM_* env var with a description", () => {
		expect(FLAG_ENV_MAPPINGS.length).toBeGreaterThan(0);
		for (const spec of FLAG_ENV_MAPPINGS) {
			expect(spec.flag.startsWith("plm-")).toBe(true);
			expect(spec.env.startsWith("PIOLIUM_")).toBe(true);
			expect(spec.description.length).toBeGreaterThan(0);
		}
	});

	it("uses unique flags and env vars (a duplicate would silently shadow another)", () => {
		const flags = FLAG_ENV_MAPPINGS.map((s) => s.flag);
		const envs = FLAG_ENV_MAPPINGS.map((s) => s.env);
		expect(new Set(flags).size).toBe(flags.length);
		expect(new Set(envs).size).toBe(envs.length);
	});
});
