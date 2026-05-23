import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	isValidAgentName,
	loadAgentsFromDirs,
	parseAgentFile,
	translateTools,
} from "../extensions/piolium/agents.ts";
import { getBundledAgentsDir } from "../extensions/piolium/bundled-resources.ts";

let dir: string;

beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "piolium-agents-"));
});

afterEach(() => {
	rmSync(dir, { recursive: true, force: true });
});

describe("translateTools", () => {
	it("maps Claude tool names to Pi names", () => {
		const { tools, dropped } = translateTools("Read, Glob, Grep, Bash, Agent, WebFetch");
		expect(tools).toEqual(["read", "find", "grep", "bash", "spawn_agent", "WebFetch"]);
		expect(dropped).toEqual([]);
	});

	it("drops SendMessage with no replacement", () => {
		const { tools, dropped } = translateTools("Read, SendMessage, Bash");
		expect(tools).toEqual(["read", "bash"]);
		expect(dropped).toEqual(["SendMessage"]);
	});

	it("preserves already-Pi-style names", () => {
		const { tools } = translateTools("read, write, bash");
		expect(tools).toEqual(["read", "write", "bash"]);
	});

	it("accepts arrays as well as strings", () => {
		const { tools } = translateTools(["Read", "Bash"]);
		expect(tools).toEqual(["read", "bash"]);
	});

	it("flags unknown tool names as dropped", () => {
		const { tools, dropped } = translateTools("Read, NotARealTool");
		expect(tools).toEqual(["read"]);
		expect(dropped).toEqual(["NotARealTool"]);
	});
});

describe("isValidAgentName", () => {
	it("accepts hyphenated lowercase names", () => {
		expect(isValidAgentName("static-analyzer")).toBe(true);
		expect(isValidAgentName("vigolium-recon-api")).toBe(true);
	});

	it("rejects invalid names", () => {
		expect(isValidAgentName("Static-Analyzer")).toBe(false);
		expect(isValidAgentName("static--analyzer")).toBe(false);
		expect(isValidAgentName("")).toBe(false);
		expect(isValidAgentName("-bad")).toBe(false);
	});
});

describe("parseAgentFile", () => {
	it("parses a well-formed manifest", () => {
		const file = join(dir, "static-analyzer.md");
		writeFileSync(
			file,
			[
				"---",
				"name: static-analyzer",
				"description: Phase 4 SAST orchestration",
				"tools: Glob, Grep, Read, Bash, Write, Edit, Agent",
				"model: sonnet",
				"skills:",
				"  - codeql",
				"  - semgrep",
				"---",
				"You are the static analyzer.",
			].join("\n"),
		);
		const { agent, diagnostics } = parseAgentFile(
			file,
			require("node:fs").readFileSync(file, "utf8"),
		);
		expect(diagnostics).toEqual([]);
		expect(agent?.name).toBe("static-analyzer");
		expect(agent?.allowedTools).toEqual([
			"find",
			"grep",
			"read",
			"bash",
			"write",
			"edit",
			"spawn_agent",
		]);
		expect(agent?.model).toBe("sonnet");
		expect(agent?.skills).toEqual(["codeql", "semgrep"]);
		expect(agent?.systemPrompt).toBe("You are the static analyzer.");
	});

	it("errors on missing description", () => {
		const file = join(dir, "no-desc.md");
		writeFileSync(file, "---\nname: no-desc\n---\nbody");
		const { agent, diagnostics } = parseAgentFile(
			file,
			require("node:fs").readFileSync(file, "utf8"),
		);
		expect(agent).toBeUndefined();
		expect(diagnostics.some((d) => d.message.includes("description"))).toBe(true);
	});

	it("errors on empty body", () => {
		const file = join(dir, "empty.md");
		writeFileSync(file, "---\nname: empty\ndescription: x\n---\n");
		const { agent, diagnostics } = parseAgentFile(
			file,
			require("node:fs").readFileSync(file, "utf8"),
		);
		expect(agent).toBeUndefined();
		expect(diagnostics.some((d) => d.message.includes("Body"))).toBe(true);
	});

	it("warns on dropped tools", () => {
		const file = join(dir, "with-dropped.md");
		writeFileSync(file, "---\ndescription: x\ntools: Read, SendMessage, NotATool\n---\nbody");
		const { agent, diagnostics } = parseAgentFile(
			file,
			require("node:fs").readFileSync(file, "utf8"),
		);
		expect(agent?.allowedTools).toEqual(["read"]);
		expect(diagnostics.some((d) => d.level === "warn" && d.message.includes("Dropped"))).toBe(true);
	});
});

describe("loadAgentsFromDirs", () => {
	it("loads multiple files; later dirs lose to earlier on collision", () => {
		const a = join(dir, "a");
		const b = join(dir, "b");
		mkdirSync(a);
		mkdirSync(b);
		writeFileSync(join(a, "x.md"), "---\ndescription: from-a\ntools: Read\n---\nA prompt");
		writeFileSync(join(b, "x.md"), "---\ndescription: from-b\ntools: Read\n---\nB prompt");
		writeFileSync(join(b, "y.md"), "---\ndescription: only-in-b\ntools: Read\n---\nY prompt");
		const result = loadAgentsFromDirs([a, b]);
		expect(result.agents.get("x")?.description).toBe("from-a");
		expect(result.agents.get("y")?.description).toBe("only-in-b");
		expect(result.diagnostics.some((d) => d.message.includes("Duplicate"))).toBe(true);
	});

	it("silently skips missing directories", () => {
		const result = loadAgentsFromDirs([join(dir, "does-not-exist")]);
		expect(result.agents.size).toBe(0);
		expect(result.diagnostics).toEqual([]);
	});
});

describe("loadAgentsFromDirs against the bundled directory", () => {
	it("loads the bundled agent corpus without errors", () => {
		const result = loadAgentsFromDirs([getBundledAgentsDir()]);
		expect(result.agents.size).toBeGreaterThanOrEqual(30);
		const errors = result.diagnostics.filter((d) => d.level === "error");
		expect(errors).toEqual([]);
		// Spot-check one agent we know should be there.
		const sa = result.agents.get("static-analyzer");
		expect(sa?.allowedTools).toContain("read");
		expect(sa?.allowedTools).toContain("bash");
		// chamber-synthesizer ships with `model: opus` from the harness merge.
		expect(result.agents.get("chamber-synthesizer")?.model).toBe("opus");
		// knowledge-base-builder has the security-threat-model skill.
		expect(result.agents.get("knowledge-base-builder")?.skills).toContain("security-threat-model");
	});
});
