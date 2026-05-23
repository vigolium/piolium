import { spawnSync } from "node:child_process";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

let tmpRoot: string;

beforeEach(() => {
	tmpRoot = mkdtempSync(join(tmpdir(), "piolium-standalone-"));
});

afterEach(() => {
	rmSync(tmpRoot, { recursive: true, force: true });
});

function runPiolium(args: string[], extraEnv: Record<string, string> = {}) {
	const env = {
		...process.env,
		PIOLIUM_HOME: join(tmpRoot, "home"),
		PIOLIUM_PACKAGE_DIR: resolve("."),
		PIOLIUM_SOURCE_PI_AGENT_DIR: join(tmpRoot, "source-agent"),
		...extraEnv,
	};
	return spawnSync(process.execPath, [resolve("bin/piolium.mjs"), ...args], {
		encoding: "utf8",
		env,
	});
}

function writeFakePi() {
	const path = join(tmpRoot, "fake-pi.mjs");
	writeFileSync(
		path,
		[
			"#!/usr/bin/env node",
			"console.log(JSON.stringify({",
			"\targv: process.argv.slice(2),",
			"\tconsoleStream: process.env.PIOLIUM_CONSOLE_STREAM,",
			"\tagentDir: process.env.PI_CODING_AGENT_DIR,",
			"}));",
			"",
		].join("\n"),
	);
	chmodSync(path, 0o755);
	return path;
}

describe("standalone piolium launcher", () => {
	it("bootstraps isolated settings and empty auth during doctor", () => {
		const sourceAgent = join(tmpRoot, "source-agent");
		mkdirSync(sourceAgent, { recursive: true });
		writeFileSync(
			join(sourceAgent, "settings.json"),
			JSON.stringify(
				{
					defaultProvider: "openai-codex",
					defaultModel: "gpt-5.5",
					defaultThinkingLevel: "high",
					theme: "piolium-srcery",
				},
				null,
				2,
			),
		);

		const result = runPiolium(["doctor"], { PIOLIUM_PI_BIN: process.execPath });

		expect(result.status).toBe(0);
		const settingsPath = join(tmpRoot, "home", "agent", "settings.json");
		const authPath = join(tmpRoot, "home", "agent", "auth.json");
		const settings = JSON.parse(readFileSync(settingsPath, "utf8"));
		expect(settings.packages).toContain(resolve("."));
		expect(settings.defaultProvider).toBe("openai-codex");
		expect(settings.defaultModel).toBe("gpt-5.5");
		expect(settings.defaultThinkingLevel).toBe("high");
		expect(settings.theme).toBe("piolium-srcery");
		expect(settings.sessionDir).toBe(join(tmpRoot, "home", "agent", "session"));
		expect(readFileSync(authPath, "utf8").trim()).toBe("{}");
	});

	it("imports auth only when explicitly requested", () => {
		const sourceAgent = join(tmpRoot, "source-agent");
		mkdirSync(sourceAgent, { recursive: true });

		const beforeImport = runPiolium(["doctor"], { PIOLIUM_PI_BIN: process.execPath });
		expect(beforeImport.status).toBe(0);
		const authPath = join(tmpRoot, "home", "agent", "auth.json");
		expect(readFileSync(authPath, "utf8").trim()).toBe("{}");
		writeFileSync(join(sourceAgent, "auth.json"), '{"demo":{"type":"api_key","api_key":"test"}}\n');

		const imported = runPiolium(["auth", "import"], { PIOLIUM_PI_BIN: process.execPath });

		expect(imported.status).toBe(0);
		expect(readFileSync(authPath, "utf8")).toContain('"demo"');
		expect(existsSync(join(sourceAgent, "auth.json"))).toBe(true);
	});

	it("syncs auth from the normal Pi agent and overwrites isolated auth", () => {
		const sourceAgent = join(tmpRoot, "source-agent");
		mkdirSync(sourceAgent, { recursive: true });
		writeFileSync(join(sourceAgent, "auth.json"), '{"source":{"type":"api_key","api_key":"new"}}\n');

		const authPath = join(tmpRoot, "home", "agent", "auth.json");
		const bootstrapped = runPiolium(["doctor"], { PIOLIUM_PI_BIN: process.execPath });
		expect(bootstrapped.status).toBe(0);
		writeFileSync(authPath, '{"old":{"type":"api_key","api_key":"old"}}\n');

		const synced = runPiolium(["auth", "sync"], { PIOLIUM_PI_BIN: process.execPath });

		expect(synced.status).toBe(0);
		expect(synced.stdout).toContain("Synced auth from");
		expect(readFileSync(authPath, "utf8")).toContain('"source"');
		expect(readFileSync(authPath, "utf8")).not.toContain('"old"');
	});

	it("auto-syncs empty isolated auth from the normal Pi agent during doctor", () => {
		const sourceAgent = join(tmpRoot, "source-agent");
		mkdirSync(sourceAgent, { recursive: true });
		writeFileSync(join(sourceAgent, "auth.json"), '{"source":{"type":"api_key","api_key":"new"}}\n');

		const result = runPiolium(["doctor"], { PIOLIUM_PI_BIN: process.execPath });

		expect(result.status).toBe(0);
		expect(result.stderr).toContain("[piolium] warning:");
		const authPath = join(tmpRoot, "home", "agent", "auth.json");
		expect(readFileSync(authPath, "utf8")).toContain('"source"');
	});

	it("enables mirrored progress for one-shot piolium prompts", () => {
		const fakePi = writeFakePi();

		const result = runPiolium(["-p", "/piolium-balanced --fresh"], {
			PIOLIUM_PI_BIN: fakePi,
		});

		expect(result.status).toBe(0);
		const payload = JSON.parse(result.stdout);
		expect(payload.consoleStream).toBe("1");
		expect(payload.argv).toContain("-p");
		expect(payload.argv).toContain("/piolium-balanced --fresh");
		expect(payload.agentDir).toBe(join(tmpRoot, "home", "agent"));
	});

	it("respects an explicit console progress override", () => {
		const fakePi = writeFakePi();

		const result = runPiolium(["-p", "/piolium-balanced --fresh"], {
			PIOLIUM_PI_BIN: fakePi,
			PIOLIUM_CONSOLE_STREAM: "0",
		});

		expect(result.status).toBe(0);
		const payload = JSON.parse(result.stdout);
		expect(payload.consoleStream).toBe("0");
	});
});
