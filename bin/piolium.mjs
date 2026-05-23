#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import {
	chmodSync,
	copyFileSync,
	existsSync,
	mkdirSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const DEFAULT_PROVIDER = "openai-codex";
const DEFAULT_MODEL = "gpt-5.5";
const DEFAULT_THINKING_LEVEL = "high";
const DEFAULT_THEME = "piolium-srcery";

const PACKAGE_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function main(argv) {
	const paths = resolvePaths();
	const [command, ...rest] = argv;

	if (command === "--help" || command === "-h") {
		printHelp();
		return 0;
	}
	if (command === "doctor") {
		bootstrapConfig(paths, { syncEmptyAuth: true });
		return runDoctor(paths);
	}
	if (command === "auth") {
		bootstrapConfig(paths);
		return runAuthCommand(paths, rest);
	}
	if (command === "reset-auth") {
		bootstrapConfig(paths, { createAuth: false });
		return resetAuth(paths);
	}
	if (command === "login") {
		bootstrapConfig(paths);
		return runPi(["/login", ...rest], paths);
	}

	bootstrapConfig(paths, { syncEmptyAuth: true });
	return runPi(command === "--" ? rest : argv, paths);
}

function resolvePaths() {
	const homeDir = expandHome(process.env.PIOLIUM_HOME || join(homedir(), ".piolium"));
	const packageDir = resolve(expandHome(process.env.PIOLIUM_PACKAGE_DIR || PACKAGE_DIR));
	const agentDir = resolve(expandHome(process.env.PIOLIUM_AGENT_DIR || join(homeDir, "agent")));
	const sessionDir = resolve(
		expandHome(process.env.PIOLIUM_SESSION_DIR || join(agentDir, "session")),
	);
	const sourcePiAgentDir = resolve(
		expandHome(process.env.PIOLIUM_SOURCE_PI_AGENT_DIR || join(homedir(), ".pi", "agent")),
	);
	return {
		homeDir,
		packageDir,
		agentDir,
		sessionDir,
		settingsPath: join(agentDir, "settings.json"),
		authPath: join(agentDir, "auth.json"),
		sourcePiSettingsPath: join(sourcePiAgentDir, "settings.json"),
		sourcePiAuthPath: join(sourcePiAgentDir, "auth.json"),
	};
}

function expandHome(value) {
	if (value === "~") return homedir();
	if (value.startsWith("~/")) return join(homedir(), value.slice(2));
	return value;
}

function bootstrapConfig(paths, options = {}) {
	const { createAuth = true, syncEmptyAuth = false } = options;
	mkdirSync(paths.agentDir, { recursive: true });
	mkdirSync(paths.sessionDir, { recursive: true });
	ensureSettings(paths);
	if (createAuth) ensureEmptyAuth(paths);
	if (syncEmptyAuth) syncEmptyAuthFromPi(paths);
}

function ensureSettings(paths) {
	const current = readJsonObject(paths.settingsPath, { strict: true }) || {};
	const source = readJsonObject(paths.sourcePiSettingsPath) || {};
	const next = { ...current };
	const packages = Array.isArray(next.packages) ? [...next.packages] : [];
	if (
		!packages.some((entry) =>
			packageEntryMatches(entry, paths.packageDir, dirname(paths.settingsPath)),
		)
	) {
		packages.unshift(paths.packageDir);
		next.packages = packages;
	}
	for (const key of ["defaultProvider", "defaultModel", "defaultThinkingLevel", "theme"]) {
		if (next[key] !== undefined) continue;
		if (source[key] !== undefined) next[key] = source[key];
	}
	next.defaultProvider ??= DEFAULT_PROVIDER;
	next.defaultModel ??= DEFAULT_MODEL;
	next.defaultThinkingLevel ??= DEFAULT_THINKING_LEVEL;
	next.theme ??= DEFAULT_THEME;
	next.sessionDir ??= paths.sessionDir;
	writeJsonObjectIfChanged(paths.settingsPath, current, next, 0o600);
}

function packageEntryMatches(entry, packageDir, baseDir) {
	const value = typeof entry === "string" ? entry : entry?.source;
	if (typeof value !== "string") return false;
	const resolved = isAbsolute(expandHome(value))
		? resolve(expandHome(value))
		: resolve(baseDir, expandHome(value));
	return resolved === packageDir;
}

function ensureEmptyAuth(paths) {
	if (existsSync(paths.authPath)) return;
	writeFileSync(paths.authPath, "{}\n", "utf8");
	chmodIfPossible(paths.authPath, 0o600);
}

function syncEmptyAuthFromPi(paths) {
	if (!isEmptyAuthFile(paths.authPath) || !existsSync(paths.sourcePiAuthPath)) return;
	if (isEmptyAuthFile(paths.sourcePiAuthPath)) return;
	console.warn(
		`[piolium] warning: ${paths.authPath} is empty; syncing auth from ${paths.sourcePiAuthPath}.`,
	);
	copyAuthFile(paths.sourcePiAuthPath, paths.authPath, "Synced");
}

function runAuthCommand(paths, args) {
	const [command, ...rest] = args;
	if (command === "import") return importAuth(paths, rest);
	if (command === "sync") return syncAuth(paths, rest);
	if (command === "path") {
		console.log(paths.authPath);
		return 0;
	}
	console.error(
		"Usage: piolium auth sync | piolium auth import [--force] [--from <auth.json>] | piolium auth path",
	);
	return 2;
}

function importAuth(paths, args) {
	let sourcePath = paths.sourcePiAuthPath;
	let force = false;
	for (let i = 0; i < args.length; i++) {
		const arg = args[i];
		if (arg === "--force") {
			force = true;
		} else if (arg === "--from" && args[i + 1]) {
			sourcePath = resolve(expandHome(args[++i]));
		} else if (arg?.startsWith("--from=")) {
			sourcePath = resolve(expandHome(arg.slice("--from=".length)));
		} else {
			console.error(`Unknown auth import argument: ${arg}`);
			return 2;
		}
	}
	if (!existsSync(sourcePath)) {
		console.error(`No source auth file found at ${sourcePath}`);
		return 1;
	}
	const targetExists = existsSync(paths.authPath);
	if (targetExists && !force && !isEmptyAuthFile(paths.authPath)) {
		console.error(
			`${paths.authPath} already contains credentials. Re-run with --force to replace it.`,
		);
		return 1;
	}
	mkdirSync(dirname(paths.authPath), { recursive: true });
	copyFileSync(sourcePath, paths.authPath);
	chmodIfPossible(paths.authPath, 0o600);
	console.log(`Imported auth into ${paths.authPath}`);
	return 0;
}

function syncAuth(paths, args) {
	if (args.length > 0) {
		console.error("Usage: piolium auth sync");
		return 2;
	}
	return copyAuthFile(paths.sourcePiAuthPath, paths.authPath, "Synced");
}

function copyAuthFile(sourcePath, targetPath, verb) {
	if (!existsSync(sourcePath)) {
		console.error(`No source auth file found at ${sourcePath}`);
		return 1;
	}
	if (resolve(sourcePath) === resolve(targetPath)) {
		console.log(`Auth already points at ${targetPath}`);
		return 0;
	}
	mkdirSync(dirname(targetPath), { recursive: true });
	copyFileSync(sourcePath, targetPath);
	chmodIfPossible(targetPath, 0o600);
	console.log(`${verb} auth from ${sourcePath} into ${targetPath}`);
	return 0;
}

function resetAuth(paths) {
	if (existsSync(paths.authPath)) rmSync(paths.authPath, { force: true });
	ensureEmptyAuth(paths);
	console.log(`Reset auth at ${paths.authPath}`);
	return 0;
}

function runDoctor(paths) {
	const piPath = resolveCommand(process.env.PIOLIUM_PI_BIN || "pi");
	const authState = authStatus(paths.authPath);
	const settings = readJsonObject(paths.settingsPath);
	const hasPackage =
		!!settings &&
		Array.isArray(settings.packages) &&
		settings.packages.some((entry) =>
			packageEntryMatches(entry, paths.packageDir, dirname(paths.settingsPath)),
		);

	console.log("Piolium standalone");
	console.log(`  home:       ${paths.homeDir}`);
	console.log(
		`  package:    ${existsSync(paths.packageDir) ? "ok" : "missing"} ${paths.packageDir}`,
	);
	console.log(`  agent:      ${paths.agentDir}`);
	console.log(`  sessions:   ${paths.sessionDir}`);
	console.log(`  settings:   ${hasPackage ? "ok" : "missing package entry"} ${paths.settingsPath}`);
	console.log(`  auth:       ${authState} ${paths.authPath}`);
	console.log(`  pi:         ${piPath || "not found"}`);
	if (!piPath) return 1;
	return existsSync(paths.packageDir) && hasPackage ? 0 : 1;
}

function runPi(args, paths) {
	const piCommand = process.env.PIOLIUM_PI_BIN || "pi";
	const finalArgs = hasSessionDirArg(args) ? args : ["--session-dir", paths.sessionDir, ...args];
	const consoleStream = defaultConsoleStreamEnv(finalArgs);
	const result = spawnSync(piCommand, finalArgs, {
		stdio: "inherit",
		env: {
			...process.env,
			PI_CODING_AGENT_DIR: paths.agentDir,
			...(consoleStream === undefined ? {} : { PIOLIUM_CONSOLE_STREAM: consoleStream }),
		},
	});
	if (result.error) {
		console.error(`Failed to run ${piCommand}: ${result.error.message}`);
		return 1;
	}
	return result.status ?? 1;
}

function defaultConsoleStreamEnv(args) {
	if (process.env.PIOLIUM_CONSOLE_STREAM !== undefined) return process.env.PIOLIUM_CONSOLE_STREAM;
	return hasPioliumPrompt(args) ? "1" : undefined;
}

function hasPioliumPrompt(args) {
	for (let i = 0; i < args.length; i++) {
		const arg = args[i];
		if ((arg === "-p" || arg === "--prompt") && args[i + 1]?.includes("/piolium-")) return true;
		if ((arg.startsWith("-p=") || arg.startsWith("--prompt=")) && arg.includes("/piolium-")) {
			return true;
		}
	}
	return false;
}

function hasSessionDirArg(args) {
	return args.some((arg) => arg === "--session-dir" || arg.startsWith("--session-dir="));
}

function readJsonObject(path, options = {}) {
	if (!existsSync(path)) return undefined;
	try {
		const parsed = JSON.parse(readFileSync(path, "utf8"));
		return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : undefined;
	} catch (error) {
		if (options.strict) {
			const message = error instanceof Error ? error.message : String(error);
			throw new Error(`Invalid JSON in ${path}: ${message}`);
		}
		return undefined;
	}
}

function writeJsonObjectIfChanged(path, before, after, mode) {
	const beforeText = JSON.stringify(before, null, 2);
	const afterText = `${JSON.stringify(after, null, 2)}\n`;
	if (existsSync(path) && `${beforeText}\n` === afterText) return;
	mkdirSync(dirname(path), { recursive: true });
	writeFileSync(path, afterText, "utf8");
	chmodIfPossible(path, mode);
}

function isEmptyAuthFile(path) {
	try {
		const text = readFileSync(path, "utf8").trim();
		return text === "" || text === "{}";
	} catch {
		return true;
	}
}

function authStatus(path) {
	if (!existsSync(path)) return "missing";
	if (isEmptyAuthFile(path)) return "empty";
	try {
		const size = statSync(path).size;
		return size > 0 ? "configured" : "empty";
	} catch {
		return "unknown";
	}
}

function chmodIfPossible(path, mode) {
	try {
		chmodSync(path, mode);
	} catch {
		// Best effort only. Some filesystems ignore POSIX modes.
	}
}

function resolveCommand(command) {
	if (command.includes("/") && existsSync(command)) return command;
	const result = spawnSync("sh", ["-c", `command -v "$1"`, "sh", command], {
		encoding: "utf8",
	});
	return result.status === 0 ? result.stdout.trim() : undefined;
}

function printHelp() {
	console.log(`piolium - isolated Pi launcher for Piolium

Usage:
  piolium [pi args...]
  piolium login
  piolium doctor
  piolium auth sync
  piolium auth import [--force] [--from <auth.json>]
  piolium auth path
  piolium reset-auth

Environment:
  PIOLIUM_HOME                 Default: ~/.piolium
  PIOLIUM_PACKAGE_DIR          Default: directory containing this package
  PIOLIUM_AGENT_DIR            Default: ~/.piolium/agent
  PIOLIUM_SESSION_DIR          Default: ~/.piolium/agent/session
  PIOLIUM_SOURCE_PI_AGENT_DIR  Default: ~/.pi/agent
  PIOLIUM_PI_BIN               Default: pi

Examples:
  piolium
  piolium -p "/piolium-balanced --fresh"
  piolium auth sync
  piolium auth import
`);
}

try {
	const exitCode = main(process.argv.slice(2));
	process.exit(exitCode);
} catch (error) {
	console.error(error instanceof Error ? error.message : String(error));
	process.exit(1);
}
