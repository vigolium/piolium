#!/usr/bin/env bun
/**
 * npm publish orchestrator for @vigolium/piolium.
 *
 * Piolium is a *source* Pi package — there is no compiled binary. Publishing
 * means shipping the runtime tree (the extension, sub-agent defs, skills,
 * prompts, themes) plus the `bin/piolium.mjs` launcher so both
 * `pi install @vigolium/piolium` and `npm i -g @vigolium/piolium` resolve.
 *
 * Flow per run: npm auth check → `bun install --ignore-scripts` (so preflight +
 * the vendored yaml refresh have deps) → preflight (typecheck + tests) → next
 * version by patch-bumping the registry's current latest → write it back to
 * package.json → stage a curated copy under build/npm/pkg with a publish-ready
 * manifest (no `private`, no `scripts`, no devDependencies) → dry-run validate
 * the tarball → publish (skipping if that version is already on the registry).
 *
 * The staged manifest drops the `scripts` block on purpose: the root has an
 * `install` lifecycle script (`bash scripts/local-install.sh`) that must never
 * run on a consumer's `npm install`. Staging also lets the committed
 * package.json keep its dev-only fields untouched.
 *
 * Env vars:
 *   PIOLIUM_VERSION             — pin the version to publish (overrides the bump)
 *   PIOLIUM_NPM_DRY_RUN=1       — stage + dry-run validate only; no registry writes
 *   PIOLIUM_NPM_SKIP_PREFLIGHT=1 — skip typecheck + tests
 *   PIOLIUM_NPM_SKIP_INSTALL=1  — skip `bun install` (deps already present)
 *   NPM_TOKEN                   — if set, a staged-dir .npmrc references it via
 *                                 `${NPM_TOKEN}` for auth (the secret is never
 *                                 written to disk; npm expands it at read time,
 *                                 and omits .npmrc from the published tarball)
 */
import { spawnSync } from "node:child_process";
import {
	copyFileSync,
	cpSync,
	existsSync,
	mkdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PKG_PATH = join(ROOT, "package.json");
const STAGE = join(ROOT, "build", "npm");
const PKG_NAME = "@vigolium/piolium";

const DRY_RUN = process.env.PIOLIUM_NPM_DRY_RUN === "1";
const SKIP_PREFLIGHT = process.env.PIOLIUM_NPM_SKIP_PREFLIGHT === "1";
const SKIP_INSTALL = process.env.PIOLIUM_NPM_SKIP_INSTALL === "1";
const PINNED_VERSION = process.env.PIOLIUM_VERSION;

/** The extension loads the yaml parser from this vendored bundle at runtime. */
const YAML_BUNDLE_REL = "extensions/piolium/_vendor/yaml.bundle.mjs";

// Copied verbatim into the staged package: everything the Pi extension loads
// at runtime, plus docs + legal. Tests, configs, lockfiles, and scripts are
// intentionally excluded.
const COPY_DIRS = ["bin", "extensions", "skills", "prompts", "themes", "agents", "docs"];
const COPY_FILES = ["README.md", "LICENSE"];
const PUBLISH_FILES = [...COPY_DIRS.map((d) => `${d}/`), ...COPY_FILES];

const PREFIX = "\x1b[36m[*]\x1b[0m";

function step(msg: string): void {
	console.log(`${PREFIX} ${msg}`);
}

function run(cmd: string, args: string[], opts: { cwd?: string; check?: boolean } = {}): number {
	const result = spawnSync(cmd, args, { cwd: opts.cwd ?? ROOT, stdio: "inherit" });
	if ((opts.check ?? true) && result.status !== 0) {
		throw new Error(`${cmd} ${args.join(" ")} failed (exit ${result.status})`);
	}
	return result.status ?? 0;
}

function npmAuthCheck(): void {
	const r = spawnSync("npm", ["whoami"], {
		cwd: ROOT,
		encoding: "utf8",
		stdio: ["ignore", "pipe", "pipe"],
	});
	if (r.status === 0) {
		step(`npm authenticated as ${(r.stdout ?? "").trim()}`);
		return;
	}
	if (process.env.NPM_TOKEN) {
		step("npm whoami failed but NPM_TOKEN is set — relying on staged-dir .npmrc");
		return;
	}
	const msg = "not authenticated to npm. Run `npm login`, or set NPM_TOKEN (an Automation token).";
	if (DRY_RUN) {
		step(`warning: ${msg}`);
		return;
	}
	throw new Error(msg);
}

function ensureDeps(): void {
	if (SKIP_INSTALL) {
		step("skip bun install (PIOLIUM_NPM_SKIP_INSTALL=1)");
		return;
	}
	// --ignore-scripts: this runs under `bun run npm-publish`, so the child
	// `bun install` inherits npm_command=run-script. Without this flag bun runs
	// the root `install` lifecycle hook (scripts/local-install.sh), whose guard
	// is fooled by that inherited value into doing a full release + local
	// install. We refresh the vendored bundle into the stage ourselves, so the
	// lifecycle is never needed here.
	step("installing dependencies (bun install --ignore-scripts)");
	run("bun", ["install", "--ignore-scripts"]);
}

function preflight(): void {
	if (SKIP_PREFLIGHT) {
		step("skip preflight (PIOLIUM_NPM_SKIP_PREFLIGHT=1)");
		return;
	}
	step("preflight: typecheck");
	run("bun", ["run", "typecheck"]);
	step("preflight: tests");
	run("bun", ["run", "test"]);
}

/** Highest version on the `latest` dist-tag, or undefined if the lookup fails. */
function registryLatest(): string | undefined {
	const r = spawnSync("npm", ["view", PKG_NAME, "version"], {
		cwd: ROOT,
		encoding: "utf8",
		stdio: ["ignore", "pipe", "ignore"],
	});
	if (r.status !== 0) return undefined;
	const v = (r.stdout ?? "").trim();
	return v.length > 0 ? v : undefined;
}

function readLocalVersion(): string {
	const pkg = JSON.parse(readFileSync(PKG_PATH, "utf8")) as { version?: string };
	return String(pkg.version ?? "0.0.0");
}

/** Patch-bump, preserving any prerelease suffix (0.0.3 → 0.0.4, 1.2.3-rc → 1.2.4-rc). */
function bumpPatch(version: string): string {
	const m = /^(\d+)\.(\d+)\.(\d+)(-.+)?$/.exec(version);
	if (!m || m[1] === undefined || m[2] === undefined || m[3] === undefined) {
		throw new Error(`cannot parse version "${version}" (expected MAJOR.MINOR.PATCH[-prerelease])`);
	}
	return `${m[1]}.${m[2]}.${Number(m[3]) + 1}${m[4] ?? ""}`;
}

function computeNextVersion(): string {
	if (PINNED_VERSION) {
		step(`using pinned PIOLIUM_VERSION=${PINNED_VERSION}`);
		return PINNED_VERSION;
	}
	const latest = registryLatest();
	const base = latest ?? readLocalVersion();
	if (latest) step(`registry latest ${PKG_NAME}@${latest}`);
	else step(`registry latest unavailable — bumping from local package.json (${base})`);
	const next = bumpPatch(base);
	step(`next version → ${next}`);
	return next;
}

/** Rewrite only the `"version":` line so the rest of the manifest is untouched. */
function writeVersion(next: string): void {
	if (DRY_RUN) {
		step("skip writing version — dry run");
		return;
	}
	const raw = readFileSync(PKG_PATH, "utf8");
	const updated = raw.replace(/("version"\s*:\s*")[^"]+(")/, `$1${next}$2`);
	if (updated === raw) throw new Error(`failed to rewrite "version" in ${PKG_PATH}`);
	writeFileSync(PKG_PATH, updated);
	step(`wrote version ${next} to package.json (not committed)`);
}

/**
 * Rebuild the vendored yaml bundle into the staged copy from the dev-time
 * `yaml` package so it stays in lockstep with package.json. Falls back to the
 * already-staged copy if `yaml` isn't installed.
 */
function refreshYamlBundle(stageDir: string): void {
	const entry = join(ROOT, "node_modules", "yaml", "dist", "index.js");
	const out = join(stageDir, YAML_BUNDLE_REL);
	if (!existsSync(entry)) {
		if (existsSync(out)) {
			step("yaml not installed — shipping the existing vendored bundle as-is");
			return;
		}
		throw new Error(`cannot refresh vendored yaml: ${entry} missing and no staged bundle at ${out}`);
	}
	step("refreshing vendored yaml bundle");
	run("bun", ["build", entry, "--outfile", out, "--target", "node", "--format", "esm", "--minify"]);
}

/**
 * Write a staged-dir .npmrc when NPM_TOKEN is set (CI/automation path). When it
 * isn't, npm falls back to ~/.npmrc — the normal local `npm login` flow.
 *
 * The file stores the literal `${NPM_TOKEN}` rather than the expanded value:
 * npm substitutes env vars at read time, so the secret never lands on disk.
 * cleanupStage() removes the staged tree (including this file) after the run.
 * npm also omits .npmrc from published tarballs regardless.
 */
function writeNpmrc(dir: string): void {
	if (!process.env.NPM_TOKEN) return;
	writeFileSync(
		join(dir, ".npmrc"),
		// Literal ${NPM_TOKEN} — npm expands it at read time, so no secret on disk.
		"registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n",
		{ mode: 0o600 },
	);
}

/** Remove the staged package tree, including any .npmrc holding auth config. */
function cleanupStage(): void {
	if (existsSync(STAGE)) rmSync(STAGE, { recursive: true, force: true });
}

/** Full package.json minus dev-only fields, with publish metadata added. */
function writeManifest(dir: string, version: string): void {
	const pkg = JSON.parse(readFileSync(PKG_PATH, "utf8")) as Record<string, unknown>;
	pkg.private = undefined;
	pkg.scripts = undefined;
	pkg.devDependencies = undefined;
	pkg.name = PKG_NAME;
	pkg.version = version;
	pkg.files = PUBLISH_FILES;
	pkg.publishConfig = { access: "public" };
	writeFileSync(join(dir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
}

function stage(version: string): string {
	cleanupStage();
	const dir = join(STAGE, "pkg");
	mkdirSync(dir, { recursive: true });

	for (const d of COPY_DIRS) {
		const src = join(ROOT, d);
		if (!existsSync(src)) throw new Error(`missing publishable dir: ${src}`);
		cpSync(src, join(dir, d), {
			recursive: true,
			filter: (s: string) => !s.endsWith(".DS_Store"),
		});
	}
	for (const f of COPY_FILES) {
		const src = join(ROOT, f);
		if (existsSync(src)) copyFileSync(src, join(dir, f));
	}

	refreshYamlBundle(dir);
	writeManifest(dir, version);
	writeNpmrc(dir);
	step(`staged ${PKG_NAME}@${version} under ${dir}`);
	return dir;
}

/** True if <PKG_NAME>@<version> already exists on the registry. */
function isPublished(version: string): boolean {
	const r = spawnSync("npm", ["view", `${PKG_NAME}@${version}`, "version"], {
		cwd: ROOT,
		encoding: "utf8",
		stdio: ["ignore", "pipe", "ignore"],
	});
	return r.status === 0 && (r.stdout ?? "").trim() === version;
}

function publishOrSkip(dir: string, version: string): void {
	if (isPublished(version)) {
		step(`skip ${PKG_NAME}@${version} — already on registry`);
		return;
	}
	step(`publishing ${PKG_NAME}@${version}`);
	run("npm", ["publish", "--access", "public"], { cwd: dir });
}

function main(): void {
	step(`npm publish ${PKG_NAME}${DRY_RUN ? "  [DRY RUN]" : ""}`);

	npmAuthCheck();
	ensureDeps();
	preflight();

	const version = computeNextVersion();
	writeVersion(version);

	try {
		const dir = stage(version);

		step("validating tarball (npm publish --dry-run)");
		run("npm", ["publish", "--dry-run", "--access", "public"], { cwd: dir });

		if (DRY_RUN) {
			step("DRY RUN — staged + validated only; no registry writes performed");
			console.log("");
			console.log(`  staged under:  ${dir}`);
			console.log(`  would publish: ${PKG_NAME}@${version}`);
			return;
		}

		publishOrSkip(dir, version);

		step("published successfully!");
		console.log("");
		console.log(`  npm install -g ${PKG_NAME}`);
		console.log(`  pi install ${PKG_NAME}`);
	} finally {
		// Always clear the staged tree (vendored bundle + auth .npmrc) after a
		// real run, including on error. Preserved only on a dry run for
		// inspection — its .npmrc holds the literal ${NPM_TOKEN}, never the
		// expanded secret.
		if (!DRY_RUN) cleanupStage();
	}
}

main();
