/**
 * Resolve directories that ship with the piolium package.
 *
 * The package layout is:
 *
 *   piolium/
 *   ├── extensions/piolium/<this-file>
 *   ├── agents/
 *   ├── skills/
 *   └── prompts/
 *
 * From any file under `extensions/piolium/`, `import.meta.dirname` resolves
 * to `<package>/extensions/piolium/`. The bundled resource roots sit two
 * levels up.
 *
 * We also expose user and project override directories so operators can
 * tweak agent prompts without forking the package. Project overrides are
 * opt-in (the runner gates them behind a setting) because a repo-controlled
 * agent file can instruct the model to run shell commands.
 */

import { existsSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";

const HERE = import.meta.dirname ?? process.cwd();
const PACKAGE_ROOT = resolve(HERE, "..", "..");

export function getPackageRoot(): string {
	return PACKAGE_ROOT;
}

export function getBundledAgentsDir(): string {
	return join(PACKAGE_ROOT, "agents");
}

export function getBundledSkillsDir(): string {
	return join(PACKAGE_ROOT, "skills");
}

/**
 * Agent discovery search paths in precedence order:
 *   1. project   <cwd>/.pi/piolium/agents/   (only if `allowProjectAgents`)
 *   2. user      ~/.pi/agent/piolium/agents/
 *   3. bundled   <package>/agents/
 *
 * Earlier paths win on collision so an operator can override individual
 * agents without copying the entire bundle.
 */
export function getAgentSearchPaths(cwd: string, allowProjectAgents: boolean): string[] {
	const paths: string[] = [];
	if (allowProjectAgents) paths.push(join(cwd, ".pi", "piolium", "agents"));
	paths.push(join(homedir(), ".pi", "agent", "piolium", "agents"));
	paths.push(getBundledAgentsDir());
	return dedupePaths(paths);
}

function dedupePaths(paths: string[]): string[] {
	const seen = new Set<string>();
	const out: string[] = [];
	for (const p of paths) {
		let key: string;
		try {
			key = realpathSync(p);
		} catch {
			key = resolve(p);
		}
		if (seen.has(key)) continue;
		seen.add(key);
		out.push(p);
	}
	return out;
}

/** Test helper — exposes the resolved layout for diagnostics. */
export function describeLayout(): { here: string; root: string; agents: string; skills: string } {
	return {
		here: HERE,
		root: PACKAGE_ROOT,
		agents: getBundledAgentsDir(),
		skills: getBundledSkillsDir(),
	};
}

// Helpful in case anyone wants to know whether the bundled tree shipped:
export function bundledAgentsExist(): boolean {
	return existsSync(getBundledAgentsDir());
}

export function bundledSkillsExist(): boolean {
	return existsSync(getBundledSkillsDir());
}

/** kept for symmetry with piolium's signature; may need real impl when packaged */
export function _internal_packageRoot_for_tests(): string {
	return dirname(getBundledAgentsDir());
}
