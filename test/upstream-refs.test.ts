import { readFileSync, readdirSync, statSync } from "node:fs";
import { extname, join } from "node:path";
import { describe, expect, it } from "vitest";
import {
	getBundledAgentsDir,
	getBundledSkillsDir,
} from "../extensions/piolium/bundled-resources.ts";

/** File extensions whose contents are scanned as UTF-8 text. */
const TEXT_EXTENSIONS = new Set([
	".md",
	".py",
	".sh",
	".yaml",
	".yml",
	".json",
	".txt",
	".ql",
	".toml",
	".cfg",
]);

function isTextFile(path: string): boolean {
	return TEXT_EXTENSIONS.has(extname(path).toLowerCase());
}

function walkTextFiles(root: string): string[] {
	const out: string[] = [];
	for (const entry of readdirSync(root)) {
		const abs = join(root, entry);
		if (statSync(abs).isDirectory()) out.push(...walkTextFiles(abs));
		else if (isTextFile(abs)) out.push(abs);
	}
	return out;
}

describe("bundled agents and skills are free of upstream archon references", () => {
	for (const [label, dir] of [
		["agents", getBundledAgentsDir()],
		["skills", getBundledSkillsDir()],
	] as const) {
		it(`${label}/ contains no archon references`, () => {
			const offenders: string[] = [];
			for (const file of walkTextFiles(dir)) {
				const text = readFileSync(file, "utf8");
				if (/archon/i.test(text)) offenders.push(file);
			}
			expect(offenders).toEqual([]);
		});
	}
});
