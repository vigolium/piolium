/**
 * Sub-agent loader.
 *
 * Reads Claude Code-style agent manifests (`agents/<name>.md` with YAML
 * frontmatter) and produces `AgentDefinition` records the runner can hand
 * straight to `createAgentSession`. Tool names from Claude's vocabulary
 * (Read, Bash, Glob, Agent, SendMessage…) are translated to Pi names at
 * load time so individual agent files stay faithful to their upstream
 * Claude Code form.
 *
 * Differences from the upstream loader:
 *   - We don't use the same diagnostic taxonomy; collisions just keep the
 *     first-seen entry (project > user > bundled) and the warning surfaces
 *     in `LoadResult.warnings`.
 *   - The frontmatter `skills` list is captured for reference only; the
 *     runner exposes the whole bundled skill set to every child session via
 *     the progressive skill loader rather than pre-loading a per-agent subset.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { basename, extname, join } from "node:path";
// Vendored bundle so a fresh `pi install <repo-path>` works without
// running `bun install` first (the npm-resolved "yaml" package would
// fail to load on a clone with no node_modules). Refresh with:
//   bun build node_modules/yaml/dist/index.js \
//     --outfile extensions/piolium/_vendor/yaml.bundle.mjs \
//     --target node --format esm --minify
import { parse as parseYaml } from "./_vendor/yaml.bundle.mjs";
import { getAgentSearchPaths } from "./bundled-resources.ts";

export interface AgentDefinition {
	/** Stable identifier — derived from filename, e.g. `static-analyzer`. */
	name: string;
	description: string;
	systemPrompt: string;
	/** Pi-style tool names (already translated from Claude vocabulary). */
	allowedTools: string[];
	/** Optional model alias — `opus`, `sonnet`, `haiku`, or a concrete id. */
	model?: string;
	/**
	 * Skills declared in the agent's frontmatter. Informational only — the
	 * runner makes all bundled skills discoverable to every child session
	 * through the progressive skill loader rather than pre-loading this subset.
	 */
	skills: string[];
	sourcePath: string;
}

export interface LoaderDiagnostic {
	level: "warn" | "error";
	path: string;
	message: string;
}

export interface LoadResult {
	agents: Map<string, AgentDefinition>;
	diagnostics: LoaderDiagnostic[];
}

const TOOL_TRANSLATION: Record<string, string | null> = {
	Read: "read",
	Write: "write",
	Edit: "edit",
	Bash: "bash",
	Grep: "grep",
	Glob: "find",
	LS: "ls",
	Ls: "ls",
	// Claude's `Agent` tool == "spawn another sub-agent". For piolium we
	// expose this only to a small set of orchestrator-style agents (KB
	// builder, static analyzer, etc.); the actual spawning is handled by the
	// extension runner, not by the child session itself. Translating to a
	// stable Pi tool name keeps the surface predictable.
	Agent: "spawn_agent",
	WebFetch: "WebFetch",
	WebSearch: "WebSearch",
	// SendMessage is how chamber agents coordinate upstream. Pi has no
	// inter-agent messaging primitive; the orchestrator replaces it with
	// shared-file rounds. Drop it from the child's allowlist.
	SendMessage: null,
};

export interface TranslateResult {
	tools: string[];
	dropped: string[];
}

export function translateTools(input: unknown): TranslateResult {
	const raw = normalizeToolList(input);
	const tools: string[] = [];
	const seen = new Set<string>();
	const dropped: string[] = [];
	for (const name of raw) {
		const trimmed = name.trim();
		if (!trimmed) continue;
		// Already a lowercase pi tool? Keep verbatim.
		if (/^[a-z][a-z0-9_]*$/.test(trimmed)) {
			if (!seen.has(trimmed)) {
				seen.add(trimmed);
				tools.push(trimmed);
			}
			continue;
		}
		const mapped = TOOL_TRANSLATION[trimmed];
		if (mapped === null || mapped === undefined) {
			dropped.push(trimmed);
			continue;
		}
		if (!seen.has(mapped)) {
			seen.add(mapped);
			tools.push(mapped);
		}
	}
	return { tools, dropped };
}

function normalizeToolList(input: unknown): string[] {
	if (Array.isArray(input)) return input.map((x) => String(x));
	if (typeof input !== "string") return [];
	return input.split(/[,\s]+/).filter(Boolean);
}

const AGENT_NAME_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

export function isValidAgentName(name: string): boolean {
	return name.length > 0 && name.length <= 64 && AGENT_NAME_RE.test(name) && !name.includes("--");
}

interface FrontmatterParsed {
	frontmatter: Record<string, unknown>;
	body: string;
}

export function splitFrontmatter(content: string): FrontmatterParsed {
	if (!content.startsWith("---")) return { frontmatter: {}, body: content };
	const rest = content.slice(3);
	const endIdx = rest.indexOf("\n---");
	if (endIdx < 0) return { frontmatter: {}, body: content };
	const yamlBlock = rest.slice(0, endIdx);
	const afterClose = rest.slice(endIdx + "\n---".length);
	const body = afterClose.replace(/^[\r\n]+/, "");
	const frontmatter = (parseYaml(yamlBlock) as Record<string, unknown> | null) ?? {};
	return { frontmatter, body };
}

export function parseAgentFile(
	filePath: string,
	content: string,
): { agent?: AgentDefinition; diagnostics: LoaderDiagnostic[] } {
	const diagnostics: LoaderDiagnostic[] = [];
	const name = basename(filePath, extname(filePath));

	if (!isValidAgentName(name)) {
		diagnostics.push({
			level: "error",
			path: filePath,
			message: `Invalid agent name "${name}" — must match /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/, no consecutive hyphens, ≤64 chars.`,
		});
		return { diagnostics };
	}

	const { frontmatter, body } = splitFrontmatter(content);
	const description =
		typeof frontmatter.description === "string" ? frontmatter.description.trim() : "";
	if (!description) {
		diagnostics.push({
			level: "error",
			path: filePath,
			message: "Frontmatter missing required `description` field.",
		});
		return { diagnostics };
	}
	if (!body.trim()) {
		diagnostics.push({ level: "error", path: filePath, message: "Body is empty." });
		return { diagnostics };
	}

	const { tools: allowedTools, dropped } = translateTools(frontmatter.tools);
	if (dropped.length > 0) {
		diagnostics.push({
			level: "warn",
			path: filePath,
			message: `Dropped unsupported tools: ${dropped.join(", ")}.`,
		});
	}

	const model =
		typeof frontmatter.model === "string" && frontmatter.model.trim()
			? frontmatter.model.trim()
			: undefined;

	const skills = normalizeSkillList(frontmatter.skills);

	return {
		agent: {
			name,
			description,
			systemPrompt: body.trim(),
			allowedTools,
			...(model ? { model } : {}),
			skills,
			sourcePath: filePath,
		},
		diagnostics,
	};
}

function normalizeSkillList(input: unknown): string[] {
	if (Array.isArray(input)) return input.map((s) => String(s).trim()).filter(Boolean);
	if (typeof input === "string") {
		return input
			.split(/[,\s]+/)
			.map((s) => s.trim())
			.filter(Boolean);
	}
	return [];
}

export function loadAgentsFromDirs(dirs: string[]): LoadResult {
	const agents = new Map<string, AgentDefinition>();
	const diagnostics: LoaderDiagnostic[] = [];

	for (const dir of dirs) {
		let entries: string[];
		try {
			const stat = statSync(dir);
			if (!stat.isDirectory()) continue;
			entries = readdirSync(dir);
		} catch {
			continue; // missing dir — fine, just skip
		}
		for (const entry of entries) {
			if (!entry.endsWith(".md")) continue;
			const filePath = join(dir, entry);
			let content: string;
			try {
				content = readFileSync(filePath, "utf8");
			} catch (err) {
				diagnostics.push({
					level: "error",
					path: filePath,
					message: `Failed to read: ${(err as Error).message}`,
				});
				continue;
			}
			const { agent, diagnostics: fileDiags } = parseAgentFile(filePath, content);
			diagnostics.push(...fileDiags);
			if (!agent) continue;
			if (agents.has(agent.name)) {
				diagnostics.push({
					level: "warn",
					path: filePath,
					message: `Duplicate agent name "${agent.name}" — keeping ${agents.get(agent.name)?.sourcePath}, ignoring this file.`,
				});
				continue;
			}
			agents.set(agent.name, agent);
		}
	}

	return { agents, diagnostics };
}

export interface LoadOptions {
	cwd: string;
	allowProjectAgents?: boolean;
}

export function loadAgents(options: LoadOptions): LoadResult {
	return loadAgentsFromDirs(getAgentSearchPaths(options.cwd, options.allowProjectAgents ?? false));
}
