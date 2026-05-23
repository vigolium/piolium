/**
 * In-process agent runner.
 *
 * Spawns a child Pi session via the SDK (`createAgentSession`) instead of
 * forking a `pi --mode json` subprocess. Rationale:
 *   - Auth, model registry, and resource discovery already live in the parent
 *     process; in-process spawn inherits them automatically.
 *   - Subagent transcripts stream as plain `AgentSessionEvent` objects, no
 *     line-oriented JSON parsing needed.
 *   - Cancellation is one `agent.abort()` call instead of POSIX signal soup.
 *
 * Each run gets its own directory under
 * `piolium/tmp/piolium/runs/<runId>/` containing:
 *   - prompt.md       — task text + injected runtime header (for replay/debugging)
 *   - transcript.jsonl — every AgentSessionEvent, one per line
 *   - result.md       — the child's final assistant text
 *   - error.txt       — present iff the run errored
 *
 * The runner does not enforce concurrency by itself — call sites schedule
 * runs through the `Scheduler` to honour the global burst cap.
 */

import { type WriteStream, createWriteStream } from "node:fs";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import type { ThinkingLevel } from "@earendil-works/pi-agent-core";
import type { ImageContent, Model, TextContent } from "@earendil-works/pi-ai";
import {
	type AgentSessionEvent,
	DefaultResourceLoader,
	type ModelRegistry,
	SessionManager,
	type ToolDefinition,
	createAgentSession,
	getAgentDir,
} from "@earendil-works/pi-coding-agent";
import type { AgentDefinition } from "./agents.ts";
import type { AuditMode } from "./audit-state.ts";
import { getBundledSkillsDir } from "./bundled-resources.ts";
import { ensureRunDir } from "./scheduler.ts";
import { WEB_TOOLS } from "./tools/web-tools.ts";

export interface RuntimeContext {
	/** Working directory the child should treat as the audited repository root. */
	cwd: string;
	mode: AuditMode;
	/** Phase identifier (Q0/L1/P5/V3/...) — used for the runtime header. */
	phase?: string;
	/**
	 * Filesystem paths the child is allowed to write. Sub-agents are told to
	 * stay within these; the orchestrator merges fragments afterwards.
	 */
	outputPaths?: string[];
	/** Free-form notes appended to the runtime header (e.g. "git unavailable"). */
	notes?: string[];
}

export interface RunAgentOptions {
	agent: AgentDefinition;
	/** The concrete task — becomes the first user message to the child. */
	task: string;
	/** Stable, per-task id used to name the transcript directory. */
	runId: string;
	runtime: RuntimeContext;
	/**
	 * Optional model override. When omitted the child boots with the
	 * settings-derived default, matching the parent.
	 */
	// biome-ignore lint/suspicious/noExplicitAny: pi-ai Model is generic over provider api
	model?: Model<any>;
	/**
	 * Optional parent registry. This preserves extension-registered providers
	 * and their request headers for child sessions without loading extensions
	 * inside the child agent.
	 */
	modelRegistry?: ModelRegistry;
	/**
	 * Thinking/reasoning level the child should use. Wire the parent's current
	 * level here so child phases reason at the same depth — without it the
	 * SDK falls back to "medium" (or "off"), regardless of how the parent
	 * was configured.
	 */
	thinkingLevel?: ThinkingLevel;
	/** External cancellation. Abort kills the child session. */
	signal?: AbortSignal;
	/** Forwarded copy of every child event — surface for UI integration. */
	onEvent?: (event: AgentSessionEvent) => void;
	/**
	 * When false (default), the child has no extensions loaded. Setting this
	 * is a footgun — extensions can re-register tools and recurse — so
	 * leave it off unless you know what you're doing.
	 */
	noExtensions?: boolean;
}

export type AgentRuntimeModel = Pick<RunAgentOptions, "model" | "modelRegistry" | "thinkingLevel">;

export interface RunAgentResult {
	/** The child's final assistant text (trimmed). Empty string if none was produced. */
	text: string;
	transcriptPath: string;
	resultPath: string;
	promptPath: string;
	durationMs: number;
	/** Last assistant `stopReason`, if any (e.g. "end_turn", "error"). */
	stopReason?: string;
	/** Populated when the child errored or aborted. */
	errorMessage?: string;
}

export class AgentRunError extends Error {
	constructor(
		message: string,
		public readonly result: RunAgentResult,
	) {
		super(message);
		this.name = "AgentRunError";
	}
}

const TRANSCRIPT_STRING_LIMIT = 8_000;

export function buildRuntimeHeader(runtime: RuntimeContext): string {
	const lines: string[] = ["# piolium Runtime", ""];
	lines.push(`- Target repository: ${runtime.cwd}`);
	lines.push("- Audit directory: piolium/");
	lines.push("- Audit state: piolium/audit-state.json");
	lines.push(`- Mode: ${runtime.mode}`);
	if (runtime.phase) lines.push(`- Phase: ${runtime.phase}`);
	if (runtime.outputPaths && runtime.outputPaths.length > 0) {
		lines.push(`- Assigned output paths: ${runtime.outputPaths.join(", ")}`);
		lines.push("- Do not write outside the assigned paths unless this prompt explicitly says to.");
	}
	lines.push("- Keep findings on disk; do not keep important state only in conversation memory.");
	lines.push(
		"- If blocked, write a short failure note to your assigned output path and exit cleanly.",
	);
	if (runtime.notes && runtime.notes.length > 0) {
		lines.push("");
		lines.push("Operator notes:");
		for (const note of runtime.notes) lines.push(`- ${note}`);
	}
	return lines.join("\n");
}

function truncateTranscriptString(value: string): string {
	if (value.length <= TRANSCRIPT_STRING_LIMIT) return value;
	return `${value.slice(0, TRANSCRIPT_STRING_LIMIT)}\n...[truncated ${value.length - TRANSCRIPT_STRING_LIMIT} chars]`;
}

function compactTranscriptValue(value: unknown, depth = 0): unknown {
	if (typeof value === "string") return truncateTranscriptString(value);
	if (value === null || typeof value !== "object") return value;
	if (depth > 8) return "[max depth]";
	if (Array.isArray(value)) return value.map((item) => compactTranscriptValue(item, depth + 1));

	const out: Record<string, unknown> = {};
	for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
		if (key === "thinkingSignature" || key === "encrypted_content" || key === "partial") continue;
		out[key] = compactTranscriptValue(child, depth + 1);
	}
	return out;
}

export function compactTranscriptEvent(event: AgentSessionEvent): unknown {
	if (event.type !== "message_update") return compactTranscriptValue(event);

	const updateEvent = event as AgentSessionEvent & {
		assistantMessageEvent?: Record<string, unknown>;
	};
	return {
		type: event.type,
		assistantMessageEvent: compactTranscriptValue(updateEvent.assistantMessageEvent ?? {}),
	};
}

function extractAssistantText(content: unknown): string {
	if (typeof content === "string") return content;
	if (!Array.isArray(content)) return "";
	return content
		.filter(
			(c): c is TextContent | ImageContent =>
				!!c && typeof c === "object" && (c as { type?: string }).type === "text",
		)
		.map((c) => (c as TextContent).text ?? "")
		.join("");
}

export async function runAgent(options: RunAgentOptions): Promise<RunAgentResult> {
	const start = Date.now();
	const runDir = ensureRunDir(options.runtime.cwd, options.runId);
	const transcriptPath = join(runDir, "transcript.jsonl");
	const resultPath = join(runDir, "result.md");
	const promptPath = join(runDir, "prompt.md");
	const errorPath = join(runDir, "error.txt");

	const header = buildRuntimeHeader(options.runtime);
	const composedSystemPrompt = `${header}\n\n${options.agent.systemPrompt}`;

	writeFileSync(
		promptPath,
		[
			`# Run ${options.runId}`,
			`Agent: ${options.agent.name}`,
			`Source: ${options.agent.sourcePath}`,
			"",
			"## Task",
			"",
			options.task,
			"",
			"## System prompt (header + agent body)",
			"",
			composedSystemPrompt,
		].join("\n"),
	);

	const transcript: WriteStream = createWriteStream(transcriptPath, { flags: "a" });
	const writeEvent = (event: AgentSessionEvent) => {
		try {
			transcript.write(`${JSON.stringify(compactTranscriptEvent(event))}\n`);
		} catch {
			// transcript loss is non-fatal; final result still surfaces via return value
		}
		options.onEvent?.(event);
	};

	const resourceLoader = new DefaultResourceLoader({
		cwd: options.runtime.cwd,
		agentDir: getAgentDir(),
		systemPrompt: composedSystemPrompt,
		additionalSkillPaths: [getBundledSkillsDir()],
		noExtensions: options.noExtensions ?? true,
		noSkills: false,
		noPromptTemplates: true,
		noThemes: true,
		noContextFiles: true,
	});
	await resourceLoader.reload();

	const childCustomTools: ToolDefinition[] = [...WEB_TOOLS];

	const allowedTools = options.agent.allowedTools;
	const { session } = await createAgentSession({
		cwd: options.runtime.cwd,
		agentDir: getAgentDir(),
		...(options.model ? { model: options.model } : {}),
		...(options.modelRegistry ? { modelRegistry: options.modelRegistry } : {}),
		...(options.thinkingLevel ? { thinkingLevel: options.thinkingLevel } : {}),
		tools: allowedTools,
		sessionManager: SessionManager.inMemory(),
		resourceLoader,
		customTools: childCustomTools,
		...(allowedTools.length === 0 ? { noTools: "all" as const } : {}),
	});

	let finalText = "";
	let stopReason: string | undefined;
	let errorMessage: string | undefined;

	const unsubscribe = session.subscribe((event) => {
		writeEvent(event);
		if (event.type === "message_end") {
			const message = event.message as {
				role?: string;
				content?: unknown;
				stopReason?: string;
				errorMessage?: string;
			};
			if (message.role !== "assistant") return;
			if (message.stopReason) stopReason = message.stopReason;
			if (message.errorMessage) errorMessage = message.errorMessage;
			const text = extractAssistantText(message.content);
			if (text) finalText = text;
		}
	});

	const abortListener = () => session.agent.abort();
	options.signal?.addEventListener("abort", abortListener, { once: true });

	let runError: unknown;
	try {
		await session.prompt(options.task);
		await session.agent.waitForIdle();
	} catch (err) {
		runError = err;
	} finally {
		options.signal?.removeEventListener("abort", abortListener);
		unsubscribe();
		session.dispose();
		await new Promise<void>((resolve) => transcript.end(() => resolve()));
	}

	if (!errorMessage && runError) {
		errorMessage = runError instanceof Error ? runError.message : String(runError);
	}
	if (!errorMessage && !finalText && stopReason === "error") {
		errorMessage = "Child session ended in error with no message.";
	}

	const trimmed = finalText.trim();
	if (trimmed) {
		writeFileSync(resultPath, `${trimmed}\n`);
	}
	if (errorMessage) {
		writeFileSync(errorPath, `${errorMessage}\n`);
	}

	const result: RunAgentResult = {
		text: trimmed,
		transcriptPath,
		resultPath,
		promptPath,
		durationMs: Date.now() - start,
		...(stopReason ? { stopReason } : {}),
		...(errorMessage ? { errorMessage } : {}),
	};

	if (errorMessage) {
		throw new AgentRunError(errorMessage, result);
	}
	return result;
}
