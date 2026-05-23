/**
 * `anthropic-vertex` provider — Anthropic Claude served by Google Vertex AI.
 *
 * Pi-ai already ships a built-in `google-vertex` provider for Gemini models
 * (api: "google-vertex", driven by `@google/genai`). It does not cover Claude
 * on Vertex, so we register a separate provider here and let users pick:
 *
 *   pi --provider anthropic-vertex --model claude-opus-4-6@default
 *   pi --provider google-vertex    --model gemini-2.5-flash
 *
 * Credentials come from Google ADC (`gcloud auth application-default login`)
 * or `GOOGLE_APPLICATION_CREDENTIALS`. Project/region resolve in this order:
 *
 *   project: options.project → GOOGLE_CLOUD_PROJECT → GCLOUD_PROJECT
 *            → ANTHROPIC_VERTEX_PROJECT_ID → `gcloud config get-value project`
 *   region:  options.region  → GOOGLE_CLOUD_LOCATION → CLOUD_ML_REGION
 *            → "us-east5"
 *
 * Ported from https://github.com/basnijholt/pi-anthropic-vertex (MIT) so
 * piolium installs ship Vertex/Claude support without a second extension.
 */

import { execSync } from "node:child_process";
import type {
	Tool as AnthropicTool,
	MessageCreateParamsStreaming,
	MessageParam,
	RawMessageStreamEvent,
} from "@anthropic-ai/sdk/resources/messages.js";
import type { AnthropicVertex } from "@anthropic-ai/vertex-sdk";
import {
	type Api,
	type AssistantMessage,
	type CacheRetention,
	type Context,
	type ImageContent,
	type Message,
	type Model,
	type SimpleStreamOptions,
	type StopReason,
	type StreamFunction,
	type StreamOptions,
	type TextContent,
	type ThinkingBudgets,
	type ThinkingContent,
	type ThinkingLevel,
	type Tool,
	type ToolCall,
	type ToolResultMessage,
	calculateCost,
	createAssistantMessageEventStream,
} from "@earendil-works/pi-ai";
import type { ExtensionAPI, ProviderModelConfig } from "@earendil-works/pi-coding-agent";

const PROVIDER_NAME = "anthropic-vertex";
const API_NAME = "anthropic-vertex";
const DEFAULT_REGION = "us-east5";
const BASE_URL = "https://{region}-aiplatform.googleapis.com";

const MODELS: ProviderModelConfig[] = [
	{
		id: "claude-sonnet-4-5@20250929",
		name: "Claude Sonnet 4.5 (Vertex AI)",
		reasoning: true,
		input: ["text", "image"],
		cost: { input: 3, output: 15, cacheRead: 0.3, cacheWrite: 3.75 },
		contextWindow: 200000,
		maxTokens: 64000,
	},
	{
		id: "claude-opus-4-5@20251101",
		name: "Claude Opus 4.5 (Vertex AI)",
		reasoning: true,
		input: ["text", "image"],
		cost: { input: 15, output: 75, cacheRead: 0.5, cacheWrite: 6.25 },
		contextWindow: 200000,
		maxTokens: 32000,
	},
	{
		id: "claude-opus-4-6@default",
		name: "Claude Opus 4.6 (Vertex AI)",
		reasoning: true,
		input: ["text", "image"],
		cost: { input: 5, output: 25, cacheRead: 0.5, cacheWrite: 6.25 },
		contextWindow: 200000,
		maxTokens: 128000,
	},
	{
		id: "claude-haiku-4-5@20251001",
		name: "Claude Haiku 4.5 (Vertex AI)",
		reasoning: false,
		input: ["text", "image"],
		cost: { input: 1, output: 5, cacheRead: 0.1, cacheWrite: 1.25 },
		contextWindow: 200000,
		maxTokens: 8192,
	},
	{
		id: "claude-sonnet-4-20250514",
		name: "Claude Sonnet 4 (Vertex AI)",
		reasoning: true,
		input: ["text", "image"],
		cost: { input: 3, output: 15, cacheRead: 0.3, cacheWrite: 3.75 },
		contextWindow: 200000,
		maxTokens: 64000,
	},
	{
		id: "claude-3-5-sonnet-v2@20241022",
		name: "Claude 3.5 Sonnet v2 (Vertex AI)",
		reasoning: false,
		input: ["text", "image"],
		cost: { input: 3, output: 15, cacheRead: 0.3, cacheWrite: 3.75 },
		contextWindow: 200000,
		maxTokens: 8192,
	},
	{
		id: "claude-3-5-haiku@20241022",
		name: "Claude 3.5 Haiku (Vertex AI)",
		reasoning: false,
		input: ["text", "image"],
		cost: { input: 1, output: 5, cacheRead: 0.1, cacheWrite: 1.25 },
		contextWindow: 200000,
		maxTokens: 8192,
	},
	{
		id: "claude-3-opus@20240229",
		name: "Claude 3 Opus (Vertex AI)",
		reasoning: false,
		input: ["text", "image"],
		cost: { input: 15, output: 75, cacheRead: 1.5, cacheWrite: 18.75 },
		contextWindow: 200000,
		maxTokens: 4096,
	},
	{
		id: "claude-3-haiku@20240307",
		name: "Claude 3 Haiku (Vertex AI)",
		reasoning: false,
		input: ["text", "image"],
		cost: { input: 0.25, output: 1.25, cacheRead: 0.025, cacheWrite: 0.3125 },
		contextWindow: 200000,
		maxTokens: 4096,
	},
];

type AnthropicVertexEffort = "low" | "medium" | "high" | "max";

interface AnthropicVertexOptions extends StreamOptions {
	thinkingEnabled?: boolean;
	thinkingBudgetTokens?: number;
	effort?: AnthropicVertexEffort;
	interleavedThinking?: boolean;
	toolChoice?: "auto" | "any" | "none" | { type: "tool"; name: string };
	project?: string;
	region?: string;
}

type ToolCallStreamingBlock = ToolCall & {
	partialJson: string;
	index: number;
};

type AnthropicStreamingBlock =
	| (TextContent & { index: number })
	| (ThinkingContent & { index: number })
	| ToolCallStreamingBlock;

// MessageParam.content is `string | Array<ContentBlockParam>`; we only push to
// the array shape, so derive that variant once.
type MessageContentBlocks = Exclude<MessageParam["content"], string>;
type MessageContentBlock = MessageContentBlocks[number];

function sanitizeSurrogates(text: string): string {
	return text.replace(/[\uD800-\uDFFF]/g, "�");
}

function mergeHeaders(
	...sources: Array<Record<string, string> | undefined>
): Record<string, string> {
	const merged: Record<string, string> = {};
	for (const source of sources) {
		if (source) Object.assign(merged, source);
	}
	return merged;
}

function supportsAdaptiveThinking(modelId: string): boolean {
	return modelId.includes("opus-4-6") || modelId.includes("opus-4.6");
}

function mapThinkingLevelToEffort(level: SimpleStreamOptions["reasoning"]): AnthropicVertexEffort {
	switch (level) {
		case "minimal":
		case "low":
			return "low";
		case "medium":
			return "medium";
		case "high":
			return "high";
		case "xhigh":
			return "max";
		default:
			return "high";
	}
}

function mapStopReason(reason: string): StopReason {
	switch (reason) {
		case "end_turn":
		case "pause_turn":
		case "stop_sequence":
			return "stop";
		case "max_tokens":
			return "length";
		case "tool_use":
			return "toolUse";
		case "refusal":
		case "sensitive":
			return "error";
		default:
			return "error";
	}
}

function resolveCacheRetention(cacheRetention?: CacheRetention): CacheRetention {
	if (cacheRetention) return cacheRetention;
	if (typeof process !== "undefined" && process.env.PI_CACHE_RETENTION === "long") return "long";
	return "short";
}

function getCacheControl(
	baseUrl: string,
	cacheRetention?: CacheRetention,
): { retention: CacheRetention; cacheControl?: { type: "ephemeral"; ttl?: "1h" } } {
	const retention = resolveCacheRetention(cacheRetention);
	if (retention === "none") return { retention };
	const ttl = retention === "long" && baseUrl.includes("api.anthropic.com") ? "1h" : undefined;
	return {
		retention,
		cacheControl: { type: "ephemeral", ...(ttl ? { ttl } : {}) },
	};
}

function convertContentBlocks(content: Array<TextContent | ImageContent>) {
	const hasImages = content.some((c) => c.type === "image");
	if (!hasImages) {
		return sanitizeSurrogates(content.map((c) => (c.type === "text" ? c.text : "")).join("\n"));
	}

	const blocks = content.map((block) => {
		if (block.type === "text") {
			return {
				type: "text" as const,
				text: sanitizeSurrogates(block.text),
			};
		}
		return {
			type: "image" as const,
			source: {
				type: "base64" as const,
				media_type: block.mimeType as "image/jpeg" | "image/png" | "image/gif" | "image/webp",
				data: block.data,
			},
		};
	});

	if (!blocks.some((b) => b.type === "text")) {
		blocks.unshift({ type: "text", text: "(see attached image)" });
	}

	return blocks;
}

function convertMessages(
	messages: Message[],
	model: Model<Api>,
	cacheControl?: { type: "ephemeral"; ttl?: "1h" },
): MessageParam[] {
	const params: MessageParam[] = [];

	for (let i = 0; i < messages.length; i++) {
		const msg = messages[i];
		if (!msg) continue;

		if (msg.role === "user") {
			if (typeof msg.content === "string") {
				if (msg.content.trim().length > 0) {
					params.push({ role: "user", content: sanitizeSurrogates(msg.content) });
				}
			} else {
				const blocks = msg.content
					.map((item) => {
						if (item.type === "text") {
							return { type: "text" as const, text: sanitizeSurrogates(item.text) };
						}
						return {
							type: "image" as const,
							source: {
								type: "base64" as const,
								media_type: item.mimeType as "image/jpeg" | "image/png" | "image/gif" | "image/webp",
								data: item.data,
							},
						};
					})
					.filter((block) => {
						if (block.type === "text") return block.text.trim().length > 0;
						return model.input.includes("image");
					});

				if (blocks.length > 0) {
					params.push({ role: "user", content: blocks });
				}
			}
		} else if (msg.role === "assistant") {
			const blocks: MessageContentBlocks = [];
			for (const block of msg.content) {
				if (block.type === "text") {
					if (block.text.trim().length === 0) continue;
					blocks.push({ type: "text", text: sanitizeSurrogates(block.text) });
				} else if (block.type === "thinking") {
					if (block.thinking.trim().length === 0) continue;
					if (!block.thinkingSignature || block.thinkingSignature.trim().length === 0) {
						blocks.push({ type: "text", text: sanitizeSurrogates(block.thinking) });
					} else {
						blocks.push({
							type: "thinking",
							thinking: sanitizeSurrogates(block.thinking),
							signature: block.thinkingSignature,
						});
					}
				} else if (block.type === "toolCall") {
					blocks.push({
						type: "tool_use",
						id: block.id,
						name: block.name,
						input: block.arguments ?? {},
					});
				}
			}

			if (blocks.length > 0) {
				params.push({ role: "assistant", content: blocks });
			}
		} else if (msg.role === "toolResult") {
			const toolResults: Array<{
				type: "tool_result";
				tool_use_id: string;
				content: ReturnType<typeof convertContentBlocks>;
				is_error: boolean;
			}> = [];

			toolResults.push({
				type: "tool_result",
				tool_use_id: msg.toolCallId,
				content: convertContentBlocks(msg.content),
				is_error: msg.isError,
			});

			let j = i + 1;
			while (j < messages.length && messages[j]?.role === "toolResult") {
				const next = messages[j] as ToolResultMessage;
				toolResults.push({
					type: "tool_result",
					tool_use_id: next.toolCallId,
					content: convertContentBlocks(next.content),
					is_error: next.isError,
				});
				j++;
			}
			i = j - 1;
			params.push({ role: "user", content: toolResults });
		}
	}

	if (cacheControl && params.length > 0) {
		const last = params[params.length - 1];
		if (last && last.role === "user") {
			if (Array.isArray(last.content)) {
				const block = last.content[last.content.length - 1] as MessageContentBlock | undefined;
				if (
					block &&
					(block.type === "text" || block.type === "image" || block.type === "tool_result")
				) {
					(block as { cache_control?: { type: "ephemeral"; ttl?: "1h" } }).cache_control = cacheControl;
				}
			} else {
				last.content = [{ type: "text", text: last.content, cache_control: cacheControl }];
			}
		}
	}

	return params;
}

function convertTools(tools: Tool[] | undefined): AnthropicTool[] {
	if (!tools) return [];
	return tools.map((tool) => {
		const schema = tool.parameters as { properties?: Record<string, unknown>; required?: string[] };
		return {
			name: tool.name,
			description: tool.description,
			input_schema: {
				type: "object",
				properties: schema.properties ?? {},
				required: schema.required ?? [],
			},
		};
	});
}

function parseStreamingJson(partial: string): Record<string, unknown> {
	if (partial.trim().length === 0) return {};
	try {
		return JSON.parse(partial) as Record<string, unknown>;
	} catch {
		return {};
	}
}

let cachedGcloudProject: string | undefined;
let gcloudProjectResolved = false;

function readProjectFromGcloud(): string | undefined {
	if (gcloudProjectResolved) return cachedGcloudProject;
	gcloudProjectResolved = true;
	try {
		const value = execSync("gcloud config get-value project", {
			encoding: "utf-8",
			stdio: ["ignore", "pipe", "ignore"],
			timeout: 3000,
		}).trim();
		cachedGcloudProject = value.length > 0 ? value : undefined;
	} catch {
		cachedGcloudProject = undefined;
	}
	return cachedGcloudProject;
}

function resolveProject(options?: AnthropicVertexOptions): string | undefined {
	return (
		options?.project ??
		process.env.GOOGLE_CLOUD_PROJECT ??
		process.env.GCLOUD_PROJECT ??
		process.env.ANTHROPIC_VERTEX_PROJECT_ID ??
		readProjectFromGcloud()
	);
}

function resolveRegion(options?: AnthropicVertexOptions): string {
	return (
		options?.region ??
		process.env.GOOGLE_CLOUD_LOCATION ??
		process.env.CLOUD_ML_REGION ??
		DEFAULT_REGION
	);
}

/**
 * Load the optional `@anthropic-ai/vertex-sdk` package on demand.
 *
 * The SDK is *not* a hard dependency — it pulls in `google-auth-library` and is
 * only needed by users who actually run Claude on Vertex. We import it lazily so
 * a plain `npm i -g @vigolium/piolium` stays free of that dependency tree (and
 * its deprecation warnings). Callers reach this only when an `anthropic-vertex`
 * model is selected, so a missing package surfaces a clear install hint instead
 * of an extension-load crash.
 */
async function loadVertexSdk(): Promise<typeof import("@anthropic-ai/vertex-sdk")> {
	try {
		return await import("@anthropic-ai/vertex-sdk");
	} catch (error) {
		throw new Error(
			"The `anthropic-vertex` provider needs the optional `@anthropic-ai/vertex-sdk` package, " +
				"which is not installed. Enable Claude-on-Vertex with:\n\n" +
				"  npm install @anthropic-ai/vertex-sdk\n",
			{ cause: error },
		);
	}
}

async function createClient(
	model: Model<Api>,
	options?: AnthropicVertexOptions,
): Promise<AnthropicVertex> {
	const vertex = await loadVertexSdk();
	const betaFeatures = ["fine-grained-tool-streaming-2025-05-14"];
	if (options?.interleavedThinking ?? true) {
		betaFeatures.push("interleaved-thinking-2025-05-14");
	}

	const project = resolveProject(options);
	if (!project) {
		throw new Error(
			"Anthropic Vertex requires a project ID. Set ANTHROPIC_VERTEX_PROJECT_ID or GOOGLE_CLOUD_PROJECT/GCLOUD_PROJECT.",
		);
	}

	return new vertex.AnthropicVertex({
		projectId: project,
		region: resolveRegion(options),
		defaultHeaders: mergeHeaders(
			{
				accept: "application/json",
				"anthropic-beta": betaFeatures.join(","),
			},
			model.headers,
			options?.headers,
		),
	});
}

function buildParams(
	model: Model<Api>,
	context: Context,
	options?: AnthropicVertexOptions,
): MessageCreateParamsStreaming {
	const { cacheControl } = getCacheControl(model.baseUrl, options?.cacheRetention);
	const params: MessageCreateParamsStreaming = {
		model: model.id,
		messages: convertMessages(context.messages, model, cacheControl),
		max_tokens: options?.maxTokens ?? (model.maxTokens / 3) | 0,
		stream: true,
	};

	if (context.systemPrompt) {
		params.system = [
			{
				type: "text",
				text: sanitizeSurrogates(context.systemPrompt),
				...(cacheControl ? { cache_control: cacheControl } : {}),
			},
		];
	}

	if (options?.temperature !== undefined) {
		params.temperature = options.temperature;
	}

	if (context.tools) {
		params.tools = convertTools(context.tools);
	}

	if (options?.thinkingEnabled && model.reasoning) {
		if (supportsAdaptiveThinking(model.id)) {
			params.thinking = { type: "adaptive" };
			if (options.effort) {
				params.output_config = { effort: options.effort };
			}
		} else {
			params.thinking = {
				type: "enabled",
				budget_tokens: options.thinkingBudgetTokens ?? 1024,
			};
		}
	}

	if (options?.metadata && typeof options.metadata.user_id === "string") {
		params.metadata = { user_id: options.metadata.user_id };
	}

	if (options?.toolChoice) {
		params.tool_choice =
			typeof options.toolChoice === "string" ? { type: options.toolChoice } : options.toolChoice;
	}

	return params;
}

const streamAnthropicVertex: StreamFunction<Api, AnthropicVertexOptions> = (
	model,
	context,
	options,
) => {
	const stream = createAssistantMessageEventStream();

	(async () => {
		const output: AssistantMessage = {
			role: "assistant",
			content: [],
			api: model.api,
			provider: model.provider,
			model: model.id,
			usage: {
				input: 0,
				output: 0,
				cacheRead: 0,
				cacheWrite: 0,
				totalTokens: 0,
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
			},
			stopReason: "stop",
			timestamp: Date.now(),
		};

		// Raw API stop reason, retained so refusals/unexpected reasons produce a
		// specific message instead of a generic "unknown error".
		let rawStopReason: string | undefined;

		try {
			const client = await createClient(model, options);
			const params = buildParams(model, context, options);
			await options?.onPayload?.(params, model);
			const events = client.messages.stream({ ...params, stream: true }, { signal: options?.signal });

			stream.push({ type: "start", partial: output });
			const blocks = output.content as AnthropicStreamingBlock[];

			for await (const event of events as AsyncIterable<RawMessageStreamEvent>) {
				if (event.type === "message_start") {
					output.usage.input = event.message.usage.input_tokens || 0;
					output.usage.output = event.message.usage.output_tokens || 0;
					output.usage.cacheRead = event.message.usage.cache_read_input_tokens || 0;
					output.usage.cacheWrite = event.message.usage.cache_creation_input_tokens || 0;
					output.usage.totalTokens =
						output.usage.input + output.usage.output + output.usage.cacheRead + output.usage.cacheWrite;
					calculateCost(model, output.usage);
				} else if (event.type === "content_block_start") {
					if (event.content_block.type === "text") {
						blocks.push({ type: "text", text: "", index: event.index });
						stream.push({ type: "text_start", contentIndex: blocks.length - 1, partial: output });
					} else if (event.content_block.type === "thinking") {
						blocks.push({
							type: "thinking",
							thinking: "",
							thinkingSignature: "",
							index: event.index,
						});
						stream.push({
							type: "thinking_start",
							contentIndex: blocks.length - 1,
							partial: output,
						});
					} else if (event.content_block.type === "tool_use") {
						blocks.push({
							type: "toolCall",
							id: event.content_block.id,
							name: event.content_block.name,
							arguments: (event.content_block.input as Record<string, unknown>) ?? {},
							partialJson: "",
							index: event.index,
						});
						stream.push({
							type: "toolcall_start",
							contentIndex: blocks.length - 1,
							partial: output,
						});
					}
				} else if (event.type === "content_block_delta") {
					const index = blocks.findIndex((b) => b.index === event.index);
					const block = blocks[index];
					if (!block) continue;

					if (event.delta.type === "text_delta" && block.type === "text") {
						block.text += event.delta.text;
						stream.push({
							type: "text_delta",
							contentIndex: index,
							delta: event.delta.text,
							partial: output,
						});
					} else if (event.delta.type === "thinking_delta" && block.type === "thinking") {
						block.thinking += event.delta.thinking;
						stream.push({
							type: "thinking_delta",
							contentIndex: index,
							delta: event.delta.thinking,
							partial: output,
						});
					} else if (event.delta.type === "input_json_delta" && block.type === "toolCall") {
						block.partialJson += event.delta.partial_json;
						const parsed = parseStreamingJson(block.partialJson);
						if (Object.keys(parsed).length > 0) {
							block.arguments = parsed;
						}
						stream.push({
							type: "toolcall_delta",
							contentIndex: index,
							delta: event.delta.partial_json,
							partial: output,
						});
					} else if (event.delta.type === "signature_delta" && block.type === "thinking") {
						block.thinkingSignature = (block.thinkingSignature ?? "") + event.delta.signature;
					}
				} else if (event.type === "content_block_stop") {
					const index = blocks.findIndex((b) => b.index === event.index);
					const block = blocks[index];
					if (!block) continue;
					(block as { index?: number }).index = undefined;
					if (block.type === "text") {
						stream.push({
							type: "text_end",
							contentIndex: index,
							content: block.text,
							partial: output,
						});
					} else if (block.type === "thinking") {
						stream.push({
							type: "thinking_end",
							contentIndex: index,
							content: block.thinking,
							partial: output,
						});
					} else if (block.type === "toolCall") {
						const parsed = parseStreamingJson(block.partialJson);
						if (Object.keys(parsed).length > 0) {
							block.arguments = parsed;
						}
						(block as { partialJson?: string }).partialJson = undefined;
						stream.push({
							type: "toolcall_end",
							contentIndex: index,
							toolCall: block,
							partial: output,
						});
					}
				} else if (event.type === "message_delta") {
					if (event.delta.stop_reason) {
						rawStopReason = event.delta.stop_reason;
						output.stopReason = mapStopReason(event.delta.stop_reason);
					}
					if (event.usage.input_tokens != null) {
						output.usage.input = event.usage.input_tokens;
					}
					if (event.usage.output_tokens != null) {
						output.usage.output = event.usage.output_tokens;
					}
					if (event.usage.cache_read_input_tokens != null) {
						output.usage.cacheRead = event.usage.cache_read_input_tokens;
					}
					if (event.usage.cache_creation_input_tokens != null) {
						output.usage.cacheWrite = event.usage.cache_creation_input_tokens;
					}
					output.usage.totalTokens =
						output.usage.input + output.usage.output + output.usage.cacheRead + output.usage.cacheWrite;
					calculateCost(model, output.usage);
				}
			}

			if (options?.signal?.aborted) {
				throw new Error("Request was aborted");
			}

			if (
				output.stopReason !== "stop" &&
				output.stopReason !== "length" &&
				output.stopReason !== "toolUse"
			) {
				if (rawStopReason === "refusal" || rawStopReason === "sensitive") {
					throw new Error(
						`The model declined to respond (stop reason: ${rawStopReason}). This is usually a content/safety refusal, not a transport error.`,
					);
				}
				throw new Error(
					`The model stream ended with an unexpected stop reason${
						rawStopReason ? ` (${rawStopReason})` : ""
					}.`,
				);
			}

			stream.push({ type: "done", reason: output.stopReason, message: output });
			stream.end();
		} catch (error) {
			for (const block of output.content) {
				(block as { index?: number }).index = undefined;
				(block as { partialJson?: string }).partialJson = undefined;
			}
			output.stopReason = options?.signal?.aborted ? "aborted" : "error";
			output.errorMessage = error instanceof Error ? error.message : JSON.stringify(error);
			stream.push({ type: "error", reason: output.stopReason, error: output });
			stream.end();
		}
	})();

	return stream;
};

function clampReasoning(
	level: ThinkingLevel | undefined,
): Exclude<ThinkingLevel, "xhigh"> | undefined {
	if (!level) return undefined;
	return level === "xhigh" ? "high" : level;
}

function adjustMaxTokensForThinking(
	baseMaxTokens: number,
	modelMaxTokens: number,
	reasoningLevel: ThinkingLevel,
	customBudgets?: ThinkingBudgets,
): { maxTokens: number; thinkingBudget: number } {
	const defaultBudgets: Required<ThinkingBudgets> = {
		minimal: 1024,
		low: 2048,
		medium: 8192,
		high: 16384,
	};
	const budgets = { ...defaultBudgets, ...customBudgets };

	const minOutputTokens = 1024;
	const level = clampReasoning(reasoningLevel) ?? "high";
	let thinkingBudget = budgets[level] ?? defaultBudgets.high;
	const maxTokens = Math.min(baseMaxTokens + thinkingBudget, modelMaxTokens);

	if (maxTokens <= thinkingBudget) {
		thinkingBudget = Math.max(0, maxTokens - minOutputTokens);
	}

	return { maxTokens, thinkingBudget };
}

const streamSimpleAnthropicVertex: StreamFunction<Api, SimpleStreamOptions> = (
	model,
	context,
	options,
) => {
	const base: AnthropicVertexOptions = {
		...(options?.temperature !== undefined ? { temperature: options.temperature } : {}),
		maxTokens: options?.maxTokens ?? Math.min(model.maxTokens, 32000),
		...(options?.signal ? { signal: options.signal } : {}),
		...(options?.apiKey ? { apiKey: options.apiKey } : {}),
		...(options?.cacheRetention ? { cacheRetention: options.cacheRetention } : {}),
		...(options?.sessionId ? { sessionId: options.sessionId } : {}),
		...(options?.headers ? { headers: options.headers } : {}),
		...(options?.onPayload ? { onPayload: options.onPayload } : {}),
		...(options?.maxRetryDelayMs !== undefined ? { maxRetryDelayMs: options.maxRetryDelayMs } : {}),
		...(options?.metadata ? { metadata: options.metadata } : {}),
	};

	if (!options?.reasoning) {
		return streamAnthropicVertex(model, context, {
			...base,
			thinkingEnabled: false,
		});
	}

	if (supportsAdaptiveThinking(model.id)) {
		const effort = mapThinkingLevelToEffort(options.reasoning);
		return streamAnthropicVertex(model, context, {
			...base,
			thinkingEnabled: true,
			effort,
		});
	}

	const adjusted = adjustMaxTokensForThinking(
		base.maxTokens ?? 0,
		model.maxTokens,
		options.reasoning,
		options.thinkingBudgets,
	);

	return streamAnthropicVertex(model, context, {
		...base,
		maxTokens: adjusted.maxTokens,
		thinkingEnabled: true,
		thinkingBudgetTokens: adjusted.thinkingBudget,
	});
};

/**
 * Register the `anthropic-vertex` provider with pi-coding-agent.
 *
 * Adds the provider + Claude-on-Vertex models. Pi-ai's built-in
 * `google-vertex` provider keeps serving Gemini models untouched.
 *
 * The `apiKey` field is required by the registry but isn't used as an
 * HTTP header here — `AnthropicVertex` authenticates via Google ADC. We
 * emit the resolved project id so `pi`'s auth-status check has something
 * non-empty to display.
 */
export function registerAnthropicVertex(pi: ExtensionAPI): void {
	pi.registerProvider(PROVIDER_NAME, {
		baseUrl: BASE_URL,
		api: API_NAME,
		apiKey:
			"!sh -lc 'printf %s \"${ANTHROPIC_VERTEX_PROJECT_ID:-${GOOGLE_CLOUD_PROJECT:-${GCLOUD_PROJECT:-$(gcloud config get-value project 2>/dev/null)}}}\"'",
		models: MODELS,
		streamSimple: streamSimpleAnthropicVertex,
	});
}
