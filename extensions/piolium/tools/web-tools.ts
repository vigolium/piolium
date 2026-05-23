/**
 * WebFetch + WebSearch tools.
 *
 * Many bundled agents declare `WebFetch` / `WebSearch` in their
 * frontmatter — without these implementations, those tool names would
 * resolve to nothing in the child session and the agent would silently lack
 * any web capability. We provide a real WebFetch and a graceful WebSearch
 * stub that points the model at workable fallbacks (`bash` + `curl`, the
 * `agent-browser` CLI, or operator-supplied URLs).
 *
 * Adapted from piolium's `src/tools/web-tools.ts`. WebFetch is verbatim;
 * WebSearch is rewritten to reflect this project's stance — we deliberately
 * don't ship a search backend; the agent is expected to fall back to bash
 * tooling.
 */

import { type Static, Type } from "@earendil-works/pi-ai";
import { type ToolDefinition, defineTool } from "@earendil-works/pi-coding-agent";

const FETCH_BODY_LIMIT = 256_000;
const FETCH_TIMEOUT_MS = 30_000;

const webFetchSchema = Type.Object({
	url: Type.String({ description: "Absolute http(s) URL to fetch." }),
	prompt: Type.Optional(
		Type.String({
			description:
				"Optional natural-language hint about what to look for. Currently informational — the full response body is returned.",
		}),
	),
});

export type WebFetchInput = Static<typeof webFetchSchema>;

/**
 * Read a response body incrementally, stopping once the decoded text reaches
 * FETCH_BODY_LIMIT. Avoids buffering an unbounded body into memory the way
 * `res.text()` would — a multi-GB response is truncated instead of OOMing.
 *
 * `bytes` is the number of body bytes actually read: the full size for a
 * complete read, or roughly FETCH_BODY_LIMIT when `truncated` (we stop early,
 * so the true size is unknown without defeating the cap).
 */
async function readCappedBody(
	res: Response,
): Promise<{ text: string; bytes: number; truncated: boolean }> {
	const reader = res.body?.getReader();
	if (!reader) {
		// No readable stream: per the Fetch spec the response carries no body
		// (e.g. 204/304/HEAD). Treat it as empty rather than `res.text()`, which
		// would buffer an unbounded body and defeat the cap on this path.
		return { text: "", bytes: 0, truncated: false };
	}
	const decoder = new TextDecoder();
	let text = "";
	let bytes = 0;
	let truncated = false;
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			if (value) {
				bytes += value.byteLength;
				text += decoder.decode(value, { stream: true });
			}
			if (text.length >= FETCH_BODY_LIMIT) {
				truncated = true;
				break;
			}
		}
	} finally {
		await reader.cancel().catch(() => {});
	}
	text += decoder.decode();
	if (text.length > FETCH_BODY_LIMIT) text = text.slice(0, FETCH_BODY_LIMIT);
	return { text, bytes, truncated };
}

export interface WebFetchDetails {
	url: string;
	status: number;
	contentType?: string;
	bytes: number;
	truncated: boolean;
}

export const WEB_FETCH_TOOL: ToolDefinition<typeof webFetchSchema, WebFetchDetails> = defineTool({
	name: "WebFetch",
	label: "Fetch URL",
	description:
		"Fetch the body of an http(s) URL and return it as text. Use for advisory pages, RFCs, package manifests, etc. Response body capped at 256KB; pass narrower URLs (e.g. raw-file URLs) for large resources.",
	parameters: webFetchSchema,
	async execute(_id, params, signal) {
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
		const onAbort = () => controller.abort();
		signal?.addEventListener("abort", onAbort, { once: true });
		try {
			const res = await fetch(params.url, {
				signal: controller.signal,
				headers: { "user-agent": "piolium-webfetch/1.0" },
				redirect: "follow",
			});
			const contentType = res.headers.get("content-type") ?? undefined;
			const { text, bytes, truncated } = await readCappedBody(res);
			const body = truncated
				? `${text}\n... [truncated; response exceeded ${FETCH_BODY_LIMIT} characters]`
				: text;
			return {
				content: [
					{
						type: "text" as const,
						text: `HTTP ${res.status}${contentType ? ` (${contentType})` : ""}\nURL: ${params.url}\n\n${body}`,
					},
				],
				details: {
					url: params.url,
					status: res.status,
					...(contentType ? { contentType } : {}),
					bytes,
					truncated,
				},
			};
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			return {
				content: [{ type: "text" as const, text: `WebFetch failed: ${msg}\nURL: ${params.url}` }],
				details: { url: params.url, status: 0, bytes: 0, truncated: false },
				isError: true,
			};
		} finally {
			clearTimeout(timeoutId);
			signal?.removeEventListener("abort", onAbort);
		}
	},
});

const webSearchSchema = Type.Object({
	query: Type.String({ description: "Search query." }),
	max_results: Type.Optional(
		Type.Number({ description: "Hint for max results — currently ignored by the fallback message." }),
	),
});

export type WebSearchInput = Static<typeof webSearchSchema>;

export interface WebSearchDetails {
	query: string;
	backend: "fallback";
}

/**
 * piolium ships no built-in search backend by design — the operator's
 * preference (per the M0 plan) is to use `bash` + `curl` against a known
 * endpoint or invoke an external `agent-browser` CLI. We surface the tool
 * name so agents that declare `WebSearch` in their allowlist still get a
 * callable, but the result instructs the model to switch tactics.
 */
export const WEB_SEARCH_TOOL: ToolDefinition<typeof webSearchSchema, WebSearchDetails> = defineTool(
	{
		name: "WebSearch",
		label: "Web search",
		description:
			"Search the web for a query. NOTE: piolium ships no built-in search backend; this tool returns instructions for falling back to `bash` + `curl` against a search endpoint, or invoking an `agent-browser` CLI if available.",
		parameters: webSearchSchema,
		async execute(_id, params) {
			return {
				content: [
					{
						type: "text" as const,
						text: [
							"WebSearch has no backend in piolium. Choose one of:",
							"  1. Run `bash` with `curl -fsSL '<search-engine-url>?q=<query>'` against an endpoint you have access to.",
							"  2. If the `agent-browser` CLI is on PATH, invoke it via `bash`: `agent-browser search '<query>'`.",
							"  3. Ask the user for an authoritative URL, then call WebFetch on it.",
							`Received query: ${params.query}`,
						].join("\n"),
					},
				],
				details: { query: params.query, backend: "fallback" as const },
				isError: true,
			};
		},
	},
);

/** Convenience: every web-related tool. Plug into `customTools` arrays. */
export const WEB_TOOLS: ToolDefinition[] = [
	WEB_FETCH_TOOL as unknown as ToolDefinition,
	WEB_SEARCH_TOOL as unknown as ToolDefinition,
];
