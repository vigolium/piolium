import type { Api, Model } from "@earendil-works/pi-ai";
import type { ModelRegistry } from "@earendil-works/pi-coding-agent";
import { describe, expect, it } from "vitest";
import {
	buildRuntimeHeader,
	compactTranscriptEvent,
	resolveAgentModel,
} from "../extensions/piolium/agent-runner.ts";

function fakeModel(provider: string, id: string, name = id): Model<Api> {
	return { provider, id, name } as Model<Api>;
}

function fakeRegistry(models: Model<Api>[]): ModelRegistry {
	return { getAvailable: () => models } as unknown as ModelRegistry;
}

describe("resolveAgentModel", () => {
	it("routes a family alias away from the parent model when an authenticated match exists", () => {
		const parent = fakeModel("openai-codex", "gpt-5.6-sol");
		const sonnet45 = fakeModel("anthropic", "claude-sonnet-4-5");
		const sonnet5 = fakeModel("anthropic", "claude-sonnet-5");
		const registry = fakeRegistry([parent, sonnet45, sonnet5]);

		expect(resolveAgentModel("sonnet", parent, registry)).toBe(sonnet5);
	});

	it("prefers a matching model from the parent's provider", () => {
		const parent = fakeModel("anthropic-vertex", "claude-opus-4-6@default");
		const direct = fakeModel("anthropic", "claude-sonnet-5");
		const vertex = fakeModel("anthropic-vertex", "claude-sonnet-4-5@20250929");
		const registry = fakeRegistry([direct, vertex]);

		expect(resolveAgentModel("sonnet", parent, registry)).toBe(vertex);
	});

	it("resolves a fully-qualified model id", () => {
		const parent = fakeModel("openai-codex", "gpt-5.6-sol");
		const requested = fakeModel("anthropic", "claude-sonnet-4-6");
		const registry = fakeRegistry([parent, requested]);

		expect(resolveAgentModel("anthropic/claude-sonnet-4-6", parent, registry)).toBe(requested);
	});

	it("falls back to the parent model when the declaration cannot be resolved", () => {
		const parent = fakeModel("openai-codex", "gpt-5.6-sol");
		const registry = fakeRegistry([parent]);

		expect(resolveAgentModel("sonnet", parent, registry)).toBe(parent);
	});
});

describe("buildRuntimeHeader", () => {
	it("includes the audit cwd, mode, and phase when provided", () => {
		const header = buildRuntimeHeader({
			cwd: "/tmp/repo",
			mode: "deep",
			phase: "P5",
		});

		expect(header).toContain("- Target repository: /tmp/repo");
		expect(header).toContain("- Mode: deep");
		expect(header).toContain("- Phase: P5");
	});

	it("appends operator notes when given", () => {
		const header = buildRuntimeHeader({
			cwd: "/tmp/repo",
			mode: "lite",
			notes: ["git unavailable", "secrets pre-filtered"],
		});

		expect(header).toContain("Operator notes:");
		expect(header).toContain("- git unavailable");
		expect(header).toContain("- secrets pre-filtered");
	});

	it("drops bulky streaming partials from transcript update events", () => {
		const compacted = compactTranscriptEvent({
			type: "message_update",
			assistantMessageEvent: {
				type: "thinking_delta",
				delta: "hello",
				partial: {
					role: "assistant",
					content: [{ type: "thinking", thinkingSignature: "x".repeat(100) }],
				},
			},
			message: {
				role: "assistant",
				content: [{ type: "thinking", thinkingSignature: "y".repeat(100) }],
			},
		} as never);

		const json = JSON.stringify(compacted);
		expect(json).toContain("thinking_delta");
		expect(json).toContain("hello");
		expect(json).not.toContain("partial");
		expect(json).not.toContain("thinkingSignature");
		expect(json).not.toContain("yyyy");
	});
});
