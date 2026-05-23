/**
 * Shared helper for orchestrators (lite/balanced/deep/etc.) — wraps a single
 * phase invocation with audit-state transitions, gate verification, and
 * structured logging via UI hooks.
 */

import { randomUUID } from "node:crypto";
import type { AgentSessionEvent } from "@earendil-works/pi-coding-agent";
import { type AgentRunError, type AgentRuntimeModel, runAgent } from "../agent-runner.ts";
import type { RuntimeContext } from "../agent-runner.ts";
import type { AgentDefinition } from "../agents.ts";
import { type AuditRunState, applyPhaseStatus } from "../audit-state.ts";
import {
	DEFAULT_HEARTBEAT_INTERVAL_MS,
	type PhaseHeartbeat,
	createPhaseHeartbeatTracker,
	heartbeatStateFields,
} from "../heartbeat.ts";
import {
	errorMessage,
	readNonNegativeIntEnv,
	readPositiveIntEnv,
	retryBackoffMs,
	sleep,
} from "../retry.ts";

export interface PhaseUiHooks {
	notify?: (text: string, level: "info" | "warning" | "error") => void;
	setStatus?: (key: string, text?: string) => void;
	/**
	 * Forwarded copy of every child agent event. Wire this from the command
	 * handler to surface tool calls + assistant text in the parent chat;
	 * otherwise the subagent runs silently and the user only sees a footer
	 * status indicator.
	 */
	onAgentEvent?: (phase: string, event: AgentSessionEvent) => void;
	/**
	 * Periodic parent-side health signal while a child agent is running.
	 * This fires even when the child model is quiet, so the UI can prove the
	 * phase has not been forgotten.
	 */
	onPhaseHeartbeat?: (phase: string, heartbeat?: PhaseHeartbeat) => void;
}

export interface RunAgentPhaseOptions {
	cwd: string;
	audit: AuditRunState;
	phaseName: string;
	statusKey: string;
	statusLabel: string;
	agent: AgentDefinition | undefined;
	missingAgentMessage: string;
	task: string;
	runtimeExtras?: Partial<Omit<RuntimeContext, "cwd" | "mode">>;
	gate: () => boolean;
	signal?: AbortSignal;
	ui?: PhaseUiHooks;
	mode: AuditRunState["mode"];
	agentRuntime?: AgentRuntimeModel;
	timeoutMs?: number;
	/** Number of retries after the first attempt. Defaults to PIOLIUM_PHASE_MAX_RETRIES or 5. */
	maxRetries?: number;
	retryBackoffBaseMs?: number;
	retryBackoffMaxMs?: number;
}

const HEARTBEAT_INTERVAL_MS = readPositiveIntEnv(
	"PIOLIUM_HEARTBEAT_INTERVAL_MS",
	DEFAULT_HEARTBEAT_INTERVAL_MS,
);

function defaultPhaseMaxRetries(): number {
	return readNonNegativeIntEnv("PIOLIUM_PHASE_MAX_RETRIES", 5);
}

function defaultPhaseBackoffBaseMs(): number {
	return readPositiveIntEnv("PIOLIUM_PHASE_BACKOFF_BASE_MS", 5000);
}

function defaultPhaseBackoffMaxMs(): number {
	return readPositiveIntEnv("PIOLIUM_PHASE_BACKOFF_MAX_MS", 120_000);
}

function makePhaseSignal(
	parent: AbortSignal | undefined,
	timeoutMs: number | undefined,
	phaseName: string,
): { signal?: AbortSignal; cleanup: () => void } {
	if (!timeoutMs || timeoutMs <= 0) {
		return { ...(parent ? { signal: parent } : {}), cleanup: () => {} };
	}

	const ctrl = new AbortController();
	let timeout: ReturnType<typeof setTimeout> | undefined = setTimeout(() => {
		ctrl.abort(new Error(`Phase ${phaseName} timed out after ${timeoutMs}ms`));
	}, timeoutMs);
	const onParentAbort = () => {
		ctrl.abort(parent?.reason ?? new Error(`Phase ${phaseName} aborted`));
	};
	if (parent) {
		if (parent.aborted) onParentAbort();
		else parent.addEventListener("abort", onParentAbort, { once: true });
	}
	return {
		signal: ctrl.signal,
		cleanup: () => {
			if (timeout) clearTimeout(timeout);
			timeout = undefined;
			if (parent) parent.removeEventListener("abort", onParentAbort);
		},
	};
}

export async function runAgentPhase(opts: RunAgentPhaseOptions): Promise<void> {
	const { cwd, audit, phaseName, statusKey, statusLabel, agent, ui, gate, mode } = opts;
	if (audit.phases[phaseName]?.status === "complete" && gate()) return;

	const maxRetries = Math.max(0, opts.maxRetries ?? defaultPhaseMaxRetries());
	const maxAttempts = maxRetries + 1;
	const backoffBaseMs = opts.retryBackoffBaseMs ?? defaultPhaseBackoffBaseMs();
	const backoffMaxMs = opts.retryBackoffMaxMs ?? defaultPhaseBackoffMaxMs();
	const onAgentEvent = ui?.onAgentEvent;
	const onPhaseHeartbeat = ui?.onPhaseHeartbeat;

	try {
		if (!agent) {
			await applyPhaseStatus(cwd, audit, phaseName, {
				status: "failed",
				error: opts.missingAgentMessage,
			});
			throw new Error(opts.missingAgentMessage);
		}

		for (let attempt = 1; attempt <= maxAttempts; attempt++) {
			const attemptLabel =
				maxAttempts > 1 ? `${statusLabel} (${attempt}/${maxAttempts})` : statusLabel;
			ui?.setStatus?.(statusKey, attemptLabel);
			await applyPhaseStatus(cwd, audit, phaseName, {
				status: "in_progress",
				attempt,
				max_attempts: maxAttempts,
				retry_backoff_ms: null,
				next_retry_at: null,
				...(attempt > 1 ? { error: `Retry attempt ${attempt}/${maxAttempts} running.` } : {}),
			});

			const runId = `${phaseName.toLowerCase()}-${audit.audit_id.replace(/[:.]/g, "-")}-a${attempt}-${randomUUID().slice(0, 8)}`;
			const phaseSignal = makePhaseSignal(opts.signal, opts.timeoutMs, phaseName);
			const heartbeat = createPhaseHeartbeatTracker({
				phase: phaseName,
				label: attemptLabel,
				runId,
			});
			let heartbeatTimer: ReturnType<typeof setInterval> | undefined;
			const emitHeartbeat = () => {
				const snapshot = heartbeat.snapshot();
				onPhaseHeartbeat?.(phaseName, snapshot);
				void applyPhaseStatus(cwd, audit, phaseName, {
					status: "in_progress",
					...heartbeatStateFields(snapshot),
				}).catch(() => {});
			};
			try {
				emitHeartbeat();
				heartbeatTimer = setInterval(emitHeartbeat, HEARTBEAT_INTERVAL_MS);
				await runAgent({
					agent,
					task: opts.task,
					runId,
					runtime: { cwd, mode, phase: phaseName, ...opts.runtimeExtras },
					...(opts.agentRuntime ? opts.agentRuntime : {}),
					...(phaseSignal.signal ? { signal: phaseSignal.signal } : {}),
					onEvent: (event) => {
						heartbeat.recordEvent(event);
						if (event.type === "tool_execution_start" || event.type === "tool_execution_end") {
							onPhaseHeartbeat?.(phaseName, heartbeat.snapshot());
						}
						onAgentEvent?.(phaseName, event);
					},
				});

				if (!gate()) {
					throw new Error(`Phase ${phaseName} gate failed — expected artifact missing.`);
				}

				await applyPhaseStatus(cwd, audit, phaseName, {
					status: "complete",
					attempt,
					max_attempts: maxAttempts,
					retry_backoff_ms: null,
					next_retry_at: null,
					last_error: null,
				});
				return;
			} catch (err) {
				const message = errorMessage(err);
				const failure = err as Partial<AgentRunError>;
				const artifacts = failure.result?.transcriptPath ? [failure.result.transcriptPath] : undefined;

				if (gate()) {
					await applyPhaseStatus(cwd, audit, phaseName, {
						status: "complete",
						attempt,
						max_attempts: maxAttempts,
						retry_backoff_ms: null,
						next_retry_at: null,
						last_error: null,
						...(artifacts ? { artifacts } : {}),
					});
					ui?.notify?.(
						`Phase ${phaseName} errored but its required artifact exists; treating it as complete.`,
						"warning",
					);
					return;
				}

				if (opts.signal?.aborted || attempt >= maxAttempts) {
					await applyPhaseStatus(cwd, audit, phaseName, {
						status: "failed",
						error:
							attempt >= maxAttempts && maxRetries > 0
								? `Failed after ${maxRetries} retries: ${message}`
								: message,
						attempt,
						max_attempts: maxAttempts,
						retry_backoff_ms: null,
						next_retry_at: null,
						last_error: message,
						...(artifacts ? { artifacts } : {}),
					});
					throw err;
				}

				const backoffMs = retryBackoffMs(attempt, backoffBaseMs, backoffMaxMs);
				const nextRetryAt = new Date(Date.now() + backoffMs).toISOString();
				await applyPhaseStatus(cwd, audit, phaseName, {
					status: "in_progress",
					error: `Attempt ${attempt}/${maxAttempts} failed: ${message}. Retrying at ${nextRetryAt}.`,
					attempt,
					max_attempts: maxAttempts,
					retry_backoff_ms: backoffMs,
					next_retry_at: nextRetryAt,
					last_error: message,
					...(artifacts ? { artifacts } : {}),
				});
				ui?.notify?.(
					`Phase ${phaseName} attempt ${attempt}/${maxAttempts} failed; retrying in ${Math.ceil(backoffMs / 1000)}s.`,
					"warning",
				);
				ui?.setStatus?.(statusKey, `${statusLabel} retrying in ${Math.ceil(backoffMs / 1000)}s`);
				await sleep(backoffMs, opts.signal);
			} finally {
				if (heartbeatTimer) clearInterval(heartbeatTimer);
				onPhaseHeartbeat?.(phaseName, undefined);
				phaseSignal.cleanup();
			}
		}
	} finally {
		ui?.setStatus?.(statusKey, undefined);
	}

	await applyPhaseStatus(cwd, audit, phaseName, {
		status: "failed",
		error: `Phase ${phaseName} failed unexpectedly without throwing.`,
	});
	throw new Error(`Phase ${phaseName} failed`);
}
