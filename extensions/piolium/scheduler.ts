/**
 * Concurrency-capped FIFO scheduler used by every audit mode.
 *
 * Why this exists:
 *   - Piolium's Deep mode mandates a hard cap of 3 concurrently active
 *     background sub-agents (the "Swarm Burst Cap"). The cap is enforced
 *     here so individual modes don't reinvent it.
 *   - Each task gets its own AbortSignal so a long-running sub-agent can be
 *     cancelled cleanly when the user aborts the audit.
 *   - Per-task timeouts catch runaway model calls without stalling the whole
 *     queue.
 *
 * The scheduler is intentionally tiny — no priority levels, no retries (let
 * the caller decide policy), no work-stealing. It only does:
 *
 *   1. honour `maxConcurrent`
 *   2. process tasks FIFO
 *   3. propagate abort and timeout via AbortSignal
 *
 * Transcript dirs (`piolium/tmp/piolium/runs/<id>/`) are exposed as helpers
 * so the agent runner (M2) writes to a stable, scheduler-known location.
 */

import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";

export interface SchedulerOptions {
	/** Maximum simultaneous in-flight tasks. Defaults to 3. */
	maxConcurrent?: number;
	/** External abort signal; aborting this aborts the scheduler and all tasks. */
	signal?: AbortSignal;
}

export interface ScheduledTask<T> {
	/** Stable identifier — surfaced in run dirs and logs. */
	id: string;
	/** Optional human label for status widgets. */
	label?: string;
	/** Per-task timeout in milliseconds. Omit for no timeout. */
	timeoutMs?: number;
	/**
	 * Task body. Receives an AbortSignal that fires on either external abort
	 * or timeout. Should reject promptly when the signal fires.
	 */
	run: (signal: AbortSignal) => Promise<T>;
}

export interface SchedulerStats {
	maxConcurrent: number;
	active: number;
	pending: number;
	completed: number;
	failed: number;
	aborted: boolean;
}

interface PendingEntry<T> {
	task: ScheduledTask<T>;
	resolve: (value: T) => void;
	reject: (err: unknown) => void;
}

export class SchedulerAbortError extends Error {
	constructor(message = "Scheduler aborted") {
		super(message);
		this.name = "SchedulerAbortError";
	}
}

export class TaskTimeoutError extends Error {
	constructor(
		public readonly taskId: string,
		public readonly timeoutMs: number,
	) {
		super(`Task ${taskId} timed out after ${timeoutMs}ms`);
		this.name = "TaskTimeoutError";
	}
}

export class Scheduler {
	readonly maxConcurrent: number;
	private active = 0;
	private completed = 0;
	private failed = 0;
	private aborted = false;
	private readonly queue: PendingEntry<unknown>[] = [];
	private readonly inflight = new Set<AbortController>();
	private readonly externalSignal?: AbortSignal;
	private readonly externalAbortListener?: () => void;

	constructor(opts: SchedulerOptions = {}) {
		this.maxConcurrent = Math.max(1, opts.maxConcurrent ?? 3);
		this.externalSignal = opts.signal;
		if (this.externalSignal) {
			if (this.externalSignal.aborted) {
				this.aborted = true;
			} else {
				this.externalAbortListener = () => this.abort();
				this.externalSignal.addEventListener("abort", this.externalAbortListener, { once: true });
			}
		}
	}

	enqueue<T>(task: ScheduledTask<T>): Promise<T> {
		if (this.aborted) {
			return Promise.reject(new SchedulerAbortError());
		}
		return new Promise<T>((resolve, reject) => {
			this.queue.push({
				task: task as ScheduledTask<unknown>,
				resolve: resolve as (v: unknown) => void,
				reject,
			});
			this.pump();
		});
	}

	/**
	 * Convenience: enqueue many tasks and wait for all settlements (mirrors
	 * Promise.allSettled). The cap still applies — only `maxConcurrent` are
	 * in-flight at once even when callers pass a giant array.
	 */
	async runBatch<T>(tasks: ScheduledTask<T>[]): Promise<PromiseSettledResult<T>[]> {
		return Promise.allSettled(tasks.map((t) => this.enqueue(t)));
	}

	abort(): void {
		if (this.aborted) return;
		this.aborted = true;
		// Reject everything still queued so callers stop waiting.
		const drain = this.queue.splice(0, this.queue.length);
		for (const entry of drain) entry.reject(new SchedulerAbortError());
		// Cancel everything currently running.
		for (const ctrl of this.inflight) ctrl.abort(new SchedulerAbortError());
	}

	stats(): SchedulerStats {
		return {
			maxConcurrent: this.maxConcurrent,
			active: this.active,
			pending: this.queue.length,
			completed: this.completed,
			failed: this.failed,
			aborted: this.aborted,
		};
	}

	dispose(): void {
		this.abort();
		if (this.externalSignal && this.externalAbortListener) {
			this.externalSignal.removeEventListener("abort", this.externalAbortListener);
		}
	}

	private pump(): void {
		while (!this.aborted && this.active < this.maxConcurrent && this.queue.length > 0) {
			const entry = this.queue.shift();
			if (!entry) break;
			void this.runEntry(entry);
		}
	}

	private async runEntry(entry: PendingEntry<unknown>): Promise<void> {
		this.active++;
		const ctrl = new AbortController();
		this.inflight.add(ctrl);
		let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
		if (entry.task.timeoutMs && entry.task.timeoutMs > 0) {
			const timeoutMs = entry.task.timeoutMs;
			timeoutHandle = setTimeout(() => {
				ctrl.abort(new TaskTimeoutError(entry.task.id, timeoutMs));
			}, timeoutMs);
		}
		try {
			const result = await entry.task.run(ctrl.signal);
			this.completed++;
			entry.resolve(result);
		} catch (err) {
			this.failed++;
			// Surface the timeout reason as the rejected error so callers can
			// distinguish abort from "task threw on its own".
			if (ctrl.signal.aborted && ctrl.signal.reason instanceof TaskTimeoutError) {
				entry.reject(ctrl.signal.reason);
			} else {
				entry.reject(err);
			}
		} finally {
			if (timeoutHandle) clearTimeout(timeoutHandle);
			this.inflight.delete(ctrl);
			this.active--;
			this.pump();
		}
	}
}

/**
 * Path conventions for per-task transcript directories. Modes use these to
 * keep raw subagent output isolated from final artifacts under `piolium/`.
 */
export function getRunsRoot(cwd: string): string {
	return join(cwd, "piolium", "tmp", "piolium", "runs");
}

export function getRunDir(cwd: string, runId: string): string {
	return join(getRunsRoot(cwd), runId);
}

export function ensureRunDir(cwd: string, runId: string): string {
	const dir = getRunDir(cwd, runId);
	if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
	return dir;
}
