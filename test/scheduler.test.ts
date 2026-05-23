import { describe, expect, it } from "vitest";
import {
	Scheduler,
	SchedulerAbortError,
	TaskTimeoutError,
} from "../extensions/piolium/scheduler.ts";

function deferred<T>(): {
	promise: Promise<T>;
	resolve: (v: T) => void;
	reject: (e: unknown) => void;
} {
	let resolve!: (v: T) => void;
	let reject!: (e: unknown) => void;
	const promise = new Promise<T>((res, rej) => {
		resolve = res;
		reject = rej;
	});
	return { promise, resolve, reject };
}

describe("Scheduler concurrency cap", () => {
	it("never runs more than maxConcurrent tasks at once", async () => {
		const cap = 3;
		const scheduler = new Scheduler({ maxConcurrent: cap });
		let active = 0;
		let peakActive = 0;
		const tasks = Array.from({ length: 12 }, (_, i) => ({
			id: `t${i}`,
			run: async () => {
				active++;
				if (active > peakActive) peakActive = active;
				await new Promise((r) => setTimeout(r, 10));
				active--;
				return i;
			},
		}));
		await scheduler.runBatch(tasks);
		expect(peakActive).toBeLessThanOrEqual(cap);
		expect(peakActive).toBe(cap);
	});

	it("preserves FIFO order for completion when tasks are uniform", async () => {
		const scheduler = new Scheduler({ maxConcurrent: 1 });
		const order: number[] = [];
		await scheduler.runBatch(
			Array.from({ length: 5 }, (_, i) => ({
				id: `t${i}`,
				run: async () => {
					order.push(i);
					return i;
				},
			})),
		);
		expect(order).toEqual([0, 1, 2, 3, 4]);
	});

	it("default cap is 3", () => {
		const scheduler = new Scheduler();
		expect(scheduler.maxConcurrent).toBe(3);
	});
});

describe("Scheduler abort", () => {
	it("aborting rejects pending tasks immediately", async () => {
		const scheduler = new Scheduler({ maxConcurrent: 1 });
		const blocker = deferred<number>();
		const first = scheduler.enqueue({ id: "first", run: () => blocker.promise });
		const second = scheduler.enqueue({
			id: "second",
			run: async () => {
				throw new Error("should never run");
			},
		});
		scheduler.abort();
		await expect(second).rejects.toBeInstanceOf(SchedulerAbortError);
		// First task is in-flight; it should also see its signal aborted.
		blocker.resolve(0);
		await expect(first).resolves.toBe(0);
	});

	it("propagates abort signal to running tasks", async () => {
		const scheduler = new Scheduler({ maxConcurrent: 1 });
		let observedAbort = false;
		const promise = scheduler.enqueue({
			id: "watch",
			run: (signal) =>
				new Promise<void>((_, reject) => {
					signal.addEventListener("abort", () => {
						observedAbort = true;
						reject(new Error("aborted from inside"));
					});
				}),
		});
		// Defer abort so the task is in-flight.
		await new Promise((r) => setTimeout(r, 5));
		scheduler.abort();
		await expect(promise).rejects.toThrow();
		expect(observedAbort).toBe(true);
	});

	it("respects an external AbortSignal", async () => {
		const ctrl = new AbortController();
		const scheduler = new Scheduler({ maxConcurrent: 1, signal: ctrl.signal });
		const blocker = deferred<number>();
		const queued = scheduler.enqueue({ id: "x", run: () => blocker.promise });
		const queuedSecond = scheduler.enqueue({ id: "y", run: () => blocker.promise });
		ctrl.abort();
		await expect(queuedSecond).rejects.toBeInstanceOf(SchedulerAbortError);
		blocker.resolve(0);
		await expect(queued).resolves.toBe(0);
	});

	it("rejects new enqueues after abort", async () => {
		const scheduler = new Scheduler({ maxConcurrent: 1 });
		scheduler.abort();
		await expect(scheduler.enqueue({ id: "late", run: async () => 1 })).rejects.toBeInstanceOf(
			SchedulerAbortError,
		);
	});
});

describe("Scheduler timeout", () => {
	it("rejects with TaskTimeoutError when a task exceeds timeoutMs", async () => {
		const scheduler = new Scheduler({ maxConcurrent: 1 });
		const promise = scheduler.enqueue({
			id: "slow",
			timeoutMs: 30,
			run: (signal) =>
				new Promise<void>((_, reject) => {
					signal.addEventListener("abort", () => reject(signal.reason));
				}),
		});
		await expect(promise).rejects.toBeInstanceOf(TaskTimeoutError);
	});

	it("does not time out fast tasks", async () => {
		const scheduler = new Scheduler({ maxConcurrent: 1 });
		const result = await scheduler.enqueue({
			id: "fast",
			timeoutMs: 100,
			run: async () => 42,
		});
		expect(result).toBe(42);
	});
});

describe("Scheduler stats + batch", () => {
	it("stats reflect lifecycle", async () => {
		const scheduler = new Scheduler({ maxConcurrent: 2 });
		expect(scheduler.stats().active).toBe(0);
		const blocker = deferred<number>();
		const a = scheduler.enqueue({ id: "a", run: () => blocker.promise });
		const b = scheduler.enqueue({ id: "b", run: () => blocker.promise });
		const c = scheduler.enqueue({ id: "c", run: () => blocker.promise });
		await new Promise((r) => setTimeout(r, 5));
		const stats = scheduler.stats();
		expect(stats.active).toBe(2);
		expect(stats.pending).toBe(1);
		blocker.resolve(0);
		await Promise.all([a, b, c]);
		const final = scheduler.stats();
		expect(final.active).toBe(0);
		expect(final.completed).toBe(3);
	});

	it("runBatch surfaces individual failures", async () => {
		const scheduler = new Scheduler({ maxConcurrent: 2 });
		const results = await scheduler.runBatch([
			{ id: "ok", run: async () => 1 },
			{
				id: "fail",
				run: async () => {
					throw new Error("boom");
				},
			},
		]);
		expect(results[0]?.status).toBe("fulfilled");
		expect(results[1]?.status).toBe("rejected");
	});
});
