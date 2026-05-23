export interface RetryOptions {
	maxRetries: number;
	backoffBaseMs: number;
	backoffMaxMs: number;
	signal?: AbortSignal;
	onRetry?: (info: RetryInfo) => void | Promise<void>;
	shouldRetry?: (err: unknown, info: RetryInfo) => boolean | Promise<boolean>;
}

export interface RetryInfo {
	attempt: number;
	maxAttempts: number;
	nextAttempt: number;
	backoffMs: number;
	nextRetryAt: string;
	errorMessage: string;
}

export function readPositiveIntEnv(name: string, fallback: number): number {
	const raw = process.env[name];
	if (raw === undefined || raw.trim() === "") return fallback;
	const parsed = Number.parseInt(raw, 10);
	return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export function readNonNegativeIntEnv(name: string, fallback: number): number {
	const raw = process.env[name];
	if (raw === undefined || raw.trim() === "") return fallback;
	const parsed = Number.parseInt(raw, 10);
	return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

export function errorMessage(err: unknown): string {
	return err instanceof Error ? err.message : typeof err === "string" ? err : "Unknown error";
}

export function retryBackoffMs(attempt: number, baseMs: number, maxMs: number): number {
	const exponent = Math.max(0, attempt - 1);
	const raw = baseMs * 2 ** exponent;
	return Math.min(maxMs, raw);
}

export async function sleep(ms: number, signal: AbortSignal | undefined): Promise<void> {
	if (ms <= 0) return;
	if (signal?.aborted) throw signal.reason ?? new Error("Aborted");
	await new Promise<void>((resolve, reject) => {
		const cleanup = () => {
			clearTimeout(timeout);
			signal?.removeEventListener("abort", onAbort);
		};
		const timeout = setTimeout(() => {
			cleanup();
			resolve();
		}, ms);
		const onAbort = () => {
			cleanup();
			reject(signal?.reason ?? new Error("Aborted"));
		};
		signal?.addEventListener("abort", onAbort, { once: true });
	});
}

export async function yieldToEventLoop(signal?: AbortSignal): Promise<void> {
	if (signal?.aborted) throw signal.reason ?? new Error("Aborted");
	await new Promise<void>((resolve, reject) => {
		const cleanup = () => {
			clearTimeout(timeout);
			signal?.removeEventListener("abort", onAbort);
		};
		const timeout = setTimeout(() => {
			cleanup();
			resolve();
		}, 0);
		const onAbort = () => {
			cleanup();
			reject(signal?.reason ?? new Error("Aborted"));
		};
		signal?.addEventListener("abort", onAbort, { once: true });
	});
}

export async function runWithRetry<T>(
	operation: (attempt: number, maxAttempts: number) => Promise<T>,
	options: RetryOptions,
): Promise<T> {
	const maxRetries = Math.max(0, options.maxRetries);
	const maxAttempts = maxRetries + 1;

	for (let attempt = 1; attempt <= maxAttempts; attempt++) {
		try {
			return await operation(attempt, maxAttempts);
		} catch (err) {
			if (options.signal?.aborted || attempt >= maxAttempts) throw err;

			const backoffMs = retryBackoffMs(attempt, options.backoffBaseMs, options.backoffMaxMs);
			const info: RetryInfo = {
				attempt,
				maxAttempts,
				nextAttempt: attempt + 1,
				backoffMs,
				nextRetryAt: new Date(Date.now() + backoffMs).toISOString(),
				errorMessage: errorMessage(err),
			};

			if (options.shouldRetry && !(await options.shouldRetry(err, info))) throw err;
			await options.onRetry?.(info);
			await sleep(backoffMs, options.signal);
		}
	}

	throw new Error("Retry loop exhausted unexpectedly.");
}
