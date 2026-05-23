import { afterEach, describe, expect, it } from "vitest";
import {
	readNonNegativeIntEnv,
	readPositiveIntEnv,
	runWithRetry,
} from "../extensions/piolium/retry.ts";

const ENV_KEYS = ["PIOLIUM_TEST_LIMIT", "ARCHON_TEST_LIMIT", "PIOLIUM_TEST_ZERO"];

afterEach(() => {
	for (const key of ENV_KEYS) delete process.env[key];
});

describe("runWithRetry", () => {
	it("retries failing operations and returns the successful result", async () => {
		let attempts = 0;
		const retryMessages: string[] = [];

		const result = await runWithRetry(
			async () => {
				attempts++;
				if (attempts < 3) throw new Error(`boom-${attempts}`);
				return "ok";
			},
			{
				maxRetries: 2,
				backoffBaseMs: 0,
				backoffMaxMs: 0,
				onRetry: (info) => {
					retryMessages.push(info.errorMessage);
				},
			},
		);

		expect(result).toBe("ok");
		expect(attempts).toBe(3);
		expect(retryMessages).toEqual(["boom-1", "boom-2"]);
	});

	it("honors shouldRetry=false", async () => {
		let attempts = 0;

		await expect(
			runWithRetry(
				async () => {
					attempts++;
					throw new Error("do-not-retry");
				},
				{
					maxRetries: 3,
					backoffBaseMs: 0,
					backoffMaxMs: 0,
					shouldRetry: () => false,
				},
			),
		).rejects.toThrow("do-not-retry");

		expect(attempts).toBe(1);
	});
});

describe("env readers", () => {
	it("reads PIOLIUM_* values", () => {
		process.env.PIOLIUM_TEST_LIMIT = "7";

		expect(readPositiveIntEnv("PIOLIUM_TEST_LIMIT", 1)).toBe(7);
	});

	it("does not read legacy ARCHON_* values", () => {
		process.env.ARCHON_TEST_LIMIT = "3";

		expect(readPositiveIntEnv("PIOLIUM_TEST_LIMIT", 1)).toBe(1);
	});

	it("allows zero for non-negative env readers", () => {
		process.env.PIOLIUM_TEST_ZERO = "0";

		expect(readNonNegativeIntEnv("PIOLIUM_TEST_ZERO", 2)).toBe(0);
	});
});
