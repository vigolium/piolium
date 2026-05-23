import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: ["test/**/*.test.ts"],
		environment: "node",
		// Audit-state tests use real fs in tmp dirs; serial keeps them simple.
		fileParallelism: false,
		coverage: {
			provider: "v8",
			include: ["extensions/**/*.ts"],
			exclude: ["extensions/**/_vendor/**"],
			reporter: ["text", "html"],
		},
	},
});
