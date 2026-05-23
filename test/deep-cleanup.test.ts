import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { phasesFor } from "../extensions/piolium/modes.ts";
import { cleanupBalancedTransientArtifacts } from "../extensions/piolium/modes/balanced.ts";
import { cleanupDeepTransientArtifacts, runDeepAudit } from "../extensions/piolium/modes/deep.ts";
import { cleanupLiteTransientArtifacts } from "../extensions/piolium/modes/lite.ts";

let cwd: string;

beforeEach(() => {
	cwd = mkdtempSync(join(tmpdir(), "piolium-deep-cleanup-"));
});

afterEach(() => {
	rmSync(cwd, { recursive: true, force: true });
});

describe("deep verification cleanup", () => {
	it("registers verification cleanup as the final deep phase", () => {
		const phases = phasesFor("deep");

		expect(phases).toHaveLength(17);
		expect(phases.at(-1)).toBe("P17");
	});

	it("removes transient deep workspaces and keeps durable outputs", () => {
		const transient = [
			"piolium/tmp/piolium/runs/run-1",
			"piolium/tmp/p12-variant-structures.bqrs",
			"piolium/findings-draft",
			"piolium/file-records/internal",
			"piolium/raw/osv-details",
			"piolium/chamber-workspace/cluster-1",
			"piolium/probe-workspace/component-a",
			"piolium/adversarial-reviews",
			"piolium/bypass-analysis",
			"piolium/codeql-artifacts/db",
			"piolium/codeql-queries",
			"piolium/semgrep-rules",
			"piolium/agentic-actions-res",
			"piolium/confirm-workspace",
			"piolium/attack-surface/raw",
		];
		for (const rel of transient) {
			mkdirSync(join(cwd, rel), { recursive: true });
			writeFileSync(join(cwd, rel, "artifact.txt"), "temporary\n");
		}
		writeFileSync(join(cwd, "piolium", "attack-pattern-registry.json"), "{}\n");
		writeFileSync(join(cwd, "piolium", "authz-coverage-gaps.md"), "temporary\n");
		mkdirSync(join(cwd, "piolium", "attack-surface"), { recursive: true });
		mkdirSync(join(cwd, "piolium", "findings", "H1-example"), { recursive: true });
		writeFileSync(join(cwd, "piolium", "final-audit-report.md"), "# Final\n");
		writeFileSync(join(cwd, "piolium", "attack-surface", "variant-summary.md"), "# Variants\n");

		const result = cleanupDeepTransientArtifacts(cwd);

		expect(result.removed).toEqual([
			"piolium/tmp",
			"piolium/chamber-workspace",
			"piolium/probe-workspace",
			"piolium/adversarial-reviews",
			"piolium/bypass-analysis",
			"piolium/codeql-artifacts",
			"piolium/codeql-queries",
			"piolium/semgrep-rules",
			"piolium/agentic-actions-res",
			"piolium/confirm-workspace",
			"piolium/raw",
			"piolium/file-records",
			"piolium/findings-draft",
			"piolium/attack-surface/raw",
			"piolium/attack-pattern-registry.json",
			"piolium/authz-coverage-gaps.md",
		]);
		expect(existsSync(join(cwd, "piolium", "tmp"))).toBe(false);
		expect(existsSync(join(cwd, "piolium", "findings-draft"))).toBe(false);
		expect(existsSync(join(cwd, "piolium", "file-records"))).toBe(false);
		expect(existsSync(join(cwd, "piolium", "raw"))).toBe(false);
		expect(existsSync(join(cwd, "piolium", "chamber-workspace"))).toBe(false);
		expect(existsSync(join(cwd, "piolium", "probe-workspace"))).toBe(false);
		expect(existsSync(join(cwd, "piolium", "adversarial-reviews"))).toBe(false);
		expect(existsSync(join(cwd, "piolium", "codeql-artifacts"))).toBe(false);
		expect(existsSync(join(cwd, "piolium", "confirm-workspace"))).toBe(false);
		expect(existsSync(join(cwd, "piolium", "attack-surface"))).toBe(true);
		expect(existsSync(join(cwd, "piolium", "findings", "H1-example"))).toBe(true);
		expect(existsSync(join(cwd, "piolium", "final-audit-report.md"))).toBe(true);
		expect(existsSync(join(cwd, "piolium", "attack-surface", "variant-summary.md"))).toBe(true);

		const summary = JSON.parse(
			readFileSync(join(cwd, "piolium", "attack-surface", "deep-cleanup-summary.json"), "utf8"),
		) as { retained: string[] };
		expect(summary.retained).toContain("piolium/findings/");
		expect(summary.retained).not.toContain("piolium/variant-summary.md");
	});

	it("can run P17 cleanup against an already completed deep audit", async () => {
		mkdirSync(join(cwd, "piolium", "tmp", "piolium", "runs", "run-1"), { recursive: true });
		writeFileSync(join(cwd, "piolium", "tmp", "piolium", "runs", "run-1", "artifact.txt"), "tmp\n");
		mkdirSync(join(cwd, "piolium", "confirm-workspace"), { recursive: true });
		writeFileSync(
			join(cwd, "piolium", "audit-state.json"),
			`${JSON.stringify(
				{
					audits: [
						{
							audit_id: "complete-deep-audit",
							mode: "deep",
							started_at: "2026-05-01T00:00:00.000Z",
							completed_at: "2026-05-01T00:01:00.000Z",
							status: "complete",
							phases: {
								P16: { status: "complete" },
							},
						},
					],
				},
				null,
				"\t",
			)}\n`,
		);

		const result = await runDeepAudit({ cwd, only: ["P17"] });

		expect(result.status).toBe("complete");
		expect(existsSync(join(cwd, "piolium", "tmp"))).toBe(false);
		expect(existsSync(join(cwd, "piolium", "confirm-workspace"))).toBe(false);
		expect(existsSync(join(cwd, "piolium", "attack-surface", "deep-cleanup-summary.json"))).toBe(
			true,
		);
	});
});

describe("lite and balanced cleanup", () => {
	it("removes lite draft findings and transient workspaces after Q3 promotion", () => {
		mkdirSync(join(cwd, "piolium", "tmp", "piolium", "runs", "q2-run"), { recursive: true });
		writeFileSync(join(cwd, "piolium", "tmp", "piolium", "runs", "q2-run", "artifact.txt"), "tmp\n");
		mkdirSync(join(cwd, "piolium", "codeql-artifacts", "db"), { recursive: true });
		writeFileSync(join(cwd, "piolium", "codeql-artifacts", "db", "artifact.txt"), "tmp\n");
		mkdirSync(join(cwd, "piolium", "confirm-workspace"), { recursive: true });
		writeFileSync(join(cwd, "piolium", "confirm-workspace", "artifact.txt"), "tmp\n");
		mkdirSync(join(cwd, "piolium", "findings-draft"), { recursive: true });
		writeFileSync(join(cwd, "piolium", "findings-draft", "q2-001-demo.md"), "draft\n");
		mkdirSync(join(cwd, "piolium", "file-records", "src"), { recursive: true });
		writeFileSync(join(cwd, "piolium", "file-records", "src", "a.json"), "{}\n");
		mkdirSync(join(cwd, "piolium", "findings", "H1-demo"), { recursive: true });
		writeFileSync(join(cwd, "piolium", "findings", "H1-demo", "draft.md"), "promoted\n");

		const result = cleanupLiteTransientArtifacts(cwd);

		expect(result.removed).toEqual([
			"piolium/tmp",
			"piolium/codeql-artifacts",
			"piolium/confirm-workspace",
			"piolium/file-records",
			"piolium/findings-draft",
		]);
		expect(existsSync(join(cwd, "piolium", "tmp"))).toBe(false);
		expect(existsSync(join(cwd, "piolium", "findings-draft"))).toBe(false);
		expect(existsSync(join(cwd, "piolium", "file-records"))).toBe(false);
		expect(existsSync(join(cwd, "piolium", "codeql-artifacts"))).toBe(false);
		expect(existsSync(join(cwd, "piolium", "confirm-workspace"))).toBe(false);
		expect(existsSync(join(cwd, "piolium", "findings", "H1-demo", "draft.md"))).toBe(true);
		expect(existsSync(join(cwd, "piolium", "attack-surface", "lite-cleanup-summary.json"))).toBe(
			true,
		);
	});

	it("removes balanced draft findings and transient workspaces after finalization", () => {
		for (const rel of [
			"piolium/tmp/piolium/runs/run-1",
			"piolium/tmp/piolium/balanced-probe",
			"piolium/tmp/piolium/balanced-chamber",
			"piolium/findings-draft",
			"piolium/file-records/src",
			"piolium/raw/osv-details",
			"piolium/probe-workspace",
			"piolium/chamber-workspace",
			"piolium/codeql-artifacts/db",
			"piolium/codeql-queries",
			"piolium/semgrep-rules",
			"piolium/confirm-workspace",
		]) {
			mkdirSync(join(cwd, rel), { recursive: true });
			writeFileSync(join(cwd, rel, "artifact.txt"), "temporary\n");
		}
		mkdirSync(join(cwd, "piolium", "findings", "H1-example"), { recursive: true });
		writeFileSync(join(cwd, "piolium", "final-audit-report.md"), "# Final\n");

		const result = cleanupBalancedTransientArtifacts(cwd);

		expect(result.removed).toContain("piolium/findings-draft");
		expect(result.removed).toContain("piolium/file-records");
		expect(result.removed).toContain("piolium/raw");
		expect(result.removed).toContain("piolium/probe-workspace");
		expect(result.removed).toContain("piolium/tmp");
		expect(result.removed).toContain("piolium/codeql-artifacts");
		expect(result.removed).toContain("piolium/codeql-queries");
		expect(result.removed).toContain("piolium/semgrep-rules");
		expect(result.removed).toContain("piolium/confirm-workspace");
		expect(existsSync(join(cwd, "piolium", "tmp"))).toBe(false);
		expect(existsSync(join(cwd, "piolium", "findings-draft"))).toBe(false);
		expect(existsSync(join(cwd, "piolium", "file-records"))).toBe(false);
		expect(existsSync(join(cwd, "piolium", "raw"))).toBe(false);
		expect(existsSync(join(cwd, "piolium", "codeql-artifacts"))).toBe(false);
		expect(existsSync(join(cwd, "piolium", "confirm-workspace"))).toBe(false);
		expect(existsSync(join(cwd, "piolium", "findings", "H1-example"))).toBe(true);
		expect(existsSync(join(cwd, "piolium", "final-audit-report.md"))).toBe(true);
		expect(existsSync(join(cwd, "piolium", "attack-surface", "balanced-cleanup-summary.json"))).toBe(
			true,
		);
	});
});
