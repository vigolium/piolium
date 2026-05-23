import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { initAudit, mutateAuditState } from "../extensions/piolium/audit-state.ts";
import { buildAuditResultStatsLines } from "../extensions/piolium/result-stats.ts";

let cwd: string;

beforeEach(() => {
	cwd = mkdtempSync(join(tmpdir(), "piolium-result-stats-"));
});

afterEach(() => {
	rmSync(cwd, { recursive: true, force: true });
});

function writeFindingDir(name: string, draft: string): void {
	const dir = join(cwd, "piolium", "findings", name);
	mkdirSync(dir, { recursive: true });
	writeFileSync(join(dir, "draft.md"), draft);
}

function writeDraft(name: string, draft: string): void {
	const dir = join(cwd, "piolium", "findings-draft");
	mkdirSync(dir, { recursive: true });
	writeFileSync(join(dir, name), draft);
}

describe("audit result stats", () => {
	it("formats audit duration and finalized finding severities", async () => {
		const audit = await initAudit(cwd, { mode: "balanced" });
		await mutateAuditState(cwd, (state) => ({
			...state,
			audits: state.audits.map((candidate) =>
				candidate.audit_id === audit.audit_id
					? {
							...candidate,
							started_at: "2026-05-01T00:00:00.000Z",
							completed_at: "2026-05-01T01:02:03.000Z",
							status: "complete",
						}
					: candidate,
			),
		}));

		writeFindingDir("H1-sqli", "---\nid: H1\nslug: sqli\nseverity: high\n---\n\nbody");
		writeFindingDir("M1-xss", "---\nid: M1\nslug: xss\nseverity: medium\n---\n\nbody");
		writeFindingDir("FP-C1-old", "---\nid: C1\nslug: old\nseverity: critical\n---\n\nbody");

		const text = buildAuditResultStatsLines(cwd, audit.audit_id, {
			nowMs: Date.parse("2026-05-01T01:02:03.000Z"),
		}).join("\n");

		expect(text).toContain("Audit duration: 1h 02m 03s");
		expect(text).toContain("Total findings: 2");
		expect(text).toContain("critical 0 | high 1 | medium 1 | low 0 | info 0");
	});

	it("falls back to directory ids when finalized draft frontmatter is malformed", () => {
		writeFindingDir(
			"H1-webhook-unwrap",
			[
				"---",
				"id: H1",
				"slug: webhook-unwrap",
				"severity: high",
				"Adversarial-Rationale: Real-SDK reproduction with `client.beta.webhooks.unwrap(...)`: confirmed",
				"---",
				"",
				"body",
			].join("\n"),
		);

		const text = buildAuditResultStatsLines(cwd, undefined, { nowMs: 0 }).join("\n");

		expect(text).toContain("Total findings: 1");
		expect(text).toContain("critical 0 | high 1 | medium 0 | low 0 | info 0");
	});

	it("falls back to draft findings when finalized findings are absent", () => {
		writeDraft("q1-001-secret.md", "---\nid: q1-001\nslug: secret\nseverity: high\n---\n\nbody");
		writeDraft("q2-001-bug.md", "---\nid: q2-001\nslug: bug\nseverity: low\n---\n\nbody");

		const text = buildAuditResultStatsLines(cwd, undefined, { nowMs: 0 }).join("\n");

		expect(text).toContain("Audit duration: unknown");
		expect(text).toContain("Total findings: 2");
		expect(text).toContain("critical 0 | high 1 | medium 0 | low 1 | info 0");
	});
});
