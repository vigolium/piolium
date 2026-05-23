import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	consolidateDrafts,
	findingsDir,
	findingsDraftDir,
	isPromotableDraft,
	isRejectedDraft,
	listDraftFindings,
	listFindingDirs,
	parseFindingDirName,
	promoteDraftsByPrefix,
} from "../extensions/piolium/findings.ts";

let cwd: string;

beforeEach(() => {
	cwd = mkdtempSync(join(tmpdir(), "piolium-findings-"));
});

afterEach(() => {
	rmSync(cwd, { recursive: true, force: true });
});

function writeDraft(name: string, body: string): void {
	const dir = findingsDraftDir(cwd);
	mkdirSync(dir, { recursive: true });
	writeFileSync(join(dir, name), body);
}

describe("listDraftFindings", () => {
	it("filters by prefix", () => {
		writeDraft(
			"p8-001-sql-injection.md",
			"---\nid: p8-001\nphase: L5\nslug: sql-injection\nseverity: high\n---\n\nDetails.",
		);
		writeDraft(
			"q1-002-secret.md",
			"---\nid: q1-002\nphase: Q1\nslug: secret\nseverity: medium\n---\n\nDetails.",
		);
		const all = listDraftFindings(cwd);
		expect(all).toHaveLength(2);
		const filtered = listDraftFindings(cwd, "p8-");
		expect(filtered).toHaveLength(1);
		expect(filtered[0]?.id).toBe("p8-001");
	});

	it("normalises severity", () => {
		writeDraft("p8-001-x.md", "---\nid: p8-001\nphase: L5\nslug: x\nseverity: SuperHigh\n---\n\nb");
		const drafts = listDraftFindings(cwd);
		expect(drafts[0]?.severity).toBe("info");
	});
});

describe("promoteDraftsByPrefix", () => {
	it("creates findings/<id>-<slug>/draft.md once and is idempotent", () => {
		writeDraft(
			"p8-001-sql-injection.md",
			"---\nid: p8-001\nphase: L5\nslug: sql-injection\nseverity: high\n---\n\nDetails of finding.",
		);
		const r1 = promoteDraftsByPrefix(cwd, "p8-");
		expect(r1.promoted).toHaveLength(1);
		expect(r1.skipped).toHaveLength(0);
		const findingDir = join(findingsDir(cwd), "p8-001-sql-injection");
		const draft = readFileSync(join(findingDir, "draft.md"), "utf8");
		expect(draft).toContain("severity: high");
		expect(draft).toContain("Details of finding.");
		const r2 = promoteDraftsByPrefix(cwd, "p8-");
		expect(r2.promoted).toHaveLength(0);
		expect(r2.skipped).toHaveLength(1);
	});
});

describe("listFindingDirs", () => {
	it("reports report/poc/evidence presence", () => {
		const dir = join(findingsDir(cwd), "p8-001-x");
		mkdirSync(dir, { recursive: true });
		writeFileSync(join(dir, "draft.md"), "ok");
		writeFileSync(join(dir, "report.md"), "x".repeat(600));
		writeFileSync(join(dir, "poc.py"), "print(1)");
		mkdirSync(join(dir, "evidence"));
		const dirs = listFindingDirs(cwd);
		expect(dirs).toHaveLength(1);
		expect(dirs[0]?.hasReport).toBe(true);
		expect(dirs[0]?.hasPoc).toBe(true);
		expect(dirs[0]?.hasEvidence).toBe(true);
	});

	it("parses severity-prefixed and FP-prefixed dir names", () => {
		expect(parseFindingDirName("H1-sql-injection")).toEqual({
			id: "H1",
			slug: "sql-injection",
		});
		expect(parseFindingDirName("C1-aws-key")).toEqual({ id: "C1", slug: "aws-key" });
		expect(parseFindingDirName("M2-weak-crypto")).toEqual({ id: "M2", slug: "weak-crypto" });
		expect(parseFindingDirName("p8-001-idor")).toEqual({ id: "p8-001", slug: "idor" });
		expect(parseFindingDirName("FP-H1-bogus")).toEqual({ id: "FP-H1", slug: "bogus" });
		expect(parseFindingDirName("FP-p8-001-idor")).toEqual({
			id: "FP-p8-001",
			slug: "idor",
		});
	});
});

describe("consolidateDrafts", () => {
	it("assigns severity-prefixed IDs and drops low/info", () => {
		writeDraft(
			"q2-001-sqli.md",
			"---\nid: q2-001\nphase: Q2\nslug: sqli\nseverity: high\n---\n\nHigh severity finding.",
		);
		writeDraft(
			"q2-002-aws-key.md",
			"---\nid: q2-002\nphase: Q2\nslug: aws-key\nseverity: critical\n---\n\nCritical finding.",
		);
		writeDraft(
			"q2-003-info-only.md",
			"---\nid: q2-003\nphase: Q2\nslug: info-only\nseverity: info\n---\n\nInfo only.",
		);
		writeDraft(
			"q1-001-token.md",
			"---\nid: q1-001\nphase: Q1\nslug: token\nseverity: medium\n---\n\nMedium.",
		);

		const result = consolidateDrafts(cwd, ["q1-", "q2-"]);

		expect(result.promoted.map((p) => p.id)).toEqual(["C1", "H1", "M1"]);
		expect(result.dropped).toHaveLength(1);
		expect(result.dropped[0]?.originalId).toBe("q2-003");

		const findingC1 = join(findingsDir(cwd), "C1-aws-key");
		const draftC1 = readFileSync(join(findingC1, "draft.md"), "utf8");
		expect(draftC1).toContain("id: C1");
		expect(draftC1).toContain("original_id: q2-002");
		expect(draftC1).toContain("severity: critical");
		// evidence/ subdir created so poc-builder can drop logs.
		expect(existsSync(join(findingC1, "evidence"))).toBe(true);
	});

	it("is idempotent for matching <ID>-<slug> directories", () => {
		writeDraft("q2-001-x.md", "---\nid: q2-001\nphase: Q2\nslug: x\nseverity: high\n---\n\nx.");
		const r1 = consolidateDrafts(cwd, ["q2-"]);
		expect(r1.promoted).toHaveLength(1);
		const r2 = consolidateDrafts(cwd, ["q2-"]);
		expect(r2.promoted).toHaveLength(1);
		expect(r2.promoted[0]?.id).toBe("H1");
		expect(r2.promoted[0]?.findingDir).toBe(r1.promoted[0]?.findingDir);
	});

	it("drops rejected drafts with reason 'rejected' even at high severity", () => {
		writeDraft(
			"q2-001-fp.md",
			"---\nid: q2-001\nphase: Q2\nslug: fp\nseverity: high\nconfirm_status: false-positive\n---\n\nDisproven.",
		);
		writeDraft(
			"q2-002-real.md",
			"---\nid: q2-002\nphase: Q2\nslug: real\nseverity: high\n---\n\nReal finding.",
		);
		const result = consolidateDrafts(cwd, ["q2-"]);
		// Only the genuine high-severity finding is promoted.
		expect(result.promoted.map((p) => p.id)).toEqual(["H1"]);
		expect(result.promoted[0]?.findingDir).toContain("real");
		const rejected = result.dropped.find((d) => d.originalId === "q2-001");
		expect(rejected?.reason).toBe("rejected");
	});
});

describe("isRejectedDraft / isPromotableDraft", () => {
	it("flags rejection via any of the recognised frontmatter keys", () => {
		writeDraft(
			"q2-001-fp.md",
			"---\nid: q2-001\nslug: fp\nseverity: high\nConfirm-Status: false-positive\n---\n\nx",
		);
		writeDraft(
			"q2-002-status.md",
			"---\nid: q2-002\nslug: s\nseverity: high\nstatus: rejected\n---\n\nx",
		);
		writeDraft("q2-003-ok.md", "---\nid: q2-003\nslug: ok\nseverity: high\n---\n\nx");
		const byId = new Map(listDraftFindings(cwd, "q2-").map((d) => [d.id, d]));
		const fp = byId.get("q2-001");
		const status = byId.get("q2-002");
		const ok = byId.get("q2-003");
		expect(fp && isRejectedDraft(fp)).toBe(true);
		expect(status && isRejectedDraft(status)).toBe(true);
		expect(ok && isRejectedDraft(ok)).toBe(false);
		// promotable = not rejected AND severity >= medium
		expect(ok && isPromotableDraft(ok)).toBe(true);
		expect(fp && isPromotableDraft(fp)).toBe(false);
	});

	it("does not promote low/info severity even when not rejected", () => {
		writeDraft("q2-010-low.md", "---\nid: q2-010\nslug: low\nseverity: low\n---\n\nx");
		const [low] = listDraftFindings(cwd, "q2-010");
		expect(low && isRejectedDraft(low)).toBe(false);
		expect(low && isPromotableDraft(low)).toBe(false);
	});
});
