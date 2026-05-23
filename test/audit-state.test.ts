import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	type AuditStateFile,
	applyPhaseStatus,
	formatAuditStatus,
	formatPhaseDetailLines,
	getAuditStatePath,
	initAudit,
	latestAudit,
	latestResumableAudit,
	markAuditStatus,
	mutateAuditState,
	readAuditState,
	setPhaseStatus,
	tallyPhases,
} from "../extensions/piolium/audit-state.ts";

let tmpRoot: string;

beforeEach(() => {
	tmpRoot = mkdtempSync(join(tmpdir(), "piolium-state-"));
});

afterEach(() => {
	rmSync(tmpRoot, { recursive: true, force: true });
});

describe("audit-state read", () => {
	it("returns exists:false when file is missing", () => {
		const result = readAuditState(tmpRoot);
		expect(result.exists).toBe(false);
		expect(result.path).toBe(getAuditStatePath(tmpRoot));
	});

	it("returns parseError for malformed JSON", () => {
		const path = getAuditStatePath(tmpRoot);
		mkdirSync(dirname(path), { recursive: true });
		writeFileSync(path, "{not json");
		const result = readAuditState(tmpRoot);
		expect(result.exists).toBe(true);
		expect(result.parseError).toBeDefined();
	});

	it("returns parseError when shape doesn't match", () => {
		const path = getAuditStatePath(tmpRoot);
		mkdirSync(dirname(path), { recursive: true });
		writeFileSync(path, JSON.stringify({ not: "audits" }));
		const result = readAuditState(tmpRoot);
		expect(result.exists).toBe(true);
		expect(result.parseError).toMatch(/audits/);
	});
});

describe("initAudit + setPhaseStatus", () => {
	it("creates a state file with the mode's default phase list", async () => {
		const run = await initAudit(tmpRoot, { mode: "lite" });
		expect(run.mode).toBe("lite");
		expect(run.status).toBe("in_progress");
		expect(Object.keys(run.phases).sort()).toEqual(["Q0", "Q1", "Q2", "Q3", "Q4"]);
		for (const phase of Object.values(run.phases)) {
			expect(phase.status).toBe("pending");
		}

		const onDisk = readAuditState(tmpRoot);
		expect(onDisk.state?.audits).toHaveLength(1);
	});

	it("transitions phase to in_progress and stamps started_at", async () => {
		const run = await initAudit(tmpRoot, { mode: "lite" });
		const updated = await setPhaseStatus(tmpRoot, run.audit_id, "Q0", { status: "in_progress" });
		expect(updated?.phases.Q0?.status).toBe("in_progress");
		expect(updated?.phases.Q0?.started_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
		expect(updated?.phases.Q0?.completed_at).toBeUndefined();
	});

	it("stamps completed_at on terminal states", async () => {
		const run = await initAudit(tmpRoot, { mode: "lite" });
		await setPhaseStatus(tmpRoot, run.audit_id, "Q0", { status: "in_progress" });
		const completed = await setPhaseStatus(tmpRoot, run.audit_id, "Q0", { status: "complete" });
		expect(completed?.phases.Q0?.completed_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);

		const failed = await setPhaseStatus(tmpRoot, run.audit_id, "Q1", {
			status: "failed",
			error: "trufflehog not found",
		});
		expect(failed?.phases.Q1?.completed_at).toBeDefined();
		expect(failed?.phases.Q1?.error).toBe("trufflehog not found");
	});

	it("returns undefined when audit_id does not exist", async () => {
		const result = await setPhaseStatus(tmpRoot, "nonexistent", "Q0", { status: "complete" });
		expect(result).toBeUndefined();
	});

	it("applyPhaseStatus mirrors the disk write onto the in-memory audit", async () => {
		const run = await initAudit(tmpRoot, { mode: "lite" });
		expect(run.phases.Q0?.status).toBe("pending");

		await applyPhaseStatus(tmpRoot, run, "Q0", { status: "in_progress" });
		expect(run.phases.Q0?.status).toBe("in_progress");
		expect(run.phases.Q0?.started_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);

		await applyPhaseStatus(tmpRoot, run, "Q0", { status: "complete" });
		expect(run.phases.Q0?.status).toBe("complete");
		expect(run.phases.Q0?.completed_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);

		const onDisk = readAuditState(tmpRoot);
		expect(onDisk.state?.audits[0]?.phases.Q0?.status).toBe("complete");
	});

	it("markAuditStatus moves the run to complete with completed_at", async () => {
		const run = await initAudit(tmpRoot, { mode: "lite" });
		const completed = await markAuditStatus(tmpRoot, run.audit_id, "complete");
		expect(completed?.status).toBe("complete");
		expect(completed?.completed_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
	});
});

describe("mutateAuditState", () => {
	it("serializes concurrent mutations on the same path", async () => {
		// 50 concurrent appends — without serialization, lost updates would
		// drop entries. The mutation queue + atomic rename guarantees all 50
		// land in the final state.
		const run = await initAudit(tmpRoot, { mode: "lite" });
		const mutations: Promise<unknown>[] = [];
		for (let i = 0; i < 50; i++) {
			mutations.push(
				mutateAuditState(tmpRoot, (state) => {
					const audit = state.audits.find((a) => a.audit_id === run.audit_id);
					if (!audit) return undefined;
					const counter = ((audit.phases.Q0?.artifacts as string[] | undefined) ?? []).length;
					return {
						...state,
						audits: state.audits.map((a) =>
							a.audit_id === run.audit_id
								? {
										...a,
										phases: {
											...a.phases,
											Q0: {
												...(a.phases.Q0 ?? { status: "pending" as const }),
												artifacts: [
													...((a.phases.Q0?.artifacts as string[] | undefined) ?? []),
													`artifact-${counter}`,
												],
											},
										},
									}
								: a,
						),
					};
				}),
			);
		}
		await Promise.all(mutations);
		const final = readAuditState(tmpRoot).state as AuditStateFile;
		const audit = final.audits.find((a) => a.audit_id === run.audit_id);
		expect(audit?.phases.Q0?.artifacts).toHaveLength(50);
	});

	it("recovers from a malformed file without destroying it", async () => {
		const path = getAuditStatePath(tmpRoot);
		mkdirSync(dirname(path), { recursive: true });
		writeFileSync(path, "garbage");
		await initAudit(tmpRoot, { mode: "lite" });

		// Fresh state is written...
		const parsed = JSON.parse(readFileSync(path, "utf8")) as AuditStateFile;
		expect(parsed.audits).toHaveLength(1);

		// ...but the corrupt original is preserved alongside it, not overwritten.
		const backups = readdirSync(dirname(path)).filter((f) =>
			f.startsWith("audit-state.json.corrupt-"),
		);
		expect(backups).toHaveLength(1);
		expect(readFileSync(join(dirname(path), backups[0] as string), "utf8")).toBe("garbage");
	});

	it("treats an empty file as fresh state without leaving a backup", async () => {
		const path = getAuditStatePath(tmpRoot);
		mkdirSync(dirname(path), { recursive: true });
		writeFileSync(path, "   \n");
		await initAudit(tmpRoot, { mode: "lite" });
		const backups = readdirSync(dirname(path)).filter((f) =>
			f.startsWith("audit-state.json.corrupt-"),
		);
		expect(backups).toEqual([]);
	});
});

describe("merge mode phase invariant", () => {
	// Mirrors the bookkeeping in modes/merge.ts: M1 is the deterministic copy,
	// a single agent pass covers M2-M7. A terminal audit must never leave a
	// merge phase stuck in pending/in_progress.
	it("leaves every phase terminal when the merge completes", async () => {
		const run = await initAudit(tmpRoot, { mode: "merge" });
		await applyPhaseStatus(tmpRoot, run, "M1", { status: "complete" });
		await applyPhaseStatus(tmpRoot, run, "M2", { status: "complete" });
		for (const p of ["M3", "M4", "M5", "M6", "M7"]) {
			await applyPhaseStatus(tmpRoot, run, p, { status: "complete" });
		}
		await markAuditStatus(tmpRoot, run.audit_id, "complete");

		const audit = latestAudit(readAuditState(tmpRoot).state as AuditStateFile);
		expect(audit?.status).toBe("complete");
		const tally = tallyPhases(audit as NonNullable<typeof audit>);
		expect(tally.pending).toBe(0);
		expect(tally.in_progress).toBe(0);
		expect(tally.complete).toBe(7);
	});

	it("skips downstream phases when the merge agent pass fails", async () => {
		const run = await initAudit(tmpRoot, { mode: "merge" });
		await applyPhaseStatus(tmpRoot, run, "M1", { status: "complete" });
		await applyPhaseStatus(tmpRoot, run, "M2", { status: "failed", error: "gate failed" });
		for (const p of ["M3", "M4", "M5", "M6", "M7"]) {
			await applyPhaseStatus(tmpRoot, run, p, { status: "skipped" });
		}
		await markAuditStatus(tmpRoot, run.audit_id, "failed");

		const audit = latestAudit(readAuditState(tmpRoot).state as AuditStateFile);
		expect(audit?.status).toBe("failed");
		const tally = tallyPhases(audit as NonNullable<typeof audit>);
		expect(tally.pending).toBe(0);
		expect(tally.in_progress).toBe(0);
		expect(tally.failed).toBe(1);
		expect(tally.skipped).toBe(5);
	});
});

describe("formatAuditStatus + tally", () => {
	it("produces multi-line summary with phase markers", async () => {
		const run = await initAudit(tmpRoot, { mode: "lite", model: "sonnet", repository: "demo/repo" });
		await setPhaseStatus(tmpRoot, run.audit_id, "Q0", { status: "complete" });
		await setPhaseStatus(tmpRoot, run.audit_id, "Q1", { status: "in_progress" });
		const state = readAuditState(tmpRoot).state as AuditStateFile;
		const lines = formatAuditStatus(state);
		const text = lines.join("\n");
		expect(text).toContain("Mode:      lite");
		expect(text).toContain("Repo:      demo/repo");
		expect(text).toContain("Q0");
		expect(text).toMatch(/✓.*Q0/);
		expect(text).toMatch(/….*Q1/);
	});

	it("surfaces failed phase error details", async () => {
		const lines = formatPhaseDetailLines([
			[
				"P6",
				{
					status: "failed",
					error: "Failed after 2 retries: Phase P6 gate failed — expected artifact missing.",
					attempt: 3,
					max_attempts: 3,
					last_error: "Phase P6 gate failed — expected artifact missing.",
					artifacts: ["piolium/tmp/piolium/runs/p6/transcript.jsonl"],
				},
			],
		]);
		const text = lines.join("\n");
		expect(text).toContain("P6");
		expect(text).toContain("Failed after 2 retries");
		expect(text).toContain("attempts: 3/3");
		expect(text).toContain("last error: Phase P6 gate failed");
		expect(text).toContain("artifacts: piolium/tmp/piolium/runs/p6/transcript.jsonl");
	});

	it("tally counts each status correctly", async () => {
		const run = await initAudit(tmpRoot, { mode: "deep" });
		await setPhaseStatus(tmpRoot, run.audit_id, "P1", { status: "complete" });
		await setPhaseStatus(tmpRoot, run.audit_id, "P2", { status: "complete" });
		await setPhaseStatus(tmpRoot, run.audit_id, "P3", { status: "in_progress" });
		await setPhaseStatus(tmpRoot, run.audit_id, "P4", { status: "failed" });
		await setPhaseStatus(tmpRoot, run.audit_id, "P5", { status: "skipped" });
		const state = readAuditState(tmpRoot).state as AuditStateFile;
		const audit = latestAudit(state);
		expect(audit).toBeDefined();
		const tally = tallyPhases(audit as NonNullable<typeof audit>);
		expect(tally.complete).toBe(2);
		expect(tally.in_progress).toBe(1);
		expect(tally.failed).toBe(1);
		expect(tally.skipped).toBe(1);
		expect(tally.pending).toBe(tally.total - 5);
	});
});

describe("latestResumableAudit", () => {
	it("returns undefined when no audits exist", () => {
		expect(latestResumableAudit({ audits: [] })).toBeUndefined();
	});

	it("returns undefined when every audit is complete", () => {
		const state: AuditStateFile = {
			audits: [
				{
					audit_id: "2026-05-13T00:00:00.000Z",
					mode: "lite",
					started_at: "2026-05-13T00:00:00.000Z",
					completed_at: "2026-05-13T00:30:00.000Z",
					status: "complete",
					phases: {},
				},
			],
		};
		expect(latestResumableAudit(state)).toBeUndefined();
	});

	it("prefers in_progress over a more recent failed audit", () => {
		const state: AuditStateFile = {
			audits: [
				{
					audit_id: "2026-05-13T01:00:00.000Z",
					mode: "balanced",
					started_at: "2026-05-13T01:00:00.000Z",
					status: "in_progress",
					phases: {},
				},
				{
					audit_id: "2026-05-13T02:00:00.000Z",
					mode: "deep",
					started_at: "2026-05-13T02:00:00.000Z",
					status: "failed",
					phases: {},
				},
			],
		};
		const picked = latestResumableAudit(state);
		expect(picked?.audit_id).toBe("2026-05-13T01:00:00.000Z");
		expect(picked?.mode).toBe("balanced");
	});

	it("falls back to failed when no in_progress exists", () => {
		const state: AuditStateFile = {
			audits: [
				{
					audit_id: "2026-05-13T01:00:00.000Z",
					mode: "lite",
					started_at: "2026-05-13T01:00:00.000Z",
					completed_at: "2026-05-13T01:30:00.000Z",
					status: "complete",
					phases: {},
				},
				{
					audit_id: "2026-05-13T02:00:00.000Z",
					mode: "balanced",
					started_at: "2026-05-13T02:00:00.000Z",
					status: "failed",
					phases: {},
				},
			],
		};
		expect(latestResumableAudit(state)?.audit_id).toBe("2026-05-13T02:00:00.000Z");
	});

	it("picks the most recent in_progress when multiple exist", () => {
		const state: AuditStateFile = {
			audits: [
				{
					audit_id: "2026-05-13T01:00:00.000Z",
					mode: "deep",
					started_at: "2026-05-13T01:00:00.000Z",
					status: "in_progress",
					phases: {},
				},
				{
					audit_id: "2026-05-13T03:00:00.000Z",
					mode: "balanced",
					started_at: "2026-05-13T03:00:00.000Z",
					status: "in_progress",
					phases: {},
				},
			],
		};
		expect(latestResumableAudit(state)?.audit_id).toBe("2026-05-13T03:00:00.000Z");
	});
});
