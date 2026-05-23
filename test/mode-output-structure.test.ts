import { describe, expect, it } from "vitest";
import {
	BALANCED_ADVISORY_SUMMARY,
	BALANCED_ATTACK_SURFACE_INVENTORY,
	BALANCED_CHAMBER_SUMMARY,
	BALANCED_CLEANUP_SUMMARY,
	BALANCED_CONSOLIDATION_MANIFEST,
	BALANCED_KB_REPORT,
	BALANCED_PROBE_SUMMARY,
	BALANCED_SAST_REPORT,
	BALANCED_VERIFICATION_SUMMARY,
} from "../extensions/piolium/modes/balanced.ts";
import { DIFF_SUMMARY } from "../extensions/piolium/modes/diff.ts";
import {
	Q1_SUMMARY,
	Q2_SUMMARY,
	Q3_CONSOLIDATION_MANIFEST,
	Q4_CLEANUP_SUMMARY,
	Q4_VERIFICATION_SUMMARY,
} from "../extensions/piolium/modes/lite.ts";
import {
	LONGSHOT_FINDINGS_DRAFT_DIR,
	LONGSHOT_SUMMARY_PATH,
	LONGSHOT_TARGETS_PATH,
} from "../extensions/piolium/modes/longshot.ts";
import { MERGE_ATTACK_SURFACE_SUMMARY } from "../extensions/piolium/modes/merge.ts";
import {
	REVISIT_PROBE_SUMMARY,
	REVISIT_R7_CHAMBER_SUMMARY,
	REVISIT_R8_CHAMBER_SUMMARY,
} from "../extensions/piolium/modes/revisit.ts";
import { RECON_REPORT_PATH } from "../extensions/piolium/recon.ts";

describe("mode output structure", () => {
	it("keeps lite durable summaries under attack-surface", () => {
		expect(RECON_REPORT_PATH).toBe("piolium/attack-surface/lite-recon.md");
		expect(Q1_SUMMARY).toBe("piolium/attack-surface/lite-q1-summary.md");
		expect(Q2_SUMMARY).toBe("piolium/attack-surface/lite-q2-summary.md");
		expect(Q3_CONSOLIDATION_MANIFEST).toBe("piolium/attack-surface/lite-consolidation-manifest.json");
		expect(Q4_VERIFICATION_SUMMARY).toBe("piolium/attack-surface/lite-verification-summary.md");
		expect(Q4_CLEANUP_SUMMARY).toBe("piolium/attack-surface/lite-cleanup-summary.json");
	});

	it("keeps balanced durable summaries under attack-surface", () => {
		expect(BALANCED_ADVISORY_SUMMARY).toBe("piolium/attack-surface/advisory-summary.md");
		expect(BALANCED_KB_REPORT).toBe("piolium/attack-surface/knowledge-base-report.md");
		expect(BALANCED_SAST_REPORT).toBe("piolium/attack-surface/source-sink-flows-all-severities.md");
		expect(BALANCED_ATTACK_SURFACE_INVENTORY).toBe(
			"piolium/attack-surface/manual-attack-surface-inventory.md",
		);
		expect(BALANCED_PROBE_SUMMARY).toBe("piolium/attack-surface/balanced-probe-summary.md");
		expect(BALANCED_CHAMBER_SUMMARY).toBe("piolium/attack-surface/balanced-chamber-summary.md");
		expect(BALANCED_VERIFICATION_SUMMARY).toBe(
			"piolium/attack-surface/balanced-verification-summary.md",
		);
		expect(BALANCED_CLEANUP_SUMMARY).toBe("piolium/attack-surface/balanced-cleanup-summary.json");
		expect(BALANCED_CONSOLIDATION_MANIFEST).toBe(
			"piolium/attack-surface/balanced-consolidation-manifest.json",
		);
	});

	it("keeps longshot durable artifacts under attack-surface and findings-draft", () => {
		expect(LONGSHOT_TARGETS_PATH).toBe("piolium/attack-surface/longshot-targets.json");
		expect(LONGSHOT_SUMMARY_PATH).toBe("piolium/attack-surface/longshot-summary.md");
		expect(LONGSHOT_FINDINGS_DRAFT_DIR).toBe("piolium/findings-draft");
	});

	it("keeps diff, revisit, and merge durable summaries under attack-surface", () => {
		expect(DIFF_SUMMARY).toBe("piolium/attack-surface/diff-summary.md");
		expect(REVISIT_PROBE_SUMMARY).toBe("piolium/attack-surface/revisit-probe-summary.md");
		expect(REVISIT_R7_CHAMBER_SUMMARY).toBe("piolium/attack-surface/revisit-r7-chamber-summary.md");
		expect(REVISIT_R8_CHAMBER_SUMMARY).toBe("piolium/attack-surface/revisit-r8-chamber-summary.md");
		expect(MERGE_ATTACK_SURFACE_SUMMARY).toBe("piolium/attack-surface/merge-summary.md");
	});
});
