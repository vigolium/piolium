/**
 * Mode → phase list registry.
 *
 * Stored phase keys are a persisted on-disk contract: `audit-state.json`
 * files reference them, so they must stay stable across versions and any
 * interoperating tooling — don't rename them. User-facing output renders
 * these keys as ordered stage labels via phase-labels.ts.
 *
 * Phase order per mode:
 *   - lite: command-defs/lite.md + piolium cleanup (Q0 → [Q1+Q2] → Q3 promote+poc → Q4 cleanup)
 *   - balanced: command-defs/balanced.md + piolium cleanup (L1 → L2 → [L3+L4] → L5 → L6 → L6b → L6c → L7)
 *   - deep: command-defs/deep.md + piolium verification + cleanup (P1 → P2 → P3 → P4 → [P5+P6+P7] → P8 → P9 → P10 → P11 → P12 → P13 → P14 → P15 → P16 → P17)
 *   - revisit: command-defs/revisit.md (R0 intent cartography → R5 → R7 → R8 → R9 → R10 → R10k → R11 → R11b → R11c)
 *   - confirm: command-defs/confirm.md (V1 → V1.5 intent cross-check → V2..V6) + piolium V7 cleanup/redaction
 *   - merge: M1 deterministic copy + M2..M7 agent-driven dedup/renumber/report (records an audit run)
 *   - diff: dynamically derived from change set; see modes/diff.ts when it lands
 *   - longshot: piolium-only hail-mary — X1 enumerate → X2 hunt fan-out → X3 aggregate
 *   - reinvest: cross-agent re-verification of CRIT/HIGH findings — I1 enumerate → I2 wave-verifier fan-out (cap 3) → I3 consensus summary
 */

import type { AuditMode } from "./audit-state.ts";

export const MODE_PHASES: Record<AuditMode, readonly string[]> = {
	lite: ["Q0", "Q1", "Q2", "Q3", "Q4"],
	balanced: ["L1", "L2", "L3", "L4", "L5", "L6", "L6b", "L6c", "L7"],
	deep: [
		"P1",
		"P2",
		"P3",
		"P4",
		"P5",
		"P6",
		"P7",
		"P8",
		"P9",
		"P10",
		"P11",
		"P12",
		"P13",
		"P14",
		"P15",
		"P16",
		"P17",
	],
	diff: [],
	confirm: ["V1", "V1.5", "V2", "V3", "V4", "V5", "V6", "V7"],
	revisit: ["R0", "R5", "R7", "R8", "R9", "R10", "R10k", "R11", "R11b", "R11c"],
	merge: ["M1", "M2", "M3", "M4", "M5", "M6", "M7"],
	longshot: ["X1", "X2", "X3"],
	reinvest: ["I1", "I2", "I3"],
};

export function phasesFor(mode: AuditMode): readonly string[] {
	return MODE_PHASES[mode];
}
