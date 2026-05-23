import type { PhaseState, PhaseStatus } from "./audit-state.ts";
import { formatPhaseListLabel } from "./phase-labels.ts";

export interface PhaseStatusTheme {
	fg(color: string, text: string): string;
}

const PHASE_TOKEN =
	/\b(?:P\d+[A-Za-z]*|Q\d+[A-Za-z]*|L\d+[A-Za-z]*|V\d+[A-Za-z]*|R\d+[A-Za-z]*|M\d+[A-Za-z]*|X\d+[A-Za-z]*)\b/g;

export function extractStatusPhase(
	text: string | undefined,
	phases: readonly string[],
): string | undefined {
	if (!text) return undefined;
	for (const match of text.matchAll(PHASE_TOKEN)) {
		const phase = match[0];
		if (phases.includes(phase)) return phase;
	}
	return undefined;
}

export function renderPhaseStatusStrip(
	phases: readonly string[],
	phaseStates: Record<string, PhaseState>,
	currentPhase: string | undefined,
	theme: PhaseStatusTheme,
): string {
	return phases
		.map((phase) => {
			const status = phaseStates[phase]?.status ?? "pending";
			return formatPhaseToken(phase, status, currentPhase === phase, theme);
		})
		.join(" ");
}

export function renderPhaseStatusList(
	phases: readonly string[],
	phaseStates: Record<string, PhaseState>,
	currentPhase: string | undefined,
	theme: PhaseStatusTheme,
): string[] {
	return phases.map((phase, index) => {
		const status = phaseStates[phase]?.status ?? "pending";
		const marker = phaseMarker(status, currentPhase === phase);
		const label = formatPhaseListLabel(phase, index, phases.length);
		const text = `• ${marker} ${label}`;
		return theme.fg(phaseColor(status, currentPhase === phase), text);
	});
}

function formatPhaseToken(
	phase: string,
	status: PhaseStatus,
	isCurrent: boolean,
	theme: PhaseStatusTheme,
): string {
	if (status === "complete") return theme.fg("success", `✓${phase}`);
	if (status === "failed") return theme.fg("error", `✗${phase}`);
	if (status === "skipped") return theme.fg("warning", `↷${phase}`);
	if (status === "in_progress" || isCurrent) return theme.fg("accent", `●${phase}`);
	return theme.fg("dim", `·${phase}`);
}

function phaseMarker(status: PhaseStatus, isCurrent: boolean): string {
	if (status === "complete") return "✓";
	if (status === "failed") return "✗";
	if (status === "skipped") return "↷";
	if (status === "in_progress" || isCurrent) return "●";
	return "·";
}

function phaseColor(status: PhaseStatus, isCurrent: boolean): string {
	if (status === "complete") return "success";
	if (status === "failed") return "error";
	if (status === "skipped") return "warning";
	if (status === "in_progress" || isCurrent) return "accent";
	return "dim";
}
