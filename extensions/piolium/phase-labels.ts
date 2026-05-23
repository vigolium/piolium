const PHASE_LABELS: Record<string, string> = {
	Q0: "Source Recon",
	Q1: "Secret Exposure Scan",
	Q2: "Fast Static Analysis",
	Q3: "Proof-of-Concept Construction",
	Q4: "Verification & Cleanup",
	L1: "Intelligence & Dependency Risk",
	L2: "Architecture & Threat Model",
	L3: "Static Analysis & Triage",
	L4: "Manual Attack Surface Probe",
	L5: "Adversarial Review & FP Check",
	L6: "Proof-of-Concept Construction",
	L6b: "Finding Report Drafting",
	L6c: "Final Report Assembly",
	L7: "Verification & Cleanup",
	P1: "Intelligence & Dependency Risk",
	P2: "Patch History & Bypass Review",
	P3: "Architecture & Threat Model",
	P4: "Static Analysis & Triage",
	P5: "Authorization & Access Control",
	P6: "State Machine & Concurrency",
	P7: "Spec, Framework & Parser Gaps",
	P8: "Manual Attack Surface Probe",
	P9: "Cross-Service Data Flow",
	P10: "Adversarial Review Chamber",
	P11: "False-Positive Verification",
	P12: "Variant Search",
	P13: "Proof-of-Concept Construction",
	P14: "Finding Report Drafting",
	P15: "Final Report Assembly",
	P16: "Finding Verification",
	P17: "Cleanup",
	V1: "Findings Inventory",
	"V1.5": "Intent Cross-Check",
	V2: "Environment Discovery",
	V3: "Environment Provisioning",
	V4: "Proof-of-Concept Execution",
	V5: "Test-Based Fallback",
	V6: "Confirmation Report",
	V7: "Cleanup & Redaction",
	R0: "Intent Cartography",
	R5: "Fresh Deep Probe",
	R7: "SAST Reclassification",
	R8: "Fresh Review Chambers",
	R9: "False-Positive Verification",
	R10: "New Finding Variants",
	R10k: "Known Finding Variants",
	R11: "Proof-of-Concept Construction",
	R11b: "Finding Report Drafting",
	R11c: "Final Report Assembly",
	M1: "Copy & Index",
	M2: "Semantic Deduplication",
	M3: "Metadata Auto-Fix",
	M4: "Quarantine Unfixable Findings",
	M5: "Severity Renumbering",
	M6: "Apply Finding Renames",
	M7: "Final Report Assembly",
	X1: "Target Enumeration",
	X2: "Per-File Hail-Mary Hunt",
	X3: "Finding Aggregation",
	I1: "Reinvest Scope Enumeration",
	I2: "Wave Verifier Fan-Out",
	I3: "Cross-Agent Consensus",
};

function basePhaseId(phase: string): string {
	return phase.split(":")[0] ?? phase;
}

function orderNumber(index: number, total: number, minWidth = 1): string {
	const width = Math.max(minWidth, total >= 10 ? 2 : 1);
	return String(index + 1).padStart(width, "0");
}

export function phaseLabel(phase: string): string {
	return PHASE_LABELS[phase] ?? PHASE_LABELS[basePhaseId(phase)] ?? "Phase";
}

export function formatPhaseListLabel(phase: string, index: number, total: number): string {
	const base = basePhaseId(phase);
	const phaseOrder = base.startsWith("P")
		? `P${orderNumber(index, total, 2)}`
		: orderNumber(index, total);
	return `${phaseOrder}. ${phaseLabel(phase)}`;
}

export function formatPhaseDetailLabel(phase: string, index: number, total: number): string {
	return `${formatPhaseListLabel(phase, index, total)} (${phase})`;
}
