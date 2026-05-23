interface CommandHelp {
	command: string;
	usage: string;
	does: string;
	example: string;
}

interface FlagHelp {
	flag: string;
	does: string;
	example: string;
}

export const PIOLIUM_STARTUP_HINT =
	"Piolium loaded. Run /piolium-help for usage and flags, or start auditing this repo with /piolium-balanced.";

const COMMANDS: CommandHelp[] = [
	{
		command: "/piolium-status",
		usage: "/piolium-status [path]",
		does: "Shows current audit progress from piolium/audit-state.json.",
		example: 'pi -p "/piolium-status"',
	},
	{
		command: "/piolium-resume",
		usage: "/piolium-resume [path]",
		does: "Resumes the most recent in-progress or failed audit in this directory.",
		example: 'pi -p "/piolium-resume"',
	},
	{
		command: "/piolium-export",
		usage:
			"/piolium-export [path] [--format=json|md-dir] [--min-severity=high] [--confirmed-only] [--exclude-fp]",
		does: "Exports finalized findings with filters and CODEOWNERS-derived owner labels.",
		example: 'pi -p "/piolium-export --min-severity=high --exclude-fp"',
	},
	{
		command: "/piolium-learn",
		usage: "/piolium-learn [path] [--apply]",
		does: "Suggests project-local candidate matchers from finalized findings.",
		example: 'pi -p "/piolium-learn --apply"',
	},
	{
		command: "/piolium-smoke",
		usage: "/piolium-smoke [path] [prompt]",
		does: "Runs a tiny agent to verify provider/auth/runner wiring before a real audit.",
		example: 'pi -p "/piolium-smoke check runner"',
	},
	{
		command: "/piolium-lite",
		usage: "/piolium-lite [path] [--fresh]",
		does: "Runs quick source recon, secret scanning, fast SAST, and cleanup.",
		example: 'pi -p "/piolium-lite --fresh"',
	},
	{
		command: "/piolium-balanced",
		usage: "/piolium-balanced [path] [--fresh]",
		does:
			"Runs the default audit pipeline with threat modeling, SAST, probes, PoCs, reports, and cleanup.",
		example: 'pi --plm-dir /path/to/repo -p "/piolium-balanced --fresh"',
	},
	{
		command: "/piolium-deep",
		usage: "/piolium-deep [path] [--fresh] [P1..P17]",
		does: "Runs the full deep pipeline, or reruns selected deep phases when phase ids are supplied.",
		example: 'pi --plm-scan-limit 250 -p "/piolium-deep --fresh"',
	},
	{
		command: "/piolium-confirm",
		usage: "/piolium-confirm [path] [--fresh] [https://target]",
		does: "Confirms existing findings against a live app or generated tests.",
		example: 'pi -p "/piolium-confirm https://staging.example.test"',
	},
	{
		command: "/piolium-diff",
		usage: "/piolium-diff [path] [--since=<sha>]",
		does: "Audits files changed since a prior commit or the last completed audit.",
		example: 'pi --plm-since abc123 -p "/piolium-diff"',
	},
	{
		command: "/piolium-revisit",
		usage: "/piolium-revisit [path] [--fresh]",
		does: "Runs an anti-anchored second pass over an existing completed audit.",
		example: 'pi -p "/piolium-revisit --fresh"',
	},
	{
		command: "/piolium-merge",
		usage: "/piolium-merge [path] --dir=<tree> --dir=<tree>",
		does: "Merges and deduplicates multiple piolium result trees into one canonical output.",
		example: 'pi -p "/piolium-merge --dir=run-a/piolium --dir=run-b/piolium"',
	},
	{
		command: "/piolium-longshot",
		usage: "/piolium-longshot [path] [--fresh] [--limit=N] [--timeout=ms] [--langs=a,b]",
		does: "Runs a broad file-by-file vulnerability hunt for high-recall bug discovery.",
		example: 'pi --plm-longshot-limit 200 --plm-longshot-langs python,go -p "/piolium-longshot"',
	},
	{
		command: "/piolium-reinvest",
		usage: "/piolium-reinvest [path] [--fresh] [--scope=C1,H1,H3]",
		does:
			"Cross-agent re-verification of CRIT/HIGH findings; writes piolium/reinvest-report.md without mutating any existing audit artefact.",
		example: 'pi -p "/piolium-reinvest --scope=C1,H1"',
	},
];

const CLI_FLAGS: FlagHelp[] = [
	{
		flag: "--plm-dir <path>",
		does: "Sets the default target directory for /piolium-* commands.",
		example: 'pi --plm-dir /path/to/repo -p "/piolium-balanced"',
	},
	{
		flag: "--plm-since <sha>",
		does: "Sets the default base commit for /piolium-diff.",
		example: 'pi --plm-since abc123 -p "/piolium-diff"',
	},
	{
		flag: "--plm-scan-limit <N>",
		does: "Caps history-aware phases to N commits. Default: 500.",
		example: 'pi --plm-scan-limit 250 -p "/piolium-deep"',
	},
	{
		flag: '--plm-scan-since "<git since expression>"',
		does: 'Caps history-aware phases to a git --since window. Default: "60 days ago".',
		example: 'pi --plm-scan-since "90 days ago" -p "/piolium-deep"',
	},
	{
		flag: "--plm-file-records <1|true>",
		does: "Writes piolium/file-records per-file candidate records. Default: off.",
		example: 'pi --plm-file-records true -p "/piolium-deep"',
	},
	{
		flag: "--plm-phase-retries <N>",
		does: "Sets retries after the first attempt for phase agents. Default: 5.",
		example: 'pi --plm-phase-retries 5 -p "/piolium-balanced"',
	},
	{
		flag: "--plm-phase-backoff <ms>",
		does: "Sets phase retry base backoff in milliseconds. Default: 5000.",
		example: 'pi --plm-phase-backoff 10000 -p "/piolium-balanced"',
	},
	{
		flag: "--plm-phase-backoff-max <ms>",
		does: "Sets phase retry max backoff in milliseconds. Default: 120000.",
		example: 'pi --plm-phase-backoff-max 180000 -p "/piolium-balanced"',
	},
	{
		flag: "--plm-lite-retries <N>",
		does: "Overrides retries for deterministic lite Q0/Q1 phases. Default: phase retries.",
		example: 'pi --plm-lite-retries 1 -p "/piolium-lite"',
	},
	{
		flag: "--plm-lite-backoff <ms>",
		does: "Overrides retry base backoff for deterministic lite Q0/Q1 phases.",
		example: 'pi --plm-lite-backoff 10000 -p "/piolium-lite"',
	},
	{
		flag: "--plm-lite-backoff-max <ms>",
		does: "Overrides retry max backoff for deterministic lite Q0/Q1 phases.",
		example: 'pi --plm-lite-backoff-max 180000 -p "/piolium-lite"',
	},
	{
		flag: "--plm-command-retries <N>",
		does: "Sets retries after the first attempt for top-level /piolium-* commands. Default: 3.",
		example: 'pi --plm-command-retries 3 -p "/piolium-balanced"',
	},
	{
		flag: "--plm-command-backoff <ms>",
		does: "Sets command retry base backoff in milliseconds. Default: 5000.",
		example: 'pi --plm-command-backoff 10000 -p "/piolium-balanced"',
	},
	{
		flag: "--plm-command-backoff-max <ms>",
		does: "Sets command retry max backoff in milliseconds. Default: 120000.",
		example: 'pi --plm-command-backoff-max 180000 -p "/piolium-balanced"',
	},
	{
		flag: "--plm-longshot-limit <N>",
		does: "Caps the number of source files hunted by /piolium-longshot. Default: 1000.",
		example: 'pi --plm-longshot-limit 200 -p "/piolium-longshot"',
	},
	{
		flag: "--plm-longshot-timeout <ms>",
		does: "Sets /piolium-longshot per-file timeout. Default: 21600000.",
		example: 'pi --plm-longshot-timeout 900000 -p "/piolium-longshot"',
	},
	{
		flag: "--plm-longshot-langs <csv>",
		does: "Restricts /piolium-longshot to a comma-separated language allowlist.",
		example: 'pi --plm-longshot-langs python,go -p "/piolium-longshot"',
	},
	{
		flag: "--plm-longshot-include-tests <true|false>",
		does: "Includes test files in /piolium-longshot enumeration when set to true.",
		example: 'pi --plm-longshot-include-tests true -p "/piolium-longshot"',
	},
];

export function buildPioliumHelpLines(): string[] {
	const lines: string[] = [
		"Piolium help",
		"",
		"Start here:",
		"  /piolium-balanced [path] [--fresh]",
		"    Default audit path for most repositories.",
		"  /piolium-help",
		"    Shows this helper.",
		"",
		"Slash commands:",
	];

	for (const command of COMMANDS) {
		lines.push(
			`  ${command.command}`,
			`    Usage:   ${command.usage}`,
			`    Does:    ${command.does}`,
			`    Example: ${command.example}`,
		);
	}

	lines.push("", "CLI session flags:");
	for (const flag of CLI_FLAGS) {
		lines.push(`  ${flag.flag}`, `    Does:    ${flag.does}`, `    Example: ${flag.example}`);
	}

	lines.push(
		"",
		"Command-local arguments win over session flags.",
		'Example: pi --plm-dir /repo-a -p "/piolium-balanced /repo-b --fresh" audits /repo-b.',
	);

	return lines;
}
