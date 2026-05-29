# Piolium Phase Reference

This document describes the implemented `/piolium-*` commands, what each phase
does, and the main files each phase writes. All output paths are relative to
the target repository directory.

The package name is Piolium. The slash command prefix implemented by the
extension is `/piolium-*`.

## Common outputs

Most audit commands write these shared artifacts:

| Path | Purpose |
| --- | --- |
| `piolium/audit-state.json` | Resumable run state, phase status, retry metadata, repository identity, and completion status. |
| `piolium/attack-surface/` | Durable audit context such as recon summaries, knowledge base files, SAST summaries, probe summaries, and phase reports. |
| `piolium/attack-surface/candidates.jsonl` | Ranked deterministic candidate matches consumed by SAST, probe, diff, revisit, and longshot phases. |
| `piolium/file-records/` | Per-source-file scan records with hash, candidate count, and risk score. |
| `piolium/findings-draft/` | Candidate findings before promotion into final finding directories. |
| `piolium/findings/<id>-<slug>/` | Finalized finding directories containing `draft.md`, PoC artifacts, evidence, and `report.md`. |
| `piolium/final-audit-report.md` | Consolidated final audit report for balanced, deep, revisit, and merge workflows. |
| `piolium/confirm-workspace/` | Confirmation, cleanup, and redaction workspace. |

## Commands without audit phases

| Command | Usage | What it does | Outputs |
| --- | --- | --- | --- |
| `/piolium-status` | `/piolium-status [path]` | Reads current audit progress for the target directory. | Displays `piolium/audit-state.json` status, or a "no audit state" message. |
| `/piolium-export` | `/piolium-export [path] [--format=json\|md-dir] [--min-severity=high] [--confirmed-only] [--exclude-fp]` | Exports finalized findings with severity, confirmation, FP, since, and owner filters. | `piolium/exports/findings-*.json` or a markdown export directory. |
| `/piolium-learn` | `/piolium-learn [path] [--apply]` | Generates project-local matcher suggestions from finalized findings; `--apply` merges them into `piolium/matchers.json`. | `piolium/attack-surface/matcher-suggestions.json`; optional `piolium/matchers.json`. |
| `/piolium-smoke` | `/piolium-smoke [path] [prompt]` | Runs a tiny inline agent through the same runner used by real audit phases. | `piolium/tmp/piolium/runs/smoke-*/` transcript and result files. |

## `/piolium-lite`

Usage: `/piolium-lite [path] [--fresh]`

Phase count: 5 (`Q0`-`Q4`)

| Phase | Name | What it does | Main outputs |
| --- | --- | --- | --- |
| `Q0` | Source Recon | Detects languages, frameworks, manifests, likely entry points, git state, scan exclusions, and deterministic candidate matches. | `piolium/attack-surface/lite-recon.md`; `piolium/attack-surface/candidates-summary.md`; `piolium/attack-surface/candidates.jsonl`; `piolium/file-records/` |
| `Q1` | Secret Exposure Scan | Runs `trufflehog`, `gitleaks`, or fallback pattern scans for exposed secrets. | `piolium/attack-surface/lite-q1-summary.md`; `piolium/findings-draft/q1-<NNN>-<slug>.md` |
| `Q2` | Fast Static Analysis | Runs a tight, high-signal static pass for issues such as command injection, traversal, SSRF, broken auth, hardcoded crypto, and weak authn/z. | `piolium/attack-surface/lite-q2-summary.md`; `piolium/findings-draft/q2-<NNN>-<slug>.md` |
| `Q3` | Proof-of-Concept Construction | Consolidates `q1-*`/`q2-*` drafts into severity-prefixed `findings/<C\|H\|M><N>-<slug>/draft.md` (drops low/info), then dispatches one `poc-builder` agent per finding to produce `poc.*` and `evidence/`. | `piolium/attack-surface/lite-consolidation-manifest.json`; `piolium/findings/<id>-<slug>/draft.md`; `piolium/findings/<id>-<slug>/poc.*` (or `poc.theoretical.md`); `piolium/findings/<id>-<slug>/evidence/` |
| `Q4` | Verification & Cleanup | Checks final finding folders and removes transient lite-run artifacts while retaining draft evidence and durable context. | `piolium/attack-surface/lite-verification-summary.md`; `piolium/attack-surface/lite-cleanup-summary.json` |

## `/piolium-balanced`

Usage: `/piolium-balanced [path] [--fresh]`

Phase count: 9 (`L1`-`L7`, including `L6b` and `L6c`)

| Phase | Name | What it does | Main outputs |
| --- | --- | --- | --- |
| `L1` | Intelligence & Dependency Risk | Gathers published advisories, dependency intelligence, repository identity, and architecture hints. | `piolium/attack-surface/advisory-summary.md` |
| `L2` | Architecture & Threat Model | Builds a compact knowledge base with project type, trust boundaries, DFD/CFD slices, attack modes, and coverage gaps. | `piolium/attack-surface/knowledge-base-report.md` |
| `L3` | Static Analysis & Triage | Runs the cheapest available static analysis and records source/sink issues. | `piolium/attack-surface/source-sink-flows-all-severities.md`; `piolium/findings-draft/p4-<NNN>-<slug>.md` |
| `L4` | Manual Attack Surface Probe | Picks high-impact slices, traces entry points and sinks, and verifies hypotheses with file/line evidence. | `piolium/attack-surface/manual-attack-surface-inventory.md`; `piolium/attack-surface/balanced-probe-summary.md`; `piolium/findings-draft/l4-<NNN>-<slug>.md` |
| `L5` | Adversarial Review & FP Check | Reviews SAST and probe drafts, marks weak findings as rejected, normalizes survivors, then consolidates valid `p8-*` drafts into severity-prefixed `findings/<C\|H\|M><N>-<slug>/` directories (drops low/info and rejected drafts). | `piolium/attack-surface/balanced-chamber-summary.md`; `piolium/attack-surface/balanced-consolidation-manifest.json`; `piolium/findings-draft/p8-<NNN>-<slug>.md`; `piolium/findings/<id>-<slug>/draft.md` |
| `L6` | Proof-of-Concept Construction | Builds a PoC or theoretical PoC for each promoted finding. | `piolium/findings/<id>-<slug>/poc.*` or `poc.theoretical.md`; `piolium/findings/<id>-<slug>/evidence/` |
| `L6b` | Finding Report Drafting | Turns each finding, PoC, and evidence bundle into a disclosure-style report. | `piolium/findings/<id>-<slug>/report.md` |
| `L6c` | Final Report Assembly | Verifies every finding has a report and writes the consolidated report. | `piolium/final-audit-report.md` |
| `L7` | Verification & Cleanup | Checks final finding folders and removes transient balanced workspaces. | `piolium/attack-surface/balanced-verification-summary.md`; `piolium/attack-surface/balanced-cleanup-summary.json` |

## `/piolium-deep`

Usage: `/piolium-deep [path] [--fresh] [P1..P17]`

Phase count: 17 (`P1`-`P17`)

You can pass one or more phase ids, such as `/piolium-deep P5`, to rerun
selected deep stages after their prerequisites exist.

| Phase | Name | What it does | Main outputs |
| --- | --- | --- | --- |
| `P1` | Intelligence & Dependency Risk | Gathers advisory, dependency, and architecture risk context. | `piolium/attack-surface/advisory-summary.md` |
| `P2` | Patch History & Bypass Review | Reviews security-relevant history and checks whether prior fixes can be bypassed. Skips when git history is unavailable. | `piolium/attack-surface/patch-bypass-summary.md` |
| `P3` | Architecture & Threat Model | Builds the deep knowledge base and reusable entry point inventory. | `piolium/attack-surface/knowledge-base-report.md`; `piolium/attack-surface/architecture-entrypoints.md` |
| `P4` | Static Analysis & Triage | Runs CodeQL/Semgrep when available or fallback static analysis, then records source-to-sink flows and candidate findings. | `piolium/attack-surface/source-sink-flows-all-severities.md`; `piolium/findings-draft/p4-<NNN>-<slug>.md` |
| `P5` | Authorization & Access Control | Enumerates public routes or operations and records expected versus actual authorization checks. | `piolium/attack-surface/public-routes-authz-matrix.md`; `piolium/findings-draft/p5-<NNN>-<slug>.md` |
| `P6` | State Machine & Concurrency | Looks for race conditions, TOCTOU, idempotency gaps, double-spend paths, and state-ordering issues. | `piolium/attack-surface/state-concurrency-summary.md`; `piolium/findings-draft/p6-<NNN>-<slug>.md` |
| `P7` | Specification, Framework Contract & Parser Gaps | Compares implementation behavior to specs, RFCs, parser expectations, framework contracts, middleware/proxy assumptions, and hidden control channels such as internal or reserved headers. | `piolium/attack-surface/spec-gap-summary.md`; `piolium/findings-draft/p7-<NNN>-<slug>.md` |
| `P8` | Manual Attack Surface Probe | Performs deeper manual hypothesis generation and evidence tracing against high-impact slices. | `piolium/attack-surface/manual-attack-surface-inventory.md`; `piolium/attack-surface/deep-probe-summary.md`; `piolium/findings-draft/p8-<NNN>-<slug>.md` |
| `P9` | Cross-Service Data Flow | Traces service boundaries and cross-component trust assumptions, or records that the repo is single-service. | `piolium/attack-surface/cross-service-edges.json`; `piolium/attack-surface/cross-service-edges.md`; `piolium/findings-draft/p9-<NNN>-<slug>.md` |
| `P10` | Adversarial Review Chamber | Clusters drafts, challenges each finding, marks false positives as rejected, and promotes valid survivors. | `piolium/chamber-workspace/index.md`; `piolium/chamber-workspace/<cluster-id>/debate.md`; `piolium/findings-draft/p10-<NNN>-<slug>.md`; `piolium/findings/<id>-<slug>/draft.md` |
| `P11` | False-Positive Verification | Performs cold verification for critical and high risk survivors and records adversarial reviews. | `piolium/adversarial-reviews/<id>.md`; updated finding draft status |
| `P12` | Variant Search | Searches for structurally similar variants of surviving findings. | `piolium/variant-summary.md`; `piolium/findings-draft/p12-<NNN>-<slug>.md`; `piolium/findings/<id>-<slug>/draft.md` |
| `P13` | Proof-of-Concept Construction | Builds PoC artifacts and evidence for each final finding. | `piolium/findings/<id>-<slug>/poc.*` or `poc.theoretical.md`; `piolium/findings/<id>-<slug>/evidence/` |
| `P14` | Finding Report Drafting | Writes per-finding disclosure reports from each draft, PoC, and evidence bundle. | `piolium/findings/<id>-<slug>/report.md` |
| `P15` | Final Report Assembly | Verifies per-finding reports and writes the consolidated audit report. | `piolium/final-audit-report.md` |
| `P16` | Finding Verification | Runs confirmation-style verification where findings exist, writes confirmation evidence, and redacts sensitive evidence. | `piolium/confirmation-report.md` when findings are confirmed; `piolium/confirm-workspace/cleanup-summary.json` |
| `P17` | Cleanup | Removes transient deep workspaces and tool artifacts after verification and final report assembly. | `piolium/attack-surface/deep-cleanup-summary.json` |

## `/piolium-confirm`

Usage: `/piolium-confirm [path] [--fresh] [https://target]`

Phase count: 7 (`V1`-`V7`)

When a remote URL is supplied, local environment discovery/provisioning is
skipped and the URL is treated as the already-running target. Remote mode also
skips local test fallback.

Before V1, the orchestrator runs a deterministic **report-repair** pass: any
finding directory that has a `draft.md` but no usable `report.md` (missing or
≤500 bytes) gets a `finding-reporter` spawned to author its `report.md`, so
theoretical and partially-finalized findings are confirmable. Unrepairable
candidates are recorded in `repair-summary.json` and surfaced by V6 as `error`
— they never abort the run.

| Phase | Name | What it does | Main outputs |
| --- | --- | --- | --- |
| `V1` | Findings Inventory + Report Repair | Repairs missing/truncated `report.md` from `draft.md` via `finding-reporter`, then reads each `piolium/findings/*/report.md` (draft fallback when repair failed), classifies findings, extracts PoC paths and metadata, records `source_kind`/`poc_kind`, and sorts by severity. | `piolium/confirm-workspace/repair-summary.json`; `piolium/confirm-workspace/findings-inventory.json` |
| `V2` | Environment Discovery | Discovers startup strategies, ports, env vars, datastores, migrations, test framework, and optional auth scaffolding. | `piolium/confirm-workspace/env-strategies.json`; `piolium/confirm-workspace/auth-spec.json` when auth is detected |
| `V3` | Environment Provisioning | Starts or prepares the target locally, seeds test identities when possible, and records connection details. | `piolium/confirm-workspace/env-connection.json` or `piolium/confirm-workspace/healthcheck-failure.log` |
| `V4` | Proof-of-Concept Execution | Runs existing runnable PoCs against the target, captures observable evidence, and updates finding reports with confirmation fields. Findings with `poc_kind: theoretical` (only a `poc.theoretical.md` note) or `none` are marked `no-poc` here and left for V5. | `piolium/confirm-workspace/poc-results.json`; `piolium/findings/<id>-<slug>/evidence/confirmed-<timestamp>.log`; updated `report.md` |
| `V5` | Test-Based Fallback | Generates and runs focused reproducer tests for unconfirmed, blocked, no-PoC, local-only, and theoretical (no-runnable-PoC) findings. | `piolium/confirm-workspace/test-mapping.json`; test/evidence files under each finding; updated `report.md` |
| `V6` | Confirmation Report | Compiles confirmation verdicts and renames false-positive finding folders with an `FP-` prefix before reporting. | `piolium/confirmation-report.md`; `piolium/confirm-workspace/false-positive-renames.json` |
| `V7` | Cleanup & Redaction | Checks final finding layout, creates missing evidence directories, and redacts common secrets from text artifacts. | `piolium/confirm-workspace/cleanup-summary.json`; redacted evidence/report files when needed |

## `/piolium-diff`

Usage: `/piolium-diff [path] [--since=<sha>]`

Phase count: 1 focused phase (`D1`)

Diff mode requires git history and a prior completed audit unless `--since` is
supplied. It skips when there are no changed files or the changed-file set is
too broad.

| Phase | Name | What it does | Main outputs |
| --- | --- | --- | --- |
| `D1` | Changed-file Scan | Reads changed files and their diffs, applies balanced-style SAST patterns to changed regions and immediate callers, and records changed attack surface. | `piolium/attack-surface/diff-summary.md`; `piolium/findings-draft/diff-<NNN>-<slug>.md` |

## `/piolium-revisit`

Usage: `/piolium-revisit [path] [--fresh]`

Phase count: 9 (`R5`, `R7`-`R11c`)

Revisit mode is an anti-anchored pass over an existing completed audit. It uses
prior findings as a negative list so the run focuses on missed or adjacent
issues.

| Phase | Name | What it does | Main outputs |
| --- | --- | --- | --- |
| `R5` | Fresh Deep Probe | Re-derives hypotheses from durable attack-surface context and prior findings as a negative list. | `piolium/attack-surface/revisit-attack-surface-inventory.md`; `piolium/attack-surface/revisit-probe-summary.md`; `piolium/findings-draft/r5-<NNN>-<slug>.md` |
| `R7` | SAST Reclassification | Runs an anti-anchored review chamber pass over prior SAST and durable context. | `piolium/attack-surface/revisit-r7-chamber-summary.md`; `piolium/findings-draft/r7-<NNN>-<slug>.md`; promoted finding directories for survivors |
| `R8` | Fresh Review Chambers | Runs a second fresh chamber pass against current attack-surface slices and prior-finding negatives. | `piolium/attack-surface/revisit-r8-chamber-summary.md`; `piolium/findings-draft/r8-<NNN>-<slug>.md`; promoted finding directories for survivors |
| `R9` | False-Positive Verification | Rechecks revisit-stage drafts and rejects weak findings. | Updated revisit drafts and finding directories |
| `R10` | New Finding Variants | Searches for variants of new revisit findings. | `piolium/findings-draft/r10-<NNN>-<slug>.md`; promoted finding directories for survivors |
| `R10k` | Known Finding Variants | Looks for corner cases and adjacent issues missed by prior passes. | New draft or finding updates when variants are found |
| `R11` | Proof-of-Concept Construction | Builds PoCs and evidence for revisit findings. | `piolium/findings/<id>-<slug>/poc.*` or `poc.theoretical.md`; `piolium/findings/<id>-<slug>/evidence/` |
| `R11b` | Finding Report Drafting | Writes reports for revisit findings. | `piolium/findings/<id>-<slug>/report.md` |
| `R11c` | Final Report Assembly | Regenerates the final report with a discoveries-by-round section. | `piolium/final-audit-report.md` containing `Discoveries by Round` |

## `/piolium-merge`

Usage: `/piolium-merge [path] --dir=<piolium-tree> --dir=<piolium-tree> [...]`

Phase count: 7 (`M1`-`M7`)

Merge mode combines at least two existing `piolium/` result trees into the
current target directory.

| Phase | Name | What it does | Main outputs |
| --- | --- | --- | --- |
| `M1` | Copy & Index | Copies source findings and attack-surface snapshots into a merge workspace under stable aliases. | `piolium/merge-workspace/findings-index.json`; `piolium/merge-workspace/attack-surface-index.json` |
| `M2` | Semantic Deduplication | Identifies findings that describe the same root cause and chooses canonical survivors. | `piolium/merge-workspace/dedup-decisions.json` |
| `M3` | Metadata Auto-Fix | Repairs frontmatter, malformed PoC metadata, naming issues, and report metadata when safe. | Updated files in `piolium/merge-workspace/` |
| `M4` | Quarantine Unfixable Findings | Moves findings that cannot be normalized safely out of the final set. | `piolium/quarantine/<orig-id>-<slug>/QUARANTINE.md` |
| `M5` | Severity Renumbering | Assigns deterministic merged finding ids by severity. | `piolium/merge-workspace/rename-map.json` |
| `M6` | Apply Finding Renames | Writes surviving canonical findings into final finding directories and rewrites internal links. | `piolium/findings/<merged-id>-<slug>/` |
| `M7` | Final Report Assembly | Merges durable context and regenerates the consolidated report. | `piolium/attack-surface/merge-summary.md`; `piolium/final-audit-report.md` |

## `/piolium-longshot`

Usage: `/piolium-longshot [path] [--fresh] [--limit=N] [--timeout=ms] [--langs=python,go] [--include-tests]`

Phase count: 3 (`X1`-`X3`)

Longshot is a hail-mary scan: enumerate every interesting source file in the
repo, point one sub-agent at each file, and let them dig as hard as possible
for vulnerabilities. The X3 aggregator then deduplicates the resulting drafts.

Unlike balanced or deep, longshot does **not** build SAST databases, run
network tooling, or execute the application. It is a brute-force read-only
hunt that scales by file count.

Resume is cheap: `audit-state.json` plus the per-file status sidecar at
`piolium/attack-surface/longshot-targets.json` let a re-run skip files that
already completed and only retry pending or failed ones.

| Phase | Name | What it does | Main outputs |
| --- | --- | --- | --- |
| `X1` | Target Enumeration | Detects dominant languages (or honors `--langs`), walks the repo, filters tests/generated/oversized files, scores each candidate by dangerous-token density and path heuristics, and writes the ordered target list. | `piolium/attack-surface/longshot-targets.json` |
| `X2` | Per-File Hail-Mary Hunt | For each target file, spawns the `longshot-hunter` agent (capped at `Scheduler.maxConcurrent`, with a per-file timeout). The agent reads the anchor file in full, follows imports/callers, and writes per-anchor draft findings. The sidecar records each file's status atomically. | `piolium/findings-draft/longshot-<sha8>-<NNN>-<slug>.md`; `piolium/findings-draft/longshot-<sha8>-000-no-finding.md` (explicit clean markers); updated `longshot-targets.json` |
| `X3` | Finding Aggregation | Single `longshot-aggregator` agent reads every X2 draft, merges duplicates by root cause, ranks by severity and confidence, drops drafts with weak evidence, and writes the curated summary plus per-finding curated drafts. | `piolium/attack-surface/longshot-summary.md`; `piolium/findings-draft/longshot-curated-<NNN>-<slug>.md` |

### Knobs

| Flag | Env | Default | Purpose |
| --- | --- | --- | --- |
| `--plm-longshot-limit` | `PIOLIUM_LONGSHOT_LIMIT` | `1000` | Hard cap on files X2 will hunt. |
| `--plm-longshot-timeout` | `PIOLIUM_LONGSHOT_TIMEOUT_MS` | `21600000` (6 h) | Per-file kill timer. |
| `--plm-longshot-langs` | `PIOLIUM_LONGSHOT_LANGS` | auto-detect | Comma-list of language names (e.g. `python,go`). |
| `--plm-longshot-include-tests` | `PIOLIUM_LONGSHOT_INCLUDE_TESTS` | off | Include test files. |

Inline forms also work: `/piolium-longshot --limit=200 --timeout=600000 --langs=python,go`.

### Outcome handling

- Per-file failures (timeouts, hunter errors) do not abort the swarm — the
  aggregator runs over whatever drafts succeeded.
- If every file fails, X2 is marked `failed` and X3 is skipped.
- If X1 produces zero candidate files (e.g. `--langs` matches nothing), X2
  and X3 are marked `skipped` and a stub summary is written.
- Longshot does not feed `/piolium-confirm` automatically; review the
  curated findings, then run `/piolium-confirm` separately if you want to
  validate them live.
