# HACKING

This file keeps the technical details that do not need to live in the concise README.

## Prerequisites

- Bun `>=1.1.0`.
- Pi, provided by `@earendil-works/pi-coding-agent`.
- `git` for source installs, history-aware audit phases, and `/piolium-diff`.
- Optional scanners for richer results: `trufflehog`, `gitleaks`, `codeql`, and `semgrep`.

Piolium falls back to simpler local scans when optional tools are not available.

## Runtime Model

Piolium is a Pi extension, not a standalone scanner process. The extension entry point is `extensions/piolium/index.ts`; it registers the `/piolium-*` slash commands, session flags, and stream renderer when Pi starts.

The quick installer also creates a `piolium` wrapper command. That wrapper runs Pi with:

```bash
PI_CODING_AGENT_DIR="$HOME/.piolium/agent"
pi --session-dir "$HOME/.piolium/agent/session"
```

This keeps Piolium auth, settings, and sessions separate from normal Pi state under `$HOME/.pi/agent`.

## Quick Installer

Install or update Piolium with:

```bash
curl -fsSL "https://cdn.vigolium.com/piolium-93833b71e48cb63548bea5a537313da6/install.sh?cb=$(date +%s)" | bash
```

The installer:

- downloads the latest tarball into `$HOME/.piolium/package`;
- verifies the sha256 checksum;
- creates a standalone `piolium` launcher next to `pi` when possible;
- bootstraps Bun from `https://bun.sh/install` if Bun is missing;
- installs Pi with `bun add -g @earendil-works/pi-coding-agent` if Pi is missing;
- registers Piolium in the isolated `$HOME/.piolium/agent` profile;
- updates shell config so the launcher is on `PATH`.

The `?cb=...` cache buster asks the CDN edge for the latest installer instead of a cached older copy.

Default Bun installs place both `pi` and `piolium` in `$HOME/.bun/bin`. If the installer falls back to `$HOME/.local/bin`, it adds that directory to shell config too.

For the default Bun bootstrap, the shell config block looks like:

```bash
export BUN_INSTALL="$HOME/.bun"
export PATH="$BUN_INSTALL/bin:$PATH"
```

Re-run the installer any time to update. It only replaces `$HOME/.piolium/package`, so Piolium auth, settings, and sessions are preserved.

## Auth

Piolium uses separate auth by default:

```bash
piolium login
```

To copy existing Pi auth into the isolated Piolium profile:

```bash
piolium auth sync
```

`piolium auth sync` copies `auth.json` from the normal Pi agent directory, `$HOME/.pi/agent` by default, into `$HOME/.piolium/agent`. Override the source with `PIOLIUM_SOURCE_PI_AGENT_DIR`.

To seed from a specific auth file without overwriting an existing non-empty Piolium auth file:

```bash
piolium auth import
```

When Piolium starts or runs `doctor`, it warns and auto-syncs if the isolated auth file is still empty and normal Pi auth exists.

## Custom Install Home

Set a custom Piolium home before running the installer:

```bash
export PIOLIUM_HOME="/opt/piolium"
export PIOLIUM_PACKAGE_DIR="$PIOLIUM_HOME/package"
export PIOLIUM_AGENT_DIR="$PIOLIUM_HOME/agent"
export PIOLIUM_SESSION_DIR="$PIOLIUM_AGENT_DIR/session"

curl -fsSL "https://cdn.vigolium.com/piolium-93833b71e48cb63548bea5a537313da6/install.sh?cb=$(date +%s)" | bash

PI_CODING_AGENT_DIR="$PIOLIUM_AGENT_DIR" \
  pi --session-dir "$PIOLIUM_SESSION_DIR" \
  -p "/piolium-status"
```

## Manual Pi Usage

Start Pi directly with Piolium's isolated profile:

```bash
PI_CODING_AGENT_DIR="$HOME/.piolium/agent" \
  pi --session-dir "$HOME/.piolium/agent/session"

PI_CODING_AGENT_DIR="$HOME/.piolium/agent" \
  pi --session-dir "$HOME/.piolium/agent/session" \
  -p "/piolium-balanced --fresh"
```

The wrapper supports the same Pi command shape:

```bash
piolium
piolium -p "/piolium-balanced --fresh"
piolium doctor
```

## Install This Checkout Locally

Build a local release bundle from the current checkout and install it into `$HOME/.piolium`:

```bash
bun run install
```

The package-manager `install` lifecycle is guarded, so plain `bun install` will not install Piolium locally.

## Build And Release

Build and publish an installer bundle:

```bash
bun run release
bash build/dist/install.sh
```

`bun run release` writes:

- `build/dist/piolium.tar.gz`
- `build/dist/piolium.checksum.txt`
- `build/dist/install.sh`

It then uploads those artifacts to the configured R2/CDN bucket. To build only local files without uploading:

```bash
UPLOAD=0 bun run release
```

Running the local installer uses the tarball beside it, installs Pi if needed, then registers Piolium in the isolated `$HOME/.piolium/agent` profile.

## Source Install

Install from a git source:

```bash
pi install git:git@github.com:vigolium/piolium.git
```

Install from a local path:

```bash
# Global install, loaded in every Pi session
pi install /absolute/path/to/piolium

# Project-local install, written to <cwd>/.pi/settings.json
pi install -l /absolute/path/to/piolium

# Relative paths work too
pi install ./piolium
```

`pi install` accepts local paths, git URLs, and npm specs. Versioned specs such as `@v0.1.0` or `@<sha>` are pinned.

By default, `pi install` writes to global Pi settings at `~/.pi/agent/settings.json`, so Piolium loads in every Pi session. Pass `-l` to write to the current project's `.pi/settings.json`.

Pi reads `package.json#pi.{extensions,skills,prompts}` and registers the bundled extension, skills, and prompt paths.

## Verify

Confirm the package is registered:

```bash
pi list
```

Then run:

```text
/piolium-status
```

If Piolium is loaded, this prints the current audit state or a "no audit state yet" message. If the command is missing, check `pi list` and session-start diagnostics.

For an end-to-end runner and provider check:

```text
/piolium-smoke
```

The smoke command writes a transcript under `piolium/tmp/piolium/runs/smoke-*/`.

## Updating

Update all non-pinned packages:

```bash
pi update
```

Update Piolium specifically:

```bash
pi update git:git@github.com:vigolium/piolium.git
```

Local-path installs always reflect the current directory. `pi update` is a no-op for them.

Versioned specs such as `@v0.1.0` and `@<sha>` are skipped by `pi update`; reinstall with a new ref to move them.

## Uninstall

```bash
pi remove /absolute/path/to/piolium
pi remove git:git@github.com:vigolium/piolium.git

# Project-local scope
pi remove -l <source>
```

## Usage Examples

Run Piolium from Pi with `-p` for one-shot commands, or start `pi` normally and type the `/piolium-*` command.

```bash
# Show command and flag help
pi -p "/piolium-help"

# Run against the current directory
pi -p "/piolium-balanced --fresh"

# Run against another repo
pi --plm-dir /path/to/repo -p "/piolium-lite"

# Stream findings in real time during the audit
pi -p "/piolium-balanced" --mode streaming

# Deep audit with bounded history scan and retry tuning
pi --plm-scan-limit 250 --plm-scan-since "90 days ago" \
  --plm-phase-retries 2 --plm-command-retries 3 \
  -p "/piolium-deep"

# Incremental diff from a specific base commit
pi --plm-since <sha> -p "/piolium-diff"

# Hail-mary scan over selected languages
pi --plm-longshot-limit 200 --plm-longshot-langs python,go \
  -p "/piolium-longshot"
```

Most commands accept an optional target directory as the first argument, for example:

```text
/piolium-balanced ../target-repo --fresh
```

## Session Flags

Useful session flags:

- `--plm-dir`: default target directory.
- `--plm-since`: default base commit for `/piolium-diff`.
- `--plm-scan-limit`: maximum commits for history-aware phases.
- `--plm-scan-since`: git `--since` window for history-aware phases.
- `--plm-phase-retries`: phase agent retry count.
- `--plm-command-retries`: whole-command retry count.
- `--plm-longshot-limit`: maximum files for `/piolium-longshot`.
- `--plm-longshot-timeout`: per-file longshot timeout in milliseconds.
- `--plm-longshot-langs`: comma-separated language allowlist.

Command-local arguments win over session flags.

## Retry Behavior

Piolium records retry metadata in `piolium/audit-state.json`. Retry counts are retries after the first attempt.

| Scope | Defaults | CLI flags |
| --- | --- | --- |
| Phase agents | `2` retries, `5000` ms base backoff, `120000` ms max backoff | `--plm-phase-retries`, `--plm-phase-backoff`, `--plm-phase-backoff-max` |
| Lite Q0/Q1 overrides | `2` retries, `5000` ms base backoff, `120000` ms max backoff | `--plm-lite-retries`, `--plm-lite-backoff`, `--plm-lite-backoff-max` |
| Command reruns | `3` retries, `5000` ms base backoff, `120000` ms max backoff | `--plm-command-retries`, `--plm-command-backoff`, `--plm-command-backoff-max` |

Example:

```bash
pi --plm-phase-retries 2 --plm-command-retries 3 -p "/piolium-balanced"
```

## History Scan Scope

History-aware phases scan the intersection of a commit limit and a git `--since` window.

| Scope | Default | CLI flag |
| --- | --- | --- |
| Commit limit | `500` commits | `--plm-scan-limit` |
| Git since window | `"60 days ago"` | `--plm-scan-since` |

Example:

```bash
pi --plm-scan-limit 250 --plm-scan-since "90 days ago" -p "/piolium-deep"
```

## Longshot Scope

`/piolium-longshot` enumerates interesting source files and spawns one sub-agent per file, capped by the global concurrency limit.

| Scope | Default | CLI flag |
| --- | --- | --- |
| Max files hunted | `1000` files | `--plm-longshot-limit` |
| Per-file kill timer | `21600000` ms, 6 h | `--plm-longshot-timeout` |
| Language allowlist | auto-detect dominant | `--plm-longshot-langs` |
| Include test files | off | `--plm-longshot-include-tests` |

Inline overrides also work:

```text
/piolium-longshot --limit=200 --langs=python,go
```

Test and generated files are filtered by default. Files larger than 1 MB are skipped.

## Development Setup

The bundled `agents/` and `skills/` directories are committed to the repo, so a fresh clone is ready to build with no extra bootstrap step.

```bash
git clone <repo-url> piolium
cd piolium
bun install

# Sanity gates
bun run typecheck
bun run lint
bun run test
```

`agents/` contains the agent markdown files and `skills/` contains the skill directories. Install Piolium into Pi:

```bash
# In-place dev install. Edits in this checkout land immediately.
pi install ./
```

Or iterate without touching Pi settings:

```bash
pi -e ./extensions/piolium/index.ts
```

Run a single test file or filter by test name:

```bash
bun run test -- test/scheduler.test.ts
bun run test -- -t "phase status strip"
```

## Registered Pi Resources

When Piolium loads, Pi picks up:

- Extension: `extensions/piolium/index.ts` registers all `/piolium-*` slash commands.
- Skills: every directory in `skills/` is exposed through Pi progressive skill loading, for example `/skill:codeql`, `/skill:semgrep`, and `/skill:vuln-report`.
- Prompts: package metadata reserves `./prompts`; add the directory when prompt aliases are introduced.

Sub-agents under `agents/` are package-private because Pi has no first-class `agents` resource type. The extension loads them on demand through `extensions/piolium/agents.ts`.

## Architecture Notes

- Mode runners live under `extensions/piolium/modes/`.
- Canonical phase order is in `extensions/piolium/modes/modes.ts`.
- Per-phase retry, state transitions, and heartbeat tracking are owned by `extensions/piolium/modes/phase-runner.ts`.
- Sub-agents run through `extensions/piolium/agent-runner.ts`, which creates child Pi sessions in-process with `createAgentSession`.
- Agent runs write transcripts to `<target>/piolium/tmp/piolium/runs/<runId>/`.
- Durable state lives at `<target>/piolium/audit-state.json`.
- File writes to audit state should go through helpers in `extensions/piolium/audit-state.ts`.

Mode names and phase IDs are persisted in audit state. Do not rename them casually.

## Output Layout

Audit output is written under the target repository's `piolium/` directory:

- `attack-surface/`: durable recon, KB, SAST, and probe summaries.
- `findings-draft/`: candidate findings.
- `findings/<id>-<slug>/`: final findings, reports, evidence, and PoCs.
- `final-audit-report.md`: final consolidated report.
- `confirm-workspace/`: confirmation-mode workspace.
- `tmp/piolium/runs/<runId>/`: sub-agent transcripts.

See [docs/output-structure.md](docs/output-structure.md) for the full layout.

## Security Note

Pi packages execute arbitrary code: extensions run TypeScript, skills can instruct the model to run shell commands, and bundled audit agents declare filesystem and shell tools. Treat Piolium as trusted-local tooling. Do not run it against untrusted repositories without sandboxing the working directory.
