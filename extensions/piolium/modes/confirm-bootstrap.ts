/**
 * Results-only bootstrap for `/piolium-confirm`.
 *
 * Lets the user run confirmation against a directory that contains only the
 * `piolium/` results folder from a previous audit (no source checkout). The
 * bootstrap clones the original repository into a sibling `<repo>-confirm/`
 * directory, checks out the audit commit, copies the results into the clone,
 * and returns the new cwd for `runConfirmAudit` to use.
 *
 * Trigger: cwd has `piolium/findings/` but no `.git/`.
 *
 * Clone URL resolution:
 *   - `--repo <url>` overrides everything.
 *   - Else infer `https://github.com/<owner>/<repo>.git` from
 *     `latestAudit(state).repository`.
 *   - Else fail with a message asking the user to pass `--repo`.
 *
 * Pre-existing destination: reuse if its origin matches the resolved URL,
 * abort otherwise so we never silently confirm against the wrong code.
 */

import { execFileSync } from "node:child_process";
import { cpSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";
import { latestAudit, readAuditState } from "../audit-state.ts";

export type BootstrapNotify = (text: string, level?: "info" | "warning" | "error") => void;

export interface BootstrapOptions {
	cwd: string;
	repoOverride?: string;
	notify?: BootstrapNotify;
}

export interface BootstrapResult {
	cwd: string;
	bootstrapped: boolean;
	cloneDir?: string;
	cloneUrl?: string;
	checkedOutCommit?: string;
}

export function isResultsOnlyDir(cwd: string): boolean {
	if (existsSync(join(cwd, ".git"))) return false;
	const findings = join(cwd, "piolium", "findings");
	if (!existsSync(findings)) return false;
	try {
		return statSync(findings).isDirectory();
	} catch {
		return false;
	}
}

export function inferGithubCloneUrl(repository: string | undefined): string | undefined {
	if (!repository) return undefined;
	if (!/^[^/\s]+\/[^/\s]+$/.test(repository)) return undefined;
	return `https://github.com/${repository}.git`;
}

export function repoBasenameFromUrl(url: string): string {
	const trimmed = url.trim().replace(/\/+$/, "");
	const tail = trimmed.split(/[/:]/).pop() ?? trimmed;
	return tail.replace(/\.git$/, "");
}

function normalizeRemote(url: string): string {
	let out = url.trim().toLowerCase();
	out = out.replace(/\.git$/, "");
	const sshMatch = out.match(/^git@([^:]+):(.+)$/);
	if (sshMatch) out = `https://${sshMatch[1]}/${sshMatch[2]}`;
	out = out.replace(/^ssh:\/\/git@/, "https://");
	return out.replace(/\/+$/, "");
}

function remoteUrlsMatch(a: string, b: string): boolean {
	return normalizeRemote(a) === normalizeRemote(b);
}

type ExecResult = { ok: true; stdout: string } | { ok: false; error: string };

function safeExec(file: string, args: string[]): ExecResult {
	try {
		const stdout = execFileSync(file, args, {
			encoding: "utf8",
			stdio: ["ignore", "pipe", "pipe"],
		}).trim();
		return { ok: true, stdout };
	} catch (err) {
		return { ok: false, error: err instanceof Error ? err.message : String(err) };
	}
}

export function bootstrapResultsOnlyConfirm(opts: BootstrapOptions): BootstrapResult {
	const { cwd, repoOverride } = opts;
	const notify: BootstrapNotify = opts.notify ?? (() => {});

	if (!isResultsOnlyDir(cwd)) {
		return { cwd, bootstrapped: false };
	}

	const stateRes = readAuditState(cwd);
	if (stateRes.parseError) {
		throw new Error(
			`Found piolium/findings/ but cannot read piolium/audit-state.json: ${stateRes.parseError}`,
		);
	}
	const audit = stateRes.state ? latestAudit(stateRes.state) : undefined;
	const auditRepository = audit?.repository;
	const auditCommit = audit?.commit ?? undefined;

	let cloneUrl: string;
	if (repoOverride) {
		cloneUrl = repoOverride;
	} else {
		const inferred = inferGithubCloneUrl(auditRepository);
		if (!inferred) {
			throw new Error(
				"Cannot infer source repository to clone — piolium/audit-state.json has no usable `repository` field. Re-run with `--repo <url>`.",
			);
		}
		cloneUrl = inferred;
	}

	const repoName = repoBasenameFromUrl(cloneUrl);
	if (!repoName) {
		throw new Error(`Unable to derive repo name from clone URL: ${cloneUrl}`);
	}
	const cloneDir = join(cwd, `${repoName}-confirm`);

	if (existsSync(cloneDir)) {
		if (!existsSync(join(cloneDir, ".git"))) {
			throw new Error(
				`Clone destination ${cloneDir} exists but is not a git working tree. Remove or rename it.`,
			);
		}
		const remote = safeExec("git", ["-C", cloneDir, "remote", "get-url", "origin"]);
		if (!remote.ok) {
			throw new Error(
				`Clone destination ${cloneDir} exists but \`git remote get-url origin\` failed: ${remote.error}`,
			);
		}
		if (!remoteUrlsMatch(remote.stdout, cloneUrl)) {
			throw new Error(
				`Clone destination ${cloneDir} has origin "${remote.stdout}" but expected "${cloneUrl}". Remove/rename the directory, or pass --repo matching the existing clone.`,
			);
		}
		notify(`Reusing existing clone at ${cloneDir}.`, "info");
	} else {
		notify(`Cloning ${cloneUrl} → ${cloneDir} ...`, "info");
		const clone = safeExec("git", ["clone", "--", cloneUrl, cloneDir]);
		if (!clone.ok) {
			throw new Error(
				`git clone failed: ${clone.error}\nIf the inferred URL is wrong (private repo, non-github host, etc.), re-run with --repo <url>.`,
			);
		}
	}

	let checkedOutCommit: string | undefined;
	if (auditCommit) {
		const checkout = safeExec("git", ["-C", cloneDir, "checkout", auditCommit]);
		if (checkout.ok) {
			checkedOutCommit = auditCommit;
			notify(`Checked out audit commit ${auditCommit}.`, "info");
		} else {
			notify(
				`Could not checkout audit commit ${auditCommit} (${checkout.error}). Falling back to current branch HEAD.`,
				"warning",
			);
		}
	} else {
		notify("Audit-state has no commit recorded; using current branch HEAD.", "warning");
	}

	const srcResults = join(cwd, "piolium");
	const destResults = join(cloneDir, "piolium");
	cpSync(srcResults, destResults, { recursive: true });
	notify(`Copied results into ${destResults}.`, "info");

	return {
		cwd: cloneDir,
		bootstrapped: true,
		cloneDir,
		cloneUrl,
		...(checkedOutCommit ? { checkedOutCommit } : {}),
	};
}
