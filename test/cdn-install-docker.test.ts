import { spawnSync } from "node:child_process";
import type { SpawnSyncReturns } from "node:child_process";
import { describe, expect, it } from "vitest";

const runCdnDockerTest = process.env.PIOLIUM_CDN_DOCKER_TEST === "1";
const itCdnDocker = runCdnDockerTest ? it : it.skip;

const dockerImage =
	process.env.PIOLIUM_CDN_DOCKER_IMAGE ?? "mcr.microsoft.com/vscode/devcontainers/typescript-node";
const installUrl =
	process.env.PIOLIUM_CDN_INSTALL_URL ??
	"https://cdn.vigolium.com/piolium-93833b71e48cb63548bea5a537313da6/install.sh";
const timeoutMs = Number(process.env.PIOLIUM_CDN_DOCKER_TIMEOUT_MS ?? 20 * 60 * 1000);

function formatDockerResult(result: SpawnSyncReturns<string>) {
	return [
		`status: ${result.status}`,
		`signal: ${result.signal ?? ""}`,
		result.error ? `error: ${result.error.message}` : "",
		"stdout:",
		result.stdout,
		"stderr:",
		result.stderr,
	]
		.filter(Boolean)
		.join("\n");
}

describe("CDN installer Docker smoke", () => {
	itCdnDocker(
		"installs Piolium from the CDN in a fresh TypeScript Node devcontainer",
		() => {
			const shellScript = [
				"set -euo pipefail",
				"",
				"if ! command -v curl >/dev/null 2>&1; then",
				'	echo "curl is required in the Docker image" >&2',
				"	exit 127",
				"fi",
				"",
				"had_bun=0",
				"command -v bun >/dev/null 2>&1 && had_bun=1",
				"",
				'case "$PIOLIUM_INSTALL_URL" in',
				'	*\\?*) install_url="${PIOLIUM_INSTALL_URL}&cb=$(date +%s)" ;;',
				'	*) install_url="${PIOLIUM_INSTALL_URL}?cb=$(date +%s)" ;;',
				"esac",
				'base_url="${PIOLIUM_INSTALL_URL%%/install.sh*}"',
				'if [ "$base_url" = "$PIOLIUM_INSTALL_URL" ]; then',
				'	base_url="${PIOLIUM_INSTALL_URL%/*}"',
				"fi",
				"",
				'curl -fsSL "$install_url" | PIOLIUM_BASE_URL="$base_url" bash 2>&1 | tee /tmp/piolium-install.log',
				"",
				'if [ "$had_bun" = 0 ]; then',
				'	grep -q -- "installing Bun" /tmp/piolium-install.log',
				'	grep -q -- "curl -fsSL https://bun.sh/install | bash" /tmp/piolium-install.log',
				"fi",
				'grep -q -- "installing dependencies" /tmp/piolium-install.log',
				'grep -q -- "package manager: bun" /tmp/piolium-install.log',
				'grep -Eq -- "running: .*bun install --production --ignore-scripts" /tmp/piolium-install.log',
				'grep -q -- "@earendil-works/pi-coding-agent" /tmp/piolium-install.log',
				'grep -Fq -- \'export BUN_INSTALL="$HOME/.bun"\' "$HOME/.bashrc"',
				'if grep -Fq -- ".piolium/bin" "$HOME/.bashrc"; then cat "$HOME/.bashrc"; exit 1; fi',
				"bash -ic 'command -v piolium' > /tmp/piolium-bin.txt 2>/tmp/piolium-path-stderr.txt",
				'grep -Fq -- "$HOME/.bun/bin/piolium" /tmp/piolium-bin.txt',
				"",
				'export PATH="$HOME/.bun/bin:$PATH"',
				"piolium doctor",
				'PI_CODING_AGENT_DIR="$HOME/.piolium/agent" pi -h > /tmp/pi-help.txt 2>&1',
				"cat /tmp/pi-help.txt",
				"",
				'grep -q -- "--plm-dir" /tmp/pi-help.txt',
				'grep -q -- "--plm-phase-retries" /tmp/pi-help.txt',
				'grep -q -- "--plm-longshot-langs" /tmp/pi-help.txt',
			].join("\n");

			// Automated runners usually do not provide a TTY, so this uses the
			// non-interactive equivalent of `docker run --rm -it ... bash`.
			const result = spawnSync(
				"docker",
				[
					"run",
					"--rm",
					"-i",
					"--env",
					`PIOLIUM_INSTALL_URL=${installUrl}`,
					dockerImage,
					"bash",
					"-lc",
					shellScript,
				],
				{
					encoding: "utf8",
					maxBuffer: 20 * 1024 * 1024,
					timeout: timeoutMs,
				},
			);
			const output = formatDockerResult(result);

			expect(result.error, output).toBeUndefined();
			expect(result.status, output).toBe(0);
		},
		timeoutMs,
	);
});
