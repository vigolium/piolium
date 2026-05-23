#!/usr/bin/env bash
# Bootstrap installer for piolium.
#
# Usage:
#   curl -fsSL <base-url>/install.sh | bash
#
# What it does:
#   1. Downloads the latest piolium tarball from R2, or uses a tarball next to
#      this installer when running from a local release bundle.
#   2. Verifies sha256 against the published checksum (if present).
#   3. Extracts package code into $HOME/.piolium/package (wipes package only).
#   4. Ensures `bun` and `pi` are available when needed (installs Bun from
#      bun.sh when neither pi nor bun is present, then installs pi via
#      `bun add -g @earendil-works/pi-coding-agent`), registers piolium in an
#      isolated $HOME/.piolium/agent config, and writes the `piolium` launcher
#      next to `pi` when possible (for Bun installs, $HOME/.bun/bin/piolium).
#
# Env overrides:
#   PIOLIUM_BASE_URL  Public URL prefix where piolium.tar.gz lives.
#                     Default: https://cdn.vigolium.com/piolium-93833b71e48cb63548bea5a537313da6
#   PIOLIUM_LOCAL_DIST_DIR Local directory containing piolium.tar.gz + checksum.
#                     Default: auto-detects the install.sh directory when possible.
#   PIOLIUM_HOME      Runtime home. Default: $HOME/.piolium
#   PIOLIUM_PACKAGE_DIR Package extraction directory. Default: $PIOLIUM_HOME/package
#   PIOLIUM_AGENT_DIR Isolated Pi config directory. Default: $PIOLIUM_HOME/agent
#   PIOLIUM_SESSION_DIR Isolated Pi session directory. Default: $PIOLIUM_AGENT_DIR/session
#   PIOLIUM_BIN_DIR   Directory for the piolium launcher. Default: directory
#                     containing `pi` when writable, otherwise ~/.local/bin.
#   PIOLIUM_SHELL_RC  Shell startup file to update with Bun + PIOLIUM_BIN_DIR.
#                     Default: ~/.bashrc for bash, ~/.zshrc for zsh, ~/.profile otherwise.
#   TARBALL_NAME      Default: piolium.tar.gz
#   SKIP_PI_INSTALL   Set to 1 to skip the `pi install` step entirely.
#   SKIP_BUN_BOOTSTRAP Set to 1 to skip auto-installing Bun/pi.
#   SKIP_PATH_SETUP   Set to 1 to skip adding Bun/Piolium to shell config.
#   NO_COLOR          Set to disable ANSI colors.

set -euo pipefail

DEFAULT_PIOLIUM_BASE_URL="https://cdn.vigolium.com/piolium-93833b71e48cb63548bea5a537313da6"
TARBALL_NAME="${TARBALL_NAME:-piolium.tar.gz}"
PIOLIUM_BASE_URL="${PIOLIUM_BASE_URL:-}"
PIOLIUM_LOCAL_DIST_DIR="${PIOLIUM_LOCAL_DIST_DIR:-}"
PIOLIUM_HOME="${PIOLIUM_HOME:-$HOME/.piolium}"
PIOLIUM_PACKAGE_DIR="${PIOLIUM_PACKAGE_DIR:-$PIOLIUM_HOME/package}"
PIOLIUM_AGENT_DIR="${PIOLIUM_AGENT_DIR:-$PIOLIUM_HOME/agent}"
PIOLIUM_SESSION_DIR="${PIOLIUM_SESSION_DIR:-$PIOLIUM_AGENT_DIR/session}"
PIOLIUM_BIN_DIR_EXPLICIT=0
if [[ -n "${PIOLIUM_BIN_DIR:-}" ]]; then
	PIOLIUM_BIN_DIR_EXPLICIT=1
else
	PIOLIUM_BIN_DIR=""
fi
PIOLIUM_SHELL_RC="${PIOLIUM_SHELL_RC:-}"
SKIP_PI_INSTALL="${SKIP_PI_INSTALL:-0}"
SKIP_BUN_BOOTSTRAP="${SKIP_BUN_BOOTSTRAP:-0}"
SKIP_PATH_SETUP="${SKIP_PATH_SETUP:-0}"
PI_NPM_PACKAGE="@earendil-works/pi-coding-agent"
PI_REPO_URL="https://github.com/earendil-works/pi"
BUN_INSTALL_URL="https://bun.sh/install"
PIOLIUM_PATH_RC_PATH=""
PIOLIUM_PATH_RC_UPDATED=0
PIOLIUM_PATH_RC_CONFIGURED=0

# ---- color helpers -----------------------------------------------------------
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
	C_INFO=$'\033[36m'   # cyan
	C_OK=$'\033[32m'     # green
	C_WARN=$'\033[33m'   # yellow
	C_ERR=$'\033[31m'    # red
	C_DIM=$'\033[2m'     # dim
	C_BOLD=$'\033[1m'    # bold
	C_RESET=$'\033[0m'
else
	C_INFO=""; C_OK=""; C_WARN=""; C_ERR=""; C_DIM=""; C_BOLD=""; C_RESET=""
fi

log()   { printf "%s[piolium]%s %s\n"     "$C_INFO" "$C_RESET" "$1"; }
ok()    { printf "%s[piolium]%s %s%s%s\n" "$C_OK"   "$C_RESET" "$C_OK" "$1" "$C_RESET"; }
warn()  { printf "%s[piolium]%s %s%s%s\n" "$C_WARN" "$C_RESET" "$C_WARN" "$1" "$C_RESET" >&2; }
err()   { printf "%s[piolium]%s %s%s%s\n" "$C_ERR"  "$C_RESET" "$C_ERR" "$1" "$C_RESET" >&2; }
dim()   { printf "%s%s%s\n" "$C_DIM" "$1" "$C_RESET"; }

host_of() {
	local u="${1#http://}"
	u="${u#https://}"
	printf '%s' "${u%%/*}"
}

detect_local_dist_dir() {
	local script_path="${BASH_SOURCE[0]:-$0}"
	[[ -f "$script_path" ]] || return 1
	local script_dir
	script_dir="$(cd "$(dirname "$script_path")" && pwd)"
	[[ -f "$script_dir/$TARBALL_NAME" ]] || return 1
	printf '%s' "$script_dir"
}

list_package_dependencies() {
	local package_json="$1/package.json"
	[[ -f "$package_json" ]] || return 1
	sed -n '/^[[:space:]]*"dependencies"[[:space:]]*:/,/^[[:space:]]*}/p' "$package_json" \
		| sed -n 's/^[[:space:]]*"\([^"]*\)"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1@\2/p' \
		| awk 'BEGIN { first = 1 } { if (!first) printf ", "; printf "%s", $0; first = 0 } END { if (!first) print "" }'
}

format_command() {
	local out="" arg quoted
	for arg in "$@"; do
		printf -v quoted "%q" "$arg"
		if [[ -n "$out" ]]; then
			out+=" "
		fi
		out+="$quoted"
	done
	printf "%s" "$out"
}

run_with_progress() {
	local label="$1"
	shift
	local display
	display="$(format_command "$@")"
	log "running: ${C_BOLD}${display}${C_RESET}"

	(
		while true; do
			sleep 15 || exit 0
			log "${label} still running..."
		done
	) &
	local progress_pid=$!
	local status=0
	"$@" || status=$?
	kill "$progress_pid" >/dev/null 2>&1 || true
	wait "$progress_pid" 2>/dev/null || true
	return "$status"
}

add_bun_to_path() {
	local bun_bin="${BUN_INSTALL:-$HOME/.bun}/bin"
	if [[ -d "$bun_bin" ]]; then
		case ":$PATH:" in
			*":$bun_bin:"*) ;;
			*) export PATH="$bun_bin:$PATH" ;;
		esac
	fi
}

find_bun() {
	if command -v bun >/dev/null 2>&1; then
		command -v bun
		return 0
	fi

	local candidate="${BUN_INSTALL:-$HOME/.bun}/bin/bun"
	if [[ -x "$candidate" ]]; then
		printf "%s\n" "$candidate"
		return 0
	fi

	return 1
}

dir_is_writable() {
	local dir="$1"
	mkdir -p "$dir" 2>/dev/null && [[ -w "$dir" ]]
}

resolve_piolium_bin_dir() {
	if [[ "$PIOLIUM_BIN_DIR_EXPLICIT" == "1" ]]; then
		mkdir -p "$PIOLIUM_BIN_DIR"
		return 0
	fi

	local pi_path pi_dir bun_bin local_bin
	bun_bin="${BUN_INSTALL:-$HOME/.bun}/bin"
	if [[ -x "$bun_bin/pi" ]] && dir_is_writable "$bun_bin"; then
		PIOLIUM_BIN_DIR="$bun_bin"
		return 0
	fi

	pi_path="$(command -v pi 2>/dev/null || true)"
	if [[ "$pi_path" == /* && "$pi_path" != */node_modules/.bin/* ]]; then
		pi_dir="$(dirname "$pi_path")"
		if dir_is_writable "$pi_dir"; then
			PIOLIUM_BIN_DIR="$pi_dir"
			return 0
		fi
	fi

	local_bin="$HOME/.local/bin"
	if dir_is_writable "$local_bin"; then
		PIOLIUM_BIN_DIR="$local_bin"
		return 0
	fi

	err "could not find a writable directory for the piolium launcher"
	return 1
}

add_piolium_to_path() {
	[[ -n "$PIOLIUM_BIN_DIR" ]] || return 0
	case ":$PATH:" in
		*":$PIOLIUM_BIN_DIR:"*) ;;
		*) export PATH="$PIOLIUM_BIN_DIR:$PATH" ;;
	esac
}

piolium_path_export_line() {
	if [[ "$PIOLIUM_BIN_DIR" == "${BUN_INSTALL:-$HOME/.bun}/bin" ]]; then
		printf 'export PATH="$BUN_INSTALL/bin:$PATH"\n'
	elif [[ "$PIOLIUM_BIN_DIR" == "$HOME/.local/bin" ]]; then
		printf 'export PATH=$HOME/.local/bin:"$PATH"\n'
	else
		local quoted_bin
		printf -v quoted_bin "%q" "$PIOLIUM_BIN_DIR"
		printf 'export PATH=%s:"$PATH"\n' "$quoted_bin"
	fi
}

detect_shell_rc() {
	if [[ -n "$PIOLIUM_SHELL_RC" ]]; then
		printf "%s\n" "$PIOLIUM_SHELL_RC"
		return 0
	fi

	case "${SHELL##*/}" in
		zsh) printf "%s\n" "$HOME/.zshrc" ;;
		bash | "") printf "%s\n" "$HOME/.bashrc" ;;
		*) printf "%s\n" "$HOME/.profile" ;;
	esac
}

configure_piolium_path() {
	export BUN_INSTALL="${BUN_INSTALL:-$HOME/.bun}"
	add_bun_to_path
	add_piolium_to_path

	if [[ "$SKIP_PATH_SETUP" == "1" ]]; then
		return 0
	fi

	local rc_path
	rc_path="$(detect_shell_rc)"
	[[ -n "$rc_path" ]] || return 0
	PIOLIUM_PATH_RC_PATH="$rc_path"

	local rc_dir quoted_bun_install wrote_block=0
	rc_dir="$(dirname "$rc_path")"
	mkdir -p "$rc_dir"
	touch "$rc_path"

	if ! grep -Fqs ".bun/bin" "$rc_path" && ! grep -Fqs "BUN_INSTALL" "$rc_path"; then
		local bun_install="${BUN_INSTALL:-$HOME/.bun}"
		if [[ "$bun_install" == "$HOME/.bun" ]]; then
			{
				printf "\n# bun\n"
				printf 'export BUN_INSTALL="$HOME/.bun"\n'
				printf 'export PATH="$BUN_INSTALL/bin:$PATH"\n'
			} >> "$rc_path"
		else
			printf -v quoted_bun_install "%q" "$bun_install"
			{
				printf "\n# bun\n"
				printf "export BUN_INSTALL=%s\n" "$quoted_bun_install"
				printf 'export PATH="$BUN_INSTALL/bin:$PATH"\n'
			} >> "$rc_path"
		fi
		wrote_block=1
	fi

	local piolium_export old_piolium_export
	piolium_export="$(piolium_path_export_line)"
	if [[ "$PIOLIUM_BIN_DIR_EXPLICIT" != "1" ]]; then
		local old_home_piolium_export old_abs_piolium_export
		old_home_piolium_export='export PATH=$HOME/.piolium/bin:"$PATH"'
		old_abs_piolium_export="export PATH=${PIOLIUM_HOME}/bin:\"\$PATH\""
		if grep -Fqs "$old_home_piolium_export" "$rc_path" \
			|| grep -Fqs "$old_abs_piolium_export" "$rc_path"; then
			local tmp_cleanup
			tmp_cleanup="$(mktemp 2>/dev/null)" || tmp_cleanup=""
			if [[ -n "$tmp_cleanup" ]] \
				&& awk -v old_home="$old_home_piolium_export" -v old_abs="$old_abs_piolium_export" \
					'{ if ($0 != old_home && $0 != old_abs) print }' "$rc_path" > "$tmp_cleanup" \
				&& cat "$tmp_cleanup" > "$rc_path"; then
				wrote_block=1
			fi
			rm -f "$tmp_cleanup"
		fi
	fi

	old_piolium_export="export PATH=${PIOLIUM_BIN_DIR}:\"\$PATH\""
	if grep -Fqs "$old_piolium_export" "$rc_path" \
		&& ! grep -Fqs "$piolium_export" "$rc_path"; then
		local tmp_rc
		tmp_rc="$(mktemp 2>/dev/null)" || tmp_rc=""
		if [[ -n "$tmp_rc" ]] \
			&& awk -v old="$old_piolium_export" -v new="$piolium_export" \
				'{ if ($0 == old) print new; else print }' "$rc_path" > "$tmp_rc" \
			&& cat "$tmp_rc" > "$rc_path"; then
			wrote_block=1
		fi
		rm -f "$tmp_rc"
	fi

	if ! grep -Fqs "$piolium_export" "$rc_path"; then
		{
			printf "\n# piolium\n"
			printf "%s\n" "$piolium_export"
		} >> "$rc_path"
		wrote_block=1
	fi

	if [[ "$wrote_block" == "1" ]]; then
		PIOLIUM_PATH_RC_UPDATED=1
		log "added Bun/Piolium PATH setup to ${rc_path}"
	fi
	PIOLIUM_PATH_RC_CONFIGURED=1
}

activate_installer_paths() {
	if [[ -n "$PIOLIUM_PATH_RC_PATH" && -f "$PIOLIUM_PATH_RC_PATH" ]]; then
		# Source in a subshell so unusual rc-file exits cannot abort a completed install.
		( set +u; source "$PIOLIUM_PATH_RC_PATH" >/dev/null 2>&1 ) || true
	fi

	export BUN_INSTALL="${BUN_INSTALL:-$HOME/.bun}"
	add_bun_to_path
	add_piolium_to_path
}

ensure_bun() {
	local bun_path
	if bun_path="$(find_bun 2>/dev/null)"; then
		add_bun_to_path
		return 0
	fi

	if [[ "$SKIP_BUN_BOOTSTRAP" == "1" ]]; then
		return 1
	fi

	if ! command -v curl >/dev/null 2>&1; then
		err "bun is missing and curl is not available to install it."
		return 1
	fi

	warn "'bun' not found — installing Bun"
	local attempt max_attempts=3
	for ((attempt = 1; attempt <= max_attempts; attempt++)); do
		log "running: ${C_BOLD}curl -fsSL ${BUN_INSTALL_URL} | bash${C_RESET} ${C_DIM}(attempt ${attempt}/${max_attempts})${C_RESET}"
		if curl -fsSL "$BUN_INSTALL_URL" | bash; then
			break
		fi
		if [[ "$attempt" == "$max_attempts" ]]; then
			err "Bun install failed"
			return 1
		fi
		warn "Bun install failed; retrying."
		sleep 2
	done

	add_bun_to_path
	if ! bun_path="$(find_bun 2>/dev/null)"; then
		local bun_bin="${BUN_INSTALL:-$HOME/.bun}/bin"
		err "Bun installed but not found on PATH"
		err "add ${bun_bin} to PATH (e.g. export PATH=\"${bun_bin}:\$PATH\") then re-run."
		return 1
	fi

	ok "Bun installed ${C_DIM}($("$bun_path" --version 2>/dev/null || printf "unknown"))${C_RESET}"
	return 0
}

# ---- pick a sha256 binary ----------------------------------------------------
if command -v shasum >/dev/null 2>&1; then
	SHA256=(shasum -a 256)
elif command -v sha256sum >/dev/null 2>&1; then
	SHA256=(sha256sum)
else
	SHA256=()
fi

# ---- download + extract ------------------------------------------------------
if [[ -z "$PIOLIUM_BASE_URL" && -z "$PIOLIUM_LOCAL_DIST_DIR" ]]; then
	PIOLIUM_LOCAL_DIST_DIR="$(detect_local_dist_dir || true)"
fi
if [[ -z "$PIOLIUM_BASE_URL" && -z "$PIOLIUM_LOCAL_DIST_DIR" ]]; then
	PIOLIUM_BASE_URL="$DEFAULT_PIOLIUM_BASE_URL"
fi

CB="$(date +%s)-$$"
if [[ -n "$PIOLIUM_LOCAL_DIST_DIR" ]]; then
	TARBALL_URL="$PIOLIUM_LOCAL_DIST_DIR/$TARBALL_NAME"
	CHECKSUM_URL="$PIOLIUM_LOCAL_DIST_DIR/${TARBALL_NAME%.tar.gz}.checksum.txt"
	HOST="local:${PIOLIUM_LOCAL_DIST_DIR}"
else
	TARBALL_URL="${PIOLIUM_BASE_URL%/}/${TARBALL_NAME}?cache-buster=${CB}"
	CHECKSUM_URL="${PIOLIUM_BASE_URL%/}/${TARBALL_NAME%.tar.gz}.checksum.txt?cache-buster=${CB}"
	HOST="$(host_of "$PIOLIUM_BASE_URL")"
fi

TMPDIR_REAL="$(mktemp -d -t piolium-install.XXXXXX)"
trap 'rm -rf "$TMPDIR_REAL"' EXIT
TARBALL_PATH="$TMPDIR_REAL/$TARBALL_NAME"

printf "%s%s%s piolium installer\n" "$C_BOLD" "▸" "$C_RESET"
log "source:  ${C_DIM}${HOST}${C_RESET}"
log "dest:    ${C_DIM}${PIOLIUM_PACKAGE_DIR}${C_RESET}"
if [[ -n "$PIOLIUM_LOCAL_DIST_DIR" ]]; then
	log "using ${C_BOLD}${TARBALL_NAME}${C_RESET} from local release bundle"
else
	log "fetching ${C_BOLD}${TARBALL_NAME}${C_RESET} ${C_DIM}(cache-buster ${CB})${C_RESET}"
fi

if [[ -n "$PIOLIUM_LOCAL_DIST_DIR" ]]; then
	if ! cp "$TARBALL_URL" "$TARBALL_PATH"; then
		err "copy failed: ${TARBALL_NAME} from ${HOST}"
		exit 1
	fi
else
	if ! curl -fsSL --retry 3 --retry-delay 2 -o "$TARBALL_PATH" "$TARBALL_URL"; then
		err "download failed: ${TARBALL_NAME} from ${HOST}"
		exit 1
	fi
fi

if [[ ${#SHA256[@]} -gt 0 ]]; then
	if [[ -n "$PIOLIUM_LOCAL_DIST_DIR" && -f "$CHECKSUM_URL" ]]; then
		cp "$CHECKSUM_URL" "$TMPDIR_REAL/checksum.txt"
	elif [[ -n "$PIOLIUM_LOCAL_DIST_DIR" ]]; then
		warn "checksum missing next to local tarball; skipping sha256 verification."
	else
		curl -fsSL --retry 2 -o "$TMPDIR_REAL/checksum.txt" "$CHECKSUM_URL" 2>/dev/null || true
	fi
	if [[ -f "$TMPDIR_REAL/checksum.txt" ]]; then
		EXPECTED=$(awk '{print $1}' "$TMPDIR_REAL/checksum.txt")
		ACTUAL=$("${SHA256[@]}" "$TARBALL_PATH" | awk '{print $1}')
		if [[ -n "$EXPECTED" && "$EXPECTED" != "$ACTUAL" ]]; then
			err "sha256 mismatch"
			err "  expected: $EXPECTED"
			err "  actual:   $ACTUAL"
			exit 1
		fi
		ok "sha256 verified ${C_DIM}(${ACTUAL:0:12}…)${C_RESET}"
	fi
fi

# Wipe and re-extract package code so a stale install can't leak deleted files.
# Persistent auth/settings/sessions live under $PIOLIUM_AGENT_DIR and are kept.
mkdir -p "$PIOLIUM_PACKAGE_DIR"
find "$PIOLIUM_PACKAGE_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf {} +

log "extracting"
# Filter the libarchive xattr noise that GNU tar prints when reading a tarball
# created by BSD tar. Real errors still surface (set -o pipefail keeps the
# tar exit code authoritative).
tar -xzf "$TARBALL_PATH" -C "$PIOLIUM_PACKAGE_DIR" 2> >(
	grep -vE 'Ignoring unknown extended header keyword .LIBARCHIVE\.xattr' >&2 || true
)

# A fresh shell may have neither pi nor bun. Bootstrap Bun before dependency
# installation so the same run can finish instead of asking for a second pass.
if ! command -v pi >/dev/null 2>&1 && ! command -v bun >/dev/null 2>&1; then
	ensure_bun || warn "Bun bootstrap failed; continuing with any available package manager."
fi

# Install runtime dependencies. The tarball excludes node_modules (platform-
# specific binaries). The core extension has no required runtime deps — the Pi
# SDK is provided by the host pi process and the yaml parser is vendored
# (extensions/piolium/_vendor/yaml.bundle.mjs) — so this is usually a no-op.
# It still runs so any optional deps a user added (e.g. @anthropic-ai/vertex-sdk
# for Claude-on-Vertex) get resolved. Prefer bun (matches engines), fall back to npm.
DEPENDENCY_NAMES="$(list_package_dependencies "$PIOLIUM_PACKAGE_DIR" || true)"
if [[ -n "$DEPENDENCY_NAMES" ]]; then
	log "installing dependencies: ${C_BOLD}${DEPENDENCY_NAMES}${C_RESET}"
else
	log "installing dependencies from package.json"
fi
(
	cd "$PIOLIUM_PACKAGE_DIR"
	if bun_path="$(find_bun 2>/dev/null)"; then
		add_bun_to_path
		log "package manager: bun $("$bun_path" --version 2>/dev/null || printf "unknown")"
		run_with_progress "dependency install" "$bun_path" install --production --ignore-scripts
	elif command -v npm >/dev/null 2>&1; then
		log "package manager: npm $(npm --version 2>/dev/null || printf "unknown")"
		run_with_progress "dependency install" npm install --omit=dev --ignore-scripts --no-audit --no-fund
	else
		echo "WARN: no bun or npm on PATH — runtime deps not installed."
		echo "      Pi will fail to load the extension with 'Cannot find module yaml'."
		echo "      Install bun (https://bun.sh) or npm and re-run."
	fi
) || warn "dependency install reported errors; pi may fail to load the extension."

# ---- ensure pi is available --------------------------------------------------
# PI_CMD is the argv prefix that runs pi. Either ("pi") when the bin is
# directly invocable, or ("bun" "<pi-path>") as a fallback when we can't
# patch the shim's shebang.
PI_CMD=()

# patch_pi_shebang rewrites a bun-installed `#!/usr/bin/env node` shim to
# `#!/usr/bin/env bun` so the user can invoke `pi` without installing node.
#
# Subtle: bun installs the bin as a SYMLINK pointing into
# node_modules/@earendil-works/pi-coding-agent/dist/cli.js. If we mv/sed-i over
# the symlink we replace it with a regular file and bun loses the package
# context — `import { APP_NAME } from "./config.js"` then can't resolve
# because there is no config.js next to /<bun-bin>/pi.
#
# Solution: follow the symlink to the real cli.js and overwrite that file
# in-place via `cat > target` (preserves inode + symlink).
#
# Returns 0 on success, 1 if patch was unnecessary or impossible.
patch_pi_shebang() {
	local pi_path="$1"

	# Resolve through symlinks. readlink -f works on Linux + recent macOS.
	local real_path
	real_path="$(readlink -f "$pi_path" 2>/dev/null || true)"
	[[ -z "$real_path" ]] && real_path="$pi_path"

	[[ -w "$real_path" ]] || return 1
	local first_line
	first_line="$(head -n1 "$real_path" 2>/dev/null || true)"
	[[ "$first_line" == "#!/usr/bin/env node" ]] || return 1

	local tmp
	tmp="$(mktemp 2>/dev/null)" || return 1
	if { printf '#!/usr/bin/env bun\n'; tail -n +2 "$real_path"; } > "$tmp" 2>/dev/null \
		&& cat "$tmp" > "$real_path"; then
		rm -f "$tmp"
		return 0
	fi
	rm -f "$tmp"
	return 1
}

ensure_pi() {
	add_bun_to_path
	if command -v pi >/dev/null 2>&1; then
		# pi is on PATH — but if it was bun-installed previously and node isn't
		# on PATH, the `#!/usr/bin/env node` shim will fail. Self-heal by
		# patching the shebang to use bun. Idempotent: patch_pi_shebang is a
		# no-op when the shebang is already correct.
		if ! command -v node >/dev/null 2>&1 && find_bun >/dev/null 2>&1; then
			if patch_pi_shebang "$(command -v pi)"; then
				log "patched pi shebang ${C_DIM}(node → bun, no node on PATH)${C_RESET}"
			fi
		fi
		PI_CMD=("pi")
		return 0
	fi

	if ! ensure_bun; then
		return 1
	fi

	local bun_path
	if ! bun_path="$(find_bun 2>/dev/null)"; then
		err "Bun is installed but could not be located."
		return 1
	fi

	warn "'pi' not found — installing via bun"
	log  "running: ${C_BOLD}${bun_path} add -g ${PI_NPM_PACKAGE}${C_RESET}"
	if ! "$bun_path" add -g "$PI_NPM_PACKAGE"; then
		err "bun add -g ${PI_NPM_PACKAGE} failed"
		return 1
	fi

	# bun installs globals to $BUN_INSTALL/bin (default $HOME/.bun/bin).
	# Add it to PATH for this shell so the just-installed pi resolves.
	add_bun_to_path

	local pi_path
	pi_path="$(command -v pi 2>/dev/null || true)"
	if [[ -z "$pi_path" ]]; then
		local bun_bin="${BUN_INSTALL:-$HOME/.bun}/bin"
		err "pi installed via bun but not on PATH"
		err "add ${bun_bin} to PATH (e.g. export PATH=\"${bun_bin}:\$PATH\") then re-run."
		return 1
	fi

	if patch_pi_shebang "$pi_path"; then
		PI_CMD=("pi")
		ok "pi installed via bun ${C_DIM}(shebang patched: node → bun, no node required)${C_RESET}"
	else
		# Patch failed (read-only, weird shim, real node already on PATH, etc).
		# Fall back to invoking via bun runtime for this session at least.
		PI_CMD=("$bun_path" "$pi_path")
		ok "pi installed via bun ${C_DIM}(running through bun runtime)${C_RESET}"
	fi
	return 0
}

write_piolium_wrapper() {
	mkdir -p "$PIOLIUM_BIN_DIR"
	local wrapper="$PIOLIUM_BIN_DIR/piolium"
	local home_default package_default agent_default session_default bun_install_default
	printf -v home_default '%q' "$PIOLIUM_HOME"
	printf -v package_default '%q' "$PIOLIUM_PACKAGE_DIR"
	printf -v agent_default '%q' "$PIOLIUM_AGENT_DIR"
	printf -v session_default '%q' "$PIOLIUM_SESSION_DIR"
	printf -v bun_install_default '%q' "${BUN_INSTALL:-$HOME/.bun}"
	cat > "$wrapper" <<EOF
#!/usr/bin/env bash
set -euo pipefail

if [[ -z "\${PIOLIUM_HOME:-}" ]]; then
	PIOLIUM_HOME=$home_default
fi
if [[ -z "\${PIOLIUM_PACKAGE_DIR:-}" ]]; then
	PIOLIUM_PACKAGE_DIR=$package_default
fi
if [[ -z "\${PIOLIUM_AGENT_DIR:-}" ]]; then
	PIOLIUM_AGENT_DIR=$agent_default
fi
if [[ -z "\${PIOLIUM_SESSION_DIR:-}" ]]; then
	PIOLIUM_SESSION_DIR=$session_default
fi
if [[ -z "\${BUN_INSTALL:-}" ]]; then
	BUN_INSTALL=$bun_install_default
fi

if [[ -d "\$BUN_INSTALL/bin" ]]; then
	case ":\$PATH:" in
		*":\$BUN_INSTALL/bin:"*) ;;
		*) export PATH="\$BUN_INSTALL/bin:\$PATH" ;;
	esac
fi

export PIOLIUM_HOME PIOLIUM_PACKAGE_DIR PIOLIUM_AGENT_DIR PIOLIUM_SESSION_DIR BUN_INSTALL

PIOLIUM_CLI="\$PIOLIUM_PACKAGE_DIR/bin/piolium.mjs"

if [[ ! -f "\$PIOLIUM_CLI" ]]; then
	echo "piolium: launcher not found at \$PIOLIUM_CLI" >&2
	echo "piolium: re-run the installer or set PIOLIUM_PACKAGE_DIR." >&2
	exit 1
fi

if command -v node >/dev/null 2>&1; then
	exec node "\$PIOLIUM_CLI" "\$@"
fi

if command -v bun >/dev/null 2>&1; then
	exec bun "\$PIOLIUM_CLI" "\$@"
fi

echo "piolium: need node or bun on PATH to run \$PIOLIUM_CLI" >&2
exit 1
EOF
	chmod +x "$wrapper"
}

remove_legacy_piolium_wrapper() {
	if [[ "$PIOLIUM_BIN_DIR_EXPLICIT" == "1" ]]; then
		return 0
	fi

	local legacy_wrapper="$PIOLIUM_HOME/bin/piolium"
	if [[ "$legacy_wrapper" != "$PIOLIUM_BIN_DIR/piolium" && -f "$legacy_wrapper" ]]; then
		rm -f "$legacy_wrapper"
		rmdir "$PIOLIUM_HOME/bin" 2>/dev/null || true
	fi
}

# ---- pi install --------------------------------------------------------------
if [[ "$SKIP_PI_INSTALL" == "1" ]]; then
	resolve_piolium_bin_dir
	write_piolium_wrapper
	remove_legacy_piolium_wrapper
	configure_piolium_path
	ok "extracted to ${PIOLIUM_PACKAGE_DIR}"
	log "SKIP_PI_INSTALL=1 — skipping isolated Pi registration."
	log "launcher: ${C_BOLD}${PIOLIUM_BIN_DIR}/piolium${C_RESET}"
	if [[ "$PIOLIUM_PATH_RC_UPDATED" == "1" ]]; then
		log "restart your shell or run: ${C_BOLD}source ${PIOLIUM_PATH_RC_PATH}${C_RESET}"
	fi
	exit 0
fi

if ! ensure_pi; then
	resolve_piolium_bin_dir
	write_piolium_wrapper
	remove_legacy_piolium_wrapper
	configure_piolium_path
	ok "extracted to ${PIOLIUM_PACKAGE_DIR}"
	if [[ "$SKIP_BUN_BOOTSTRAP" == "1" ]]; then
		warn "could not auto-install pi (SKIP_BUN_BOOTSTRAP=1)."
	else
		warn "could not auto-install pi."
		warn "install Bun (${BUN_INSTALL_URL}) or pi (${PI_REPO_URL}), then run:"
	fi
	warn "  PI_CODING_AGENT_DIR=\"${PIOLIUM_AGENT_DIR}\" pi install ${PIOLIUM_PACKAGE_DIR}"
	if [[ "$PIOLIUM_PATH_RC_UPDATED" == "1" ]]; then
		log "restart your shell or run: ${C_BOLD}source ${PIOLIUM_PATH_RC_PATH}${C_RESET}"
	fi
	exit 0
fi

resolve_piolium_bin_dir
write_piolium_wrapper
remove_legacy_piolium_wrapper
configure_piolium_path

log "running: ${C_BOLD}PI_CODING_AGENT_DIR=${PIOLIUM_AGENT_DIR} ${PI_CMD[*]} install ${PIOLIUM_PACKAGE_DIR}${C_RESET}"
PI_CODING_AGENT_DIR="$PIOLIUM_AGENT_DIR" "${PI_CMD[@]}" install "$PIOLIUM_PACKAGE_DIR"

if PIOLIUM_HOME="$PIOLIUM_HOME" PIOLIUM_PACKAGE_DIR="$PIOLIUM_PACKAGE_DIR" "$PIOLIUM_BIN_DIR/piolium" doctor >/dev/null; then
	ok "standalone config ready at ${PIOLIUM_AGENT_DIR}"
else
	warn "standalone doctor reported an issue; run ${PIOLIUM_BIN_DIR}/piolium doctor for details."
fi

activate_installer_paths

case ":$PATH:" in
	*":$PIOLIUM_BIN_DIR:"*)
		ok "done. launcher: ${C_BOLD}${PIOLIUM_BIN_DIR}/piolium${C_RESET}"
		;;
	*)
		ok "done. launcher: ${C_BOLD}${PIOLIUM_BIN_DIR}/piolium${C_RESET}"
		warn "add ${PIOLIUM_BIN_DIR} to PATH to run 'piolium' directly."
		;;
esac

if [[ "$PIOLIUM_PATH_RC_UPDATED" == "1" ]]; then
	log "PATH updated in ${C_BOLD}${PIOLIUM_PATH_RC_PATH}${C_RESET}; restart your shell or run:"
	log "  ${C_BOLD}source ${PIOLIUM_PATH_RC_PATH}${C_RESET}"
elif [[ "$PIOLIUM_PATH_RC_CONFIGURED" == "1" ]]; then
	log "PATH already configured in ${C_BOLD}${PIOLIUM_PATH_RC_PATH}${C_RESET}."
elif [[ "$SKIP_PATH_SETUP" == "1" ]]; then
	warn "SKIP_PATH_SETUP=1 — shell PATH config was not updated."
fi

activate_installer_paths
