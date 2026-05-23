#!/usr/bin/env bash
# Build the current checkout and install it into ~/.piolium using the local bundle.

set -euo pipefail

if [[ "${npm_command:-}" != "run-script" ]]; then
	echo "[piolium] skipping package-manager lifecycle install."
	echo "[piolium] run 'bun run install' to install Piolium locally."
	exit 0
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "[piolium] building local release bundle"
UPLOAD=0 bun run release

echo "[piolium] installing local bundle into ${PIOLIUM_HOME:-$HOME/.piolium}"
bash "$REPO_ROOT/build/dist/install.sh"
