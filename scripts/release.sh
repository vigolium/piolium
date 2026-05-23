#!/usr/bin/env bash
# Package piolium into a local installable release bundle.
#
# Steps:
#   1. Warn on dirty working tree
#   2. tar czf build/dist/piolium.tar.gz (with excludes)
#   3. sha256 checksum
#   4. copy install.sh next to the tarball so `bash build/dist/install.sh` works
#   5. upload tarball + checksum + install.sh to R2 by default
#   6. If INSTALL_BASE_URL is set, fetch ?cb=<nonce> and compare sha256
#
# Env overrides:
#   UPLOAD           Set to 0 to skip R2 upload. Default: 1
#   R2_ALIAS         (default: r2)
#   R2_BUCKET        (default: vigolium-dist)
#   R2_PREFIX        (default: piolium-93833b71e48cb63548bea5a537313da6)
#   TARBALL_NAME     (default: piolium.tar.gz)
#   OUT_DIR          (default: build/dist)
#   INSTALL_BASE_URL (optional; e.g. https://cdn.example.com — verify CDN if set)
#   SKIP_CDN_VERIFY  (set to 1 to skip the verify step even if INSTALL_BASE_URL is set)

set -euo pipefail

UPLOAD="${UPLOAD:-1}"
R2_ALIAS="${R2_ALIAS:-r2}"
R2_BUCKET="${R2_BUCKET:-vigolium-dist}"
R2_PREFIX="${R2_PREFIX:-piolium-93833b71e48cb63548bea5a537313da6}"
TARBALL_NAME="${TARBALL_NAME:-piolium.tar.gz}"
OUT_DIR="${OUT_DIR:-build/dist}"
INSTALL_BASE_URL="${INSTALL_BASE_URL:-}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

TARBALL="$OUT_DIR/$TARBALL_NAME"
CHECKSUM="$OUT_DIR/${TARBALL_NAME%.tar.gz}.checksum.txt"
LOCAL_INSTALLER="$OUT_DIR/install.sh"
INSTALLER_SRC="$REPO_ROOT/scripts/install.sh"

if command -v shasum >/dev/null 2>&1; then
  SHA256=(shasum -a 256)
elif command -v sha256sum >/dev/null 2>&1; then
  SHA256=(sha256sum)
else
  echo "[release] ERROR: need shasum or sha256sum" >&2
  exit 1
fi

TAR_METADATA_ARGS=()
if tar --help 2>&1 | grep -q -- '--no-mac-metadata'; then
  TAR_METADATA_ARGS+=(--no-mac-metadata)
fi
if tar --help 2>&1 | grep -q -- '--no-xattrs'; then
  TAR_METADATA_ARGS+=(--no-xattrs)
fi

echo "[release] repo:    $REPO_ROOT"
echo "[release] tarball: $TARBALL"
if [[ "$UPLOAD" == "1" ]]; then
  echo "[release] target:  $R2_ALIAS/$R2_BUCKET/$R2_PREFIX/"
else
  echo "[release] target:  local bundle only (UPLOAD=0)"
fi

# ---- 1. Dirty-tree warning ----------------------------------------------------
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if ! git diff --quiet 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; then
    echo "[release] WARN: working tree has uncommitted changes — packaging as-is."
  fi
fi

# ---- 2. Refresh the vendored yaml bundle -------------------------------------
# The extension imports yaml from extensions/piolium/_vendor/yaml.bundle.mjs so
# that fresh `pi install <repo-path>` clones (with no node_modules populated)
# can load the extension. Rebuild from the dev-time `yaml` package each release
# so the vendored copy stays in lockstep with package.json's devDeps version.
VENDOR_BUNDLE="$REPO_ROOT/extensions/piolium/_vendor/yaml.bundle.mjs"
if [[ -f "$REPO_ROOT/node_modules/yaml/dist/index.js" ]]; then
  echo "[release] refreshing $VENDOR_BUNDLE"
  bun build "$REPO_ROOT/node_modules/yaml/dist/index.js" \
    --outfile "$VENDOR_BUNDLE" \
    --target node --format esm --minify >/dev/null
else
  echo "[release] WARN: node_modules/yaml not present — using existing $VENDOR_BUNDLE as-is."
  echo "         Run 'bun install' before release to refresh the vendored bundle."
fi

# ---- 3. Build the tarball ----------------------------------------------------
mkdir -p "$OUT_DIR"
rm -f "$TARBALL" "$CHECKSUM" "$LOCAL_INSTALLER"

if [[ ! -f "$INSTALLER_SRC" ]]; then
  echo "[release] ERROR: $INSTALLER_SRC missing — install.sh must live alongside release.sh." >&2
  exit 1
fi

# COPYFILE_DISABLE + --no-mac-metadata + --no-xattrs strip BSD-tar's macOS
# extended-attribute headers. GNU tar on Linux prints one
# "Ignoring unknown extended header keyword 'LIBARCHIVE.xattr.…'" line per
# file otherwise, which spams the install output for hundreds of lines.
# If a previous run generated audit output at the repo root, drop it before
# packaging. Don't use `--exclude=./piolium` here — BSD tar matches the
# pattern against any path *component* named `piolium`, which would also
# strip `./extensions/piolium/` (the entire extension source tree).
if [[ -d "$REPO_ROOT/piolium" ]]; then
  echo "[release] removing top-level piolium/ audit output before packaging"
  rm -rf "$REPO_ROOT/piolium"
fi

COPYFILE_DISABLE=1 tar -czf "$TARBALL" \
  "${TAR_METADATA_ARGS[@]}" \
  --exclude='./node_modules' \
  --exclude='./.git' \
  --exclude='./.env' \
  --exclude='./.env.local' \
  --exclude='./.DS_Store' \
  --exclude='./build' \
  --exclude='./dist' \
  --exclude='./test' \
  --exclude='./coverage' \
  --exclude='./*.log' \
  -C "$REPO_ROOT" .

# Sanity check: real .env files must never ship.
LEAKED=$(tar -tzf "$TARBALL" | grep -E '^\./\.env(\.local)?$' || true)
if [[ -n "$LEAKED" ]]; then
  echo "[release] ERROR: tarball contains secret env files — refusing to upload." >&2
  echo "$LEAKED" | sed 's/^/  /' >&2
  exit 1
fi

SIZE=$(du -h "$TARBALL" | awk '{print $1}')
echo "[release] packaged: $TARBALL ($SIZE)"

# ---- 3. Checksum -------------------------------------------------------------
( cd "$OUT_DIR" && "${SHA256[@]}" "$TARBALL_NAME" > "$(basename "$CHECKSUM")" )
LOCAL_SHA=$(awk '{print $1}' "$CHECKSUM")
echo "[release] sha256:   $LOCAL_SHA"

# ---- 4. Local installer ------------------------------------------------------
cp "$INSTALLER_SRC" "$LOCAL_INSTALLER"
chmod +x "$LOCAL_INSTALLER"
echo "[release] installer: $LOCAL_INSTALLER"
echo "[release] local install command:"
echo "          bash $LOCAL_INSTALLER"

# ---- 5. Upload to R2 ---------------------------------------------------------
if [[ "$UPLOAD" != "1" ]]; then
  echo "[release] upload skipped (UPLOAD=0)."
  echo "[release] done."
  exit 0
fi

if ! command -v mc >/dev/null 2>&1; then
  echo "[release] ERROR: mc (minio client) not found — install it or run with UPLOAD=0." >&2
  exit 1
fi

DEST="$R2_ALIAS/$R2_BUCKET/$R2_PREFIX/"
echo "[release] uploading to $DEST"
mc cp "$TARBALL"       "$DEST"
mc cp "$CHECKSUM"      "$DEST"
mc cp "$LOCAL_INSTALLER" "$DEST"

# ---- 6. CDN verify -----------------------------------------------------------
if [[ -n "$INSTALL_BASE_URL" && "${SKIP_CDN_VERIFY:-0}" != "1" ]]; then
  CB="$(date +%s%N)"
  URL="${INSTALL_BASE_URL%/}/$TARBALL_NAME?cb=$CB"
  echo "[release] verifying CDN: $URL"
  REMOTE_SHA=$(curl -fsSL "$URL" | "${SHA256[@]}" | awk '{print $1}')
  if [[ "$REMOTE_SHA" != "$LOCAL_SHA" ]]; then
    echo "[release] ERROR: CDN sha256 mismatch" >&2
    echo "  local:  $LOCAL_SHA" >&2
    echo "  remote: $REMOTE_SHA" >&2
    echo "  (Cloudflare edge cache may be stale — retry with a fresh ?cb= or purge.)" >&2
    exit 1
  fi
  echo "[release] CDN OK ($REMOTE_SHA)"
else
  echo "[release] CDN verify skipped (set INSTALL_BASE_URL to enable)."
fi

echo "[release] done."
