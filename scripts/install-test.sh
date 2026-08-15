#!/usr/bin/env bash
# slip installer regression test (SLIP-123)
#
# Verifies that install_prebuilt() checks a downloaded Linux archive
# against its published .sha256 sidecar. The sidecar names the release
# asset, but the installer stores the archive as `slip.tar.gz`. Covers
# the success, mismatch, and malformed-digest cases. Uses no live
# network and no root: `fetch` is stubbed to copy local fixtures, and
# `install` targets a temporary prefix.
#
# Usage:
#   bash scripts/install-test.sh
#
# Exit codes: 0 all cases passed · 1 one or more cases failed.

set -euo pipefail

# ── Setup ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
INSTALLER="$PROJECT_DIR/install.sh"

WORK="$(mktemp -d)"
PREFIX="$WORK/prefix"
FIXTURE_DIR="$WORK/fixtures"
mkdir -p "$FIXTURE_DIR" "$PREFIX/bin"

cleanup() {
    local exit_code=$?
    rm -rf "$WORK"
    exit "$exit_code"
}
trap cleanup EXIT

# fail <message>: print failure and exit the harness non-zero. The cleanup
# trap propagates the exit code after removing the temp dir.
fail() {
    echo "FAIL: $1" >&2
    exit 1
}

# Source the installer with the test seam so only the function definitions are
# loaded: argument parsing, need_root, and dispatch do not run.
# shellcheck source=/dev/null
SLIP_INSTALLER_MAIN=0 . "$INSTALLER"

# ── Fixture generation ───────────────────────────────────────────────────────
# Build a release-style archive: bare `slip` and `slipd` entries (no top-level
# directory), matching .github/workflows/release.yml packaging.
ASSET_NAME="slip-x86_64-unknown-linux-musl.tar.gz"
ARCHIVE="$FIXTURE_DIR/$ASSET_NAME"

stage="$WORK/stage"
mkdir -p "$stage"
{
    printf '#!/usr/bin/env bash\necho "slip stub"\n' > "$stage/slip"
    printf '#!/usr/bin/env bash\necho "slipd stub"\n' > "$stage/slipd"
}
chmod 755 "$stage/slip" "$stage/slipd"
tar -czf "$ARCHIVE" -C "$stage" slip slipd
rm -rf "$stage"

REAL_DIGEST="$(sha256sum "$ARCHIVE" | awk '{print $1}')"

# Published sidecar names the release asset (NOT `slip.tar.gz`). This is the
# exact regression case: the installer saves the archive as `slip.tar.gz` but
# the sidecar references `slip-x86_64-unknown-linux-musl.tar.gz`.
write_sidecar() {
    # write_sidecar <path> <digest-or-junk>
    printf '%s  %s\n' "$2" "$ASSET_NAME" > "$1"
}

SIDECAR_OK="$FIXTURE_DIR/ok.sha256"
SIDECAR_MISMATCH="$FIXTURE_DIR/mismatch.sha256"
SIDECAR_MALFORMED="$FIXTURE_DIR/malformed.sha256"

write_sidecar "$SIDECAR_OK" "$REAL_DIGEST"
write_sidecar "$SIDECAR_MISMATCH" "1111111111111111111111111111111111111111111111111111111111111111"
# Wrong-length + non-hex: a single `z`; fails the length check first.
write_sidecar "$SIDECAR_MALFORMED" "z"

# ── Stub fetch ───────────────────────────────────────────────────────────────
# Override the installer's `fetch` so no network is used. Maps by URL suffix:
# *.sha256 → the currently-selected sidecar fixture; otherwise → the archive.
# A missing sidecar fixture makes `fetch` return nonzero, preserving the
# installer's existing "missing sidecar → skip verification" policy.
CURRENT_SIDECAR="$SIDECAR_OK"
fetch() {
    # fetch <url> <output>
    case "$1" in
        *.sha256)
            if [ -f "$CURRENT_SIDECAR" ]; then
                cp "$CURRENT_SIDECAR" "$2"
            else
                return 1
            fi
            ;;
        *)
            cp "$ARCHIVE" "$2"
            ;;
    esac
}

# ── Case runner ──────────────────────────────────────────────────────────────
# run_case <name> <expected_exit> <sidecar>: runs install_prebuilt in a subshell
# against a fresh prefix and asserts the exit code and that the binaries are
# present (success) or absent (failure).
run_case() {
    local name="$1" expected_exit="$2" sidecar="$3" rc prefix
    CURRENT_SIDECAR="$sidecar"
    prefix="$WORK/prefix-$name"
    mkdir -p "$prefix/bin"

    # install_prebuilt references the global PREFIX; set it per case.
    PREFIX="$prefix"

    # Run in a subshell so `error` (which calls exit 1) cannot terminate the
    # harness. Suppress the installer's colored stderr noise.
    rc=0
    ( install_prebuilt "v0.0.0-test" "x86_64-unknown-linux-musl" ) >/dev/null 2>&1 || rc=$?

    if [ "$rc" -ne "$expected_exit" ]; then
        fail "$name: expected exit $expected_exit, got $rc"
    fi

    if [ "$expected_exit" -eq 0 ]; then
        # Success: both binaries must be present and executable.
        if [ ! -x "$prefix/bin/slip" ] || [ ! -x "$prefix/bin/slipd" ]; then
            fail "$name: expected slip and slipd installed in $prefix/bin"
        fi
    else
        # Failure: neither binary may be installed.
        if [ -e "$prefix/bin/slip" ] || [ -e "$prefix/bin/slipd" ]; then
            fail "$name: binaries installed despite verification failure"
        fi
    fi

    echo "PASS: $name (exit $rc)"
}

# ── Cases ────────────────────────────────────────────────────────────────────
# 1. Matching digest, sidecar names the published asset, archive stored as
#    `slip.tar.gz`: the original SLIP-123 regression. Must succeed and install
#    both binaries.
run_case "matching" 0 "$SIDECAR_OK"

# 2. Mismatched digest: must fail before either binary is installed.
run_case "mismatch" 1 "$SIDECAR_MISMATCH"

# 3. Malformed (wrong-length, non-hex) digest: must fail before installation.
run_case "malformed" 1 "$SIDECAR_MALFORMED"

echo ""
echo "All installer regression cases passed."
exit 0