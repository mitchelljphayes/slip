#!/usr/bin/env bash
#
# slip install script — downloads and installs slipd + slip CLI.
#
# On Linux x86_64/aarch64, downloads a prebuilt static (musl) binary from
# GitHub releases. On all other targets (macOS today) — or when a prebuilt
# binary is not available — builds from source via cargo. See
# `install_source()` below.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/mitchelljphayes/slip/main/install.sh | bash
#   curl -sSL ... | bash -s -- --version v0.1.0
#   curl -sSL ... | bash -s -- --prefix /usr/local
#   curl -sSL ... | bash -s -- --uninstall
#
set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────
REPO="mitchelljphayes/slip"
PREFIX="/usr/local"
CONFIG_DIR="/etc/slip"
DATA_DIR="/var/lib/slip"
SERVICE_USER="slip"
VERSION=""

# ── OS detection (set early, used throughout) ─────────────────────────────
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"

# ── Helpers ────────────────────────────────────────────────────────────────
info()  { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
warn()  { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
error() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || error "required command not found: $1"; }

need_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "this script must be run as root (use sudo)"
    fi
}

# detect_arch: prints the rust-style target triple to use for downloads, or
# the literal `source` when no prebuilt binary exists for the host (macOS
# today; any non-linux-musl target). The cargo check in install_source()
# produces a prescriptive error when no prebuilt binary exists AND cargo is
# missing.
detect_arch() {
    local os arch
    os="$OS"
    arch="$(uname -m)"
    case "$os/$arch" in
        linux/x86_64|linux/amd64) echo "x86_64-unknown-linux-musl" ;;
        linux/aarch64|linux/arm64) echo "aarch64-unknown-linux-musl" ;;
        *)                         echo "source" ;;
    esac
}

# sha256_of: prints the SHA-256 digest of <file> using whichever tool is
# available. Returns nonzero when neither sha256sum nor shasum is present.
# Used by checksum_verify so the local archive filename is irrelevant to
# verification: the published sidecar may name the release asset while the
# installer stores the archive as `slip.tar.gz` (SLIP-123).
sha256_of() {
    # sha256_of <file>
    local digest
    if command -v sha256sum >/dev/null 2>&1; then
        digest="$(sha256sum "$1" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        digest="$(shasum -a 256 "$1" | awk '{print $1}')"
    else
        return 1
    fi
    printf '%s\n' "$digest"
}

# checksum_verify: verifies <archive>.sha256 against <archive> by extracting
# the expected digest from the sidecar and comparing it to a digest computed
# over the local archive. The sidecar's filename field is treated as
# untrusted and ignored, so the local archive name does not need to match the
# release asset basename (SLIP-123). Falls back to a warn (no fail) when
# neither sha256sum nor shasum is present; all other failure modes
# (unreadable, malformed, mismatched) fail with a prescriptive error before
# extraction or installation.
checksum_verify() {
    # checksum_verify <archive> <archive.sha256>
    local archive shafile expected actual
    archive="$1"
    shafile="$2"

    # Tool selection is shared with sha256_of; if no tool is available we
    # preserve the historical warn-and-skip behavior rather than failing.
    if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
        warn "neither sha256sum nor shasum found — skipped checksum verification"
        return 0
    fi

    # Read only the first whitespace-delimited field of the first sidecar
    # line. The sidecar is untrusted network input; the filename field is
    # ignored entirely.
    if ! expected="$(awk 'NR==1{print $1; exit}' "$shafile" 2>/dev/null)"; then
        error "checksum verification failed — cannot read sidecar $shafile (re-download the release or verify manually with sha256sum)"
    fi
    if [ -z "$expected" ]; then
        error "checksum verification failed — sidecar $shafile is empty (re-download the release or verify manually with sha256sum)"
    fi

    # Require exactly 64 hexadecimal characters. Separate the length check
    # (so a wrong-length digest is rejected before the hex-content case) and
    # the invalid-hex case (POSIX `case`, no regex).
    if [ "${#expected}" -ne 64 ]; then
        error "checksum verification failed — sidecar digest is not 64 hex characters (got ${#expected}); re-download the release or verify manually with sha256sum"
    fi
    case "$expected" in
        *[!0-9a-fA-F]*)
            error "checksum verification failed — sidecar digest contains non-hex characters; re-download the release or verify manually with sha256sum"
            ;;
    esac

    # Normalize the expected digest to lowercase for a case-insensitive
    # comparison (sha256sum emits lowercase; shasum may emit uppercase on
    # some platforms).
    expected="$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')"

    # Compute the archive digest under its local name.
    if ! actual="$(sha256_of "$archive")"; then
        error "checksum verification failed — could not compute digest of $archive"
    fi
    # shasum on some platforms prefixes a binary-mode `*` marker; awk already
    # stripped to the first field, so `actual` is pure hex. Normalize case.
    actual="$(printf '%s' "$actual" | tr '[:upper:]' '[:lower:]')"

    if [ "$expected" != "$actual" ]; then
        error "checksum verification failed — archive digest $actual does not match sidecar $expected; re-download the release or verify manually with sha256sum"
    fi

    info "Checksum verified."
}

fetch() {
    # fetch <url> <output>
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        error "neither curl nor wget is installed"
    fi
}

# ── install_prebuilt: download + verify + extract + install binaries ───────
# Defined before the test seam so tests can source the installer with
# SLIP_INSTALLER_MAIN=0 and invoke this function directly.
install_prebuilt() {
    # install_prebuilt <version> <target>
    local p_version p_target p_url p_tmpdir
    p_version="$1"
    p_target="$2"

    p_tmpdir="$(mktemp -d)"
    trap 'rm -rf "$p_tmpdir"' RETURN

    p_url="https://github.com/$REPO/releases/download/$p_version/slip-$p_target.tar.gz"
    info "Downloading $p_url..."
    fetch "$p_url" "$p_tmpdir/slip.tar.gz" \
        || { warn "download failed (version $p_version may not have $p_target binaries)"; return 1; }

    # Verify checksum if available
    if fetch "$p_url.sha256" "$p_tmpdir/slip.tar.gz.sha256" 2>/dev/null; then
        info "Verifying checksum..."
        checksum_verify "$p_tmpdir/slip.tar.gz" "$p_tmpdir/slip.tar.gz.sha256"
    fi

    # Extract
    tar -xzf "$p_tmpdir/slip.tar.gz" -C "$p_tmpdir"

    # Install binaries
    install -Dm755 "$p_tmpdir/slipd" "$PREFIX/bin/slipd"
    install -Dm755 "$p_tmpdir/slip"   "$PREFIX/bin/slip"
    info "Binaries installed to $PREFIX/bin/"
}

# ── Test seam ──────────────────────────────────────────────────────────────
# When sourced with SLIP_INSTALLER_MAIN=0, return before top-level argument
# parsing so tests can invoke individual functions (install_prebuilt,
# checksum_verify, sha256_of) without running the installer or the root/need
# guards. Normal execution (the default) is unaffected.
if [ "${SLIP_INSTALLER_MAIN:-1}" = "0" ]; then
    return 0 2>/dev/null || exit 0
fi

# ── Parse args ─────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --version)  VERSION="$2";  shift 2 ;;
        --prefix)   PREFIX="$2";    shift 2 ;;
        --uninstall) UNINSTALL=1;   shift   ;;
        --help|-h)
            cat <<EOF
slip installer

Usage:
  install.sh [options]

Options:
  --version <tag>   Install a specific version (e.g. v0.1.0). Default: latest release.
  --prefix <path>    Install prefix (default: /usr/local).
  --uninstall        Remove slipd, slip, user, and directories.
  --help             Show this help.

On Linux x86_64/aarch64 this downloads the prebuilt static binary. On all
other hosts (macOS today) — or when a prebuilt binary is not available — it
builds from source via cargo (requires the Rust toolchain + git).
EOF
            exit 0
            ;;
        *) error "unknown option: $1" ;;
    esac
done

# ── Uninstall ──────────────────────────────────────────────────────────────
if [ "${UNINSTALL:-0}" = "1" ]; then
    need_root
    info "Uninstalling slip..."

    systemctl stop slipd.service 2>/dev/null || true
    systemctl disable slipd.service 2>/dev/null || true
    rm -f /etc/systemd/system/slipd.service
    systemctl daemon-reload 2>/dev/null || true

    rm -f "$PREFIX/bin/slipd" "$PREFIX/bin/slip"

    if id "$SERVICE_USER" &>/dev/null; then
        userdel "$SERVICE_USER" 2>/dev/null || true
    fi

    read -rp "Remove config and data directories ($CONFIG_DIR, $DATA_DIR)? [y/N] " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR" "$DATA_DIR"
        info "Removed $CONFIG_DIR and $DATA_DIR"
    fi

    info "slip uninstalled."
    exit 0
fi

# ── Install ────────────────────────────────────────────────────────────────
need_root
need uname
need tar

# Determine target
TARGET="$(detect_arch)"
info "Target: $TARGET"

# ── install_source: build from source via cargo ────────────────────────────
install_source() {
    # install_source [version]
    local s_version s_src s_clone_dir s_cleanups s_cargo_home
    s_version="${1:-}"

    # Prescriptive cargo check: name the remedy, not just the missing binary.
    if ! command -v cargo >/dev/null 2>&1; then
        error "no prebuilt binary for $OS/$(uname -m) and cargo not found — install the Rust toolchain (https://rustup.rs) or use a Linux x86_64/aarch64 host with prebuilt binaries"
    fi
    need git

    # Resolve source tree.
    # Heuristic: if the directory containing this script has the workspace
    # Cargo.toml + crates/slip-cli/Cargo.toml, use it in place. Otherwise clone
    # into a temp dir. We deliberately avoid readlink -f (absent on stock
    # macOS) and plain `pwd` (would point at the user's CWD, not the script's
    # dir).
    s_cleanups=()
    _source_cleanup() {
        for d in "${s_cleanups[@]:-}"; do
            [ -n "$d" ] && rm -rf "$d"
        done
    }
    trap '_source_cleanup' RETURN

    local script_dir
    script_dir="$(cd "$(dirname "$0")" && pwd)"
    if [ -f "$script_dir/Cargo.toml" ] && [ -f "$script_dir/crates/slip-cli/Cargo.toml" ]; then
        s_src="$script_dir"
        info "Using local checkout at $s_src"
        if [ -n "$s_version" ]; then
            info "Checking out $s_version in $s_src..."
            if ! git -C "$s_src" fetch --tags --depth 1 origin "$s_version" 2>/dev/null \
               && ! git -C "$s_src" fetch --tags origin "$s_version" 2>/dev/null; then
                error "version $s_version not found in $s_src — check that it's a real git tag (e.g. v0.1.0)"
            fi
            git -C "$s_src" checkout "$s_version"
        else
            # In-place + no version: build the current working tree. Never
            # surprise a dev by checking out a tag in their working tree.
            warn "building from current working tree (not a pinned release) at $s_src"
        fi
    else
        # Clone into a temp dir.
        s_clone_dir="$(mktemp -d)"
        s_cleanups+=("$s_clone_dir")
        s_src="$s_clone_dir/slip"
        if [ -z "$s_version" ]; then
            info "Cloning latest from https://github.com/$REPO.git..."
            git clone --depth 1 "https://github.com/$REPO.git" "$s_src"
        else
            info "Cloning $s_version from https://github.com/$REPO.git..."
            if ! git clone --depth 1 --branch "$s_version" "https://github.com/$REPO.git" "$s_src" 2>/dev/null; then
                # --branch works for tags too; fall back to full clone + checkout
                git clone "https://github.com/$REPO.git" "$s_src"
                if ! git -C "$s_src" checkout "$s_version" 2>/dev/null; then
                    error "version $s_version not found in https://github.com/$REPO.git — check that it's a real git tag (e.g. v0.1.0)"
                fi
            fi
        fi
    fi

    # Hygienic CARGO_HOME under the temp dir so we don't pollute /root/.cargo
    # when run under sudo.
    s_cargo_home="$(mktemp -d)/cargo-home"
    s_cleanups+=("$(dirname "$s_cargo_home")")
    mkdir -p "$s_cargo_home"

    info "Building + installing slip-cli (release)..."
    CARGO_HOME="$s_cargo_home" cargo install --locked --root "$PREFIX" \
        --path "$s_src/crates/slip-cli" \
        || CARGO_HOME="$s_cargo_home" cargo install --root "$PREFIX" \
            --path "$s_src/crates/slip-cli"

    info "Building + installing slipd (release)..."
    CARGO_HOME="$s_cargo_home" cargo install --locked --root "$PREFIX" \
        --path "$s_src/crates/slipd" \
        || CARGO_HOME="$s_cargo_home" cargo install --root "$PREFIX" \
            --path "$s_src/crates/slipd"

    info "Binaries installed to $PREFIX/bin/"
}

# ── Dispatch ───────────────────────────────────────────────────────────────
if [ "$TARGET" = "source" ]; then
    install_source "$VERSION"
else
    # Prebuilt path: resolve latest version if VERSION empty (only needed here).
    if [ -z "$VERSION" ]; then
        info "Detecting latest release..."
        VERSION=$(fetch "https://api.github.com/repos/$REPO/releases/latest" - \
            | grep '"tag_name"' \
            | head -1 \
            | sed -E 's/.*"([^"]+)".*/\1/')
        [ -z "$VERSION" ] && error "could not determine latest release version"
    fi
    info "Installing slip $VERSION"
    if ! install_prebuilt "$VERSION" "$TARGET"; then
        warn "no prebuilt binary for $OS/$(uname -m) — falling back to source build"
        install_source "$VERSION"
    fi
fi

# ── OS-guarded Linux-only setup ─────────────────────────────────────────────
# Service user, container-runtime group, and /etc + /var/lib directory setup
# are Linux-only. On macOS (and any other non-Linux host) slipd runs as the
# invoking user with prefix-relative paths — there is no systemd, useradd,
# or chown equivalent to set up here.
if [ "$OS" = "linux" ]; then
    # Create service user
    if ! id "$SERVICE_USER" &>/dev/null; then
        info "Creating service user '$SERVICE_USER'..."
        useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    fi

    # Add to container runtime group (Docker or Podman)
    for group in docker podman; do
        if getent group "$group" &>/dev/null; then
            usermod -aG "$group" "$SERVICE_USER"
            info "Added $SERVICE_USER to $group group"
            break
        fi
    done

    # Create directories
    mkdir -p "$CONFIG_DIR/apps"
    mkdir -p "$DATA_DIR/state" "$DATA_DIR/secrets" "$DATA_DIR/volumes"
    chown -R "$SERVICE_USER":"$SERVICE_USER" "$DATA_DIR" "$CONFIG_DIR"
else
    # Non-Linux hosts: ensure the prefix-relative config/data dirs exist so
    # slipd has somewhere to write when run with --prefix. Owned by the
    # invoking user (already root).
    mkdir -p "$PREFIX/etc/slip/apps" 2>/dev/null || true
    mkdir -p "$PREFIX/var/lib/slip/state" "$PREFIX/var/lib/slip/secrets" "$PREFIX/var/lib/slip/volumes" 2>/dev/null || true
fi

# ─── UFW bridge DNS rule — NOT added here (SLIP-102 follow-up) ────────────────
# The FR §3.8 remedy (`ufw allow in on <bridge> to any port 53`) requires the
# slip network's bridge interface name, which only exists after slipd's
# `ensure_network` runs on first start (slipd/src/main.rs:135). At install.sh
# time the network doesn't exist yet, so we can't name the bridge.
#
# The immediate remedy path is `sudo slip doctor --fix`, which detects the
# missing rule and applies it (with confirmation + rollback). The right home
# for automatic install-time UFW setup is `slip server init`'s post-bootstrap
# phase (after slipd has created the network) — tracked as a SLIP-102
# follow-up ticket. See `slip doctor --help` and
# `.opencode/sessions/2026-07-12_09-55-18_SLIP-102_slip-doctor/plan.md` for
# the full rationale.

info ""
info "✅ slip ${VERSION:-current tree} installed successfully!"
info ""

# Offer to run `slip server init` (TTY-gated)
if [ -t 0 ] && [ "${SLIP_NONINTERACTIVE:-0}" != "1" ]; then
    info "Run 'slip server init' now to configure the server?"
    printf "  [Y/n] " >&2
    read -r reply
    case "$reply" in
        n*|N*) info "Skipped. Run 'slip server init' later as root." ;;
        *)     exec "$PREFIX/bin/slip" server init ;;
    esac
else
    info "Run 'slip server init' as root to configure the server."
fi