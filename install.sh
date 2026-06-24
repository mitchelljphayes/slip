#!/usr/bin/env bash
#
# slip install script — downloads and installs slipd + slip CLI.
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

detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)  echo "x86_64-unknown-linux-musl" ;;
        aarch64|arm64) echo "aarch64-unknown-linux-musl" ;;
        *)             error "unsupported architecture: $arch" ;;
    esac
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

# Determine version
if [ -z "$VERSION" ]; then
    info "Detecting latest release..."
    VERSION=$(fetch "https://api.github.com/repos/$REPO/releases/latest" - \
        | grep '"tag_name"' \
        | head -1 \
        | sed -E 's/.*"([^"]+)".*/\1/')
    [ -z "$VERSION" ] && error "could not determine latest release version"
fi
info "Installing slip $VERSION"

# Determine target
TARGET="$(detect_arch)"
info "Target: $TARGET"

# Download
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

URL="https://github.com/$REPO/releases/download/$VERSION/slip-$TARGET.tar.gz"
info "Downloading $URL..."
fetch "$URL" "$TMPDIR/slip.tar.gz" \
    || error "download failed (version $VERSION may not have $TARGET binaries)"

# Verify checksum if available
SHA_URL="$URL.sha256"
if fetch "$SHA_URL" "$TMPDIR/slip.tar.gz.sha256" 2>/dev/null; then
    info "Verifying checksum..."
    (cd "$TMPDIR" && sha256sum -c slip.tar.gz.sha256) \
        || error "checksum verification failed"
fi

# Extract
tar -xzf "$TMPDIR/slip.tar.gz" -C "$TMPDIR"

# Install binaries
install -Dm755 "$TMPDIR/slipd" "$PREFIX/bin/slipd"
install -Dm755 "$TMPDIR/slip"   "$PREFIX/bin/slip"
info "Binaries installed to $PREFIX/bin/"

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

# Write default config if none exists
if [ ! -f "$CONFIG_DIR/slip.toml" ]; then
    info "Writing default config to $CONFIG_DIR/slip.toml..."
    cat > "$CONFIG_DIR/slip.toml" <<'EOF'
[server]
listen = "127.0.0.1:7890"

[runtime]
backend = "auto"

[caddy]
admin_api = "http://localhost:2019"

[storage]
path = "/var/lib/slip"
EOF
    chown "$SERVICE_USER":"$SERVICE_USER" "$CONFIG_DIR/slip.toml"
fi

# Install systemd service
info "Installing systemd service..."
cat > /etc/systemd/system/slipd.service <<EOF
[Unit]
Description=slip deploy daemon
After=network-online.target podman.service docker.service caddy.service
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=$PREFIX/bin/slipd --config $CONFIG_DIR
Restart=on-failure
RestartSec=5
Environment="RUST_LOG=info"

# Hardening
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$DATA_DIR $CONFIG_DIR

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

info ""
info "✅ slip $VERSION installed successfully!"
info ""
info "Next steps:"
info "  1. Edit $CONFIG_DIR/slip.toml"
info "  2. Create app configs in $CONFIG_DIR/apps/"
info "  3. Validate:          slipd --config $CONFIG_DIR --check"
info "  4. Start the service:  systemctl enable --now slipd"
info "  5. Check logs:         journalctl -u slipd -f"
info ""
info "See https://github.com/$REPO/blob/main/docs/getting-started.md"
info "for full setup instructions."