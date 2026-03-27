#!/usr/bin/env bash
# slip smoke test — end-to-end validation of the deploy flow
#
# Prerequisites:
#   - Docker running
#   - Caddy running (or will be started by slipd bootstrap)
#   - slipd binary built (cargo build --release)
#
# Usage:
#   ./scripts/smoke-test.sh
#
# Environment variables:
#   SLIP_BIN      - path to slipd binary (default: ./target/release/slipd)
#   SLIP_SECRET   - HMAC secret for signing (default: test-secret)
#   TIMEOUT       - max seconds to wait for deploy (default: 120)

set -euo pipefail

# Configurable
SLIP_BIN="${SLIP_BIN:-./target/release/slipd}"
SLIP_SECRET="${SLIP_SECRET:-test-secret}"
TIMEOUT="${TIMEOUT:-120}"
APP="smoke-test"
IMAGE="nginx"
TAG1="alpine"
TAG2="stable-alpine"

# Temp directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TEMP_DIR=$(mktemp -d)
CONFIG_DIR="$TEMP_DIR/config"
STATE_DIR="$TEMP_DIR/state"

# Cleanup on exit
cleanup() {
    local exit_code=$?
    echo ""
    echo ">>> Cleaning up..."
    
    # Stop slipd if running
    if [ -n "${SLIPD_PID:-}" ] && kill -0 "$SLIPD_PID" 2>/dev/null; then
        echo "Stopping slipd (PID $SLIPD_PID)..."
        kill "$SLIPD_PID" 2>/dev/null || true
        wait "$SLIPD_PID" 2>/dev/null || true
    fi
    
    # Remove test containers
    echo "Removing test containers..."
    docker ps -a --filter "label=slip.app=$APP" --format "{{.ID}}" | while read -r cid; do
        docker rm -f "$cid" 2>/dev/null || true
    done
    
    # Remove temp directory
    rm -rf "$TEMP_DIR"
    
    echo "Cleanup complete."
    exit $exit_code
}
trap cleanup EXIT

# Helper: JSON parsing with jq or python3 fallback
json_get() {
    local json="$1"
    local key="$2"
    if command -v jq &>/dev/null; then
        echo "$json" | jq -r "$key // empty"
    else
        echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get($key,''))" 2>/dev/null || echo ""
    fi
}

# Helper: Compute HMAC-SHA256 signature
compute_signature() {
    local payload="$1"
    printf '%s' "$payload" | openssl dgst -sha256 -hmac "$SLIP_SECRET" | cut -d' ' -f2
}

# Helper: Send deploy webhook
send_deploy() {
    local tag="$1"
    local payload
    payload=$(printf '{"app":"%s","image":"%s","tag":"%s"}' "$APP" "$IMAGE" "$tag")
    local sig
    sig=$(compute_signature "$payload")
    
    curl -s -w "\n%{http_code}" -X POST "http://localhost:7890/v1/deploy" \
        -H "Content-Type: application/json" \
        -H "X-Slip-Signature: sha256=$sig" \
        -d "$payload"
}

# Helper: Poll for deploy completion
poll_deploy() {
    local deploy_id="$1"
    local start_time
    start_time=$(date +%s)
    
    while true; do
        local elapsed
        elapsed=$(( $(date +%s) - start_time ))
        if [ "$elapsed" -gt "$TIMEOUT" ]; then
            echo "FAIL: deploy timed out after ${TIMEOUT}s"
            return 1
        fi
        
        local response
        response=$(curl -s "http://localhost:7890/v1/deploys/$deploy_id")
        local status
        status=$(json_get "$response" "'.status'")
        
        printf "  [%3ds] %s\r" "$elapsed" "$status"
        
        case "$status" in
            completed)
                echo ""
                echo "PASS: deploy completed in ${elapsed}s"
                return 0
                ;;
            failed)
                local error
                error=$(json_get "$response" "'.error'")
                echo ""
                echo "FAIL: deploy failed: $error"
                return 1
                ;;
            *)
                sleep 2
                ;;
        esac
    done
}

echo "=== slip smoke test ==="
echo ""

# ── Setup ──────────────────────────────────────────────────────────────────────
echo ">>> Setting up test environment..."

# Create config directory structure
mkdir -p "$CONFIG_DIR/apps"
mkdir -p "$STATE_DIR"

# Write slip.toml
cat > "$CONFIG_DIR/slip.toml" <<EOF
[server]
listen = "127.0.0.1:7890"

[auth]
secret = "$SLIP_SECRET"

[caddy]
admin_api = "http://127.0.0.1:2019"

[storage]
path = "$STATE_DIR"

[registry]
# No GHCR token needed for nginx
EOF

# Write app config
cat > "$CONFIG_DIR/apps/$APP.toml" <<EOF
[app]
name = "$APP"
image = "$IMAGE"

[routing]
domain = "$APP.localhost"
port = 80

[health]
path = "/"
interval = "1s"
timeout = "3s"
retries = 10
start_period = "3s"

[deploy]
strategy = "blue-green"
drain_timeout = "2s"

[network]
name = "slip"
EOF

echo "Config dir: $CONFIG_DIR"
echo ""

# ── Build slipd if needed ──────────────────────────────────────────────────────
if [ ! -x "$SLIP_BIN" ]; then
    echo ">>> Building slipd..."
    cargo build --release --bin slipd
    SLIP_BIN="$PROJECT_DIR/target/release/slipd"
fi

# ── Start slipd ─────────────────────────────────────────────────────────────────
echo ">>> Starting slipd..."
"$SLIP_BIN" --config "$CONFIG_DIR/slip.toml" &
SLIPD_PID=$!
echo "slipd PID: $SLIPD_PID"

# Wait for slipd to be ready
echo "Waiting for slipd to be ready..."
for i in {1..30}; do
    if curl -s "http://localhost:7890/v1/status" >/dev/null 2>&1; then
        echo "slipd is ready"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "FAIL: slipd did not start within 30s"
        exit 1
    fi
    sleep 1
done
echo ""

# ── Test 1: First deploy ────────────────────────────────────────────────────────
echo ""
echo "=== Test 1: First deploy ($TAG1) ==="
echo ""

RESPONSE=$(send_deploy "$TAG1")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" != "202" ]; then
    echo "FAIL: expected 202, got $HTTP_CODE"
    echo "$BODY"
    exit 1
fi
echo "PASS: deploy accepted (202)"

DEPLOY_ID=$(json_get "$BODY" "'.deploy_id'")
if [ -z "$DEPLOY_ID" ]; then
    echo "FAIL: could not extract deploy_id"
    exit 1
fi
echo "Deploy ID: $DEPLOY_ID"

poll_deploy "$DEPLOY_ID" || exit 1

# Verify container is running
echo "Verifying container..."
CONTAINER_COUNT=$(docker ps --filter "label=slip.app=$APP" --format "{{.ID}}" | wc -l | tr -d ' ')
if [ "$CONTAINER_COUNT" -ne 1 ]; then
    echo "FAIL: expected 1 running container, found $CONTAINER_COUNT"
    exit 1
fi
echo "PASS: 1 container running"

# ── Test 2: Second deploy (blue-green) ──────────────────────────────────────────
echo ""
echo "=== Test 2: Second deploy ($TAG2) ==="
echo ""

RESPONSE=$(send_deploy "$TAG2")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" != "202" ]; then
    echo "FAIL: expected 202, got $HTTP_CODE"
    exit 1
fi
echo "PASS: deploy accepted (202)"

DEPLOY_ID=$(json_get "$BODY" "'.deploy_id'")
echo "Deploy ID: $DEPLOY_ID"

poll_deploy "$DEPLOY_ID" || exit 1

# Verify only one container running (old one stopped)
echo "Verifying container..."
CONTAINER_COUNT=$(docker ps --filter "label=slip.app=$APP" --format "{{.ID}}" | wc -l | tr -d ' ')
if [ "$CONTAINER_COUNT" -ne 1 ]; then
    echo "FAIL: expected 1 running container, found $CONTAINER_COUNT"
    exit 1
fi
echo "PASS: 1 container running (old stopped)"

# ── Test 3: Failed deploy (rollback) ────────────────────────────────────────────
echo ""
echo "=== Test 3: Failed deploy (nonexistent image) ==="
echo ""

# Save current container ID
OLD_CONTAINER=$(docker ps --filter "label=slip.app=$APP" --format "{{.ID}}" | head -1)

RESPONSE=$(send_deploy "nonexistent-image-tag-12345")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" != "202" ]; then
    echo "FAIL: expected 202, got $HTTP_CODE"
    exit 1
fi
echo "PASS: deploy accepted (202)"

DEPLOY_ID=$(json_get "$BODY" "'.deploy_id'")
echo "Deploy ID: $DEPLOY_ID"

# This should fail
if poll_deploy "$DEPLOY_ID"; then
    echo "FAIL: expected deploy to fail for nonexistent image"
    exit 1
fi
echo "PASS: deploy failed as expected"

# Verify old container is still running
echo "Verifying rollback..."
NEW_CONTAINER=$(docker ps --filter "label=slip.app=$APP" --format "{{.ID}}" | head -1)
if [ "$OLD_CONTAINER" != "$NEW_CONTAINER" ]; then
    echo "FAIL: container changed after failed deploy (expected rollback)"
    echo "  Old: $OLD_CONTAINER"
    echo "  New: $NEW_CONTAINER"
    exit 1
fi
echo "PASS: old container still running (rollback successful)"

# ── Final status check ──────────────────────────────────────────────────────────
echo ""
echo ">>> Final status check..."
curl -s "http://localhost:7890/v1/status" | python3 -m json.tool 2>/dev/null || \
    curl -s "http://localhost:7890/v1/status"

echo ""
echo "=== all smoke tests passed ==="
