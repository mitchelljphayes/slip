#!/usr/bin/env bash
set -euo pipefail

# Configurable
SLIP_URL="${SLIP_URL:-http://localhost:7890}"
SLIP_SECRET="${SLIP_SECRET:-test-secret}"
APP="${APP:-smoke-test}"
IMAGE="${IMAGE:-nginx}"
TAG="${TAG:-alpine}"
TIMEOUT="${TIMEOUT:-60}"

echo "=== slip smoke test ==="
echo "URL:    $SLIP_URL"
echo "App:    $APP"
echo "Image:  $IMAGE:$TAG"
echo ""

# Build the deploy payload
PAYLOAD=$(printf '{"app":"%s","image":"%s","tag":"%s"}' "$APP" "$IMAGE" "$TAG")

# Compute HMAC-SHA256 signature
SIGNATURE=$(printf '%s' "$PAYLOAD" | openssl dgst -sha256 -hmac "$SLIP_SECRET" | cut -d' ' -f2)

# Send deploy webhook
echo ">>> Sending deploy webhook..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$SLIP_URL/v1/deploy" \
  -H "Content-Type: application/json" \
  -H "X-Slip-Signature: sha256=$SIGNATURE" \
  -d "$PAYLOAD")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" != "202" ]; then
  echo "FAIL: expected 202, got $HTTP_CODE"
  echo "$BODY"
  exit 1
fi

echo "PASS: deploy accepted (202)"
DEPLOY_ID=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['deploy_id'])" 2>/dev/null || echo "")

if [ -z "$DEPLOY_ID" ]; then
  echo "WARN: could not extract deploy_id from response"
  echo "$BODY"
  exit 1
fi

echo "Deploy ID: $DEPLOY_ID"
echo ""

# Poll for completion
echo ">>> Polling deploy status..."
START_TIME=$(date +%s)

while true; do
  ELAPSED=$(( $(date +%s) - START_TIME ))
  if [ "$ELAPSED" -gt "$TIMEOUT" ]; then
    echo "FAIL: deploy timed out after ${TIMEOUT}s"
    exit 1
  fi

  STATUS_RESPONSE=$(curl -s "$SLIP_URL/v1/deploys/$DEPLOY_ID")
  STATUS=$(echo "$STATUS_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null || echo "unknown")

  echo "  [${ELAPSED}s] status: $STATUS"

  case "$STATUS" in
    completed)
      echo ""
      echo "PASS: deploy completed in ${ELAPSED}s"
      break
      ;;
    failed)
      ERROR=$(echo "$STATUS_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error','unknown'))" 2>/dev/null || echo "unknown")
      echo ""
      echo "FAIL: deploy failed: $ERROR"
      exit 1
      ;;
    *)
      sleep 2
      ;;
  esac
done

# Check daemon status
echo ""
echo ">>> Checking daemon status..."
STATUS_RESPONSE=$(curl -s "$SLIP_URL/v1/status")
echo "$STATUS_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$STATUS_RESPONSE"

echo ""
echo "=== smoke test passed ==="
