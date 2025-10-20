#!/bin/sh
set -e

PROXY_HOST="openconnect-proxy"
HTTP_PORT=8888
SOCKS_PORT=8889
TARGET_URL="http://example.com"
RETRIES=3
PASSED=0
FAILED=0

apk add --no-cache curl > /dev/null 2>&1

test_proxy() {
  name="$1"
  proxy_url="$2"
  attempt=1

  while [ "$attempt" -le "$RETRIES" ]; do
    if curl -sf --max-time 10 --proxy "$proxy_url" "$TARGET_URL" > /dev/null 2>&1; then
      echo "PASS: $name"
      PASSED=$((PASSED + 1))
      return 0
    fi
    echo "  Attempt $attempt/$RETRIES for $name failed, retrying..." >&2
    attempt=$((attempt + 1))
    sleep 2
  done

  echo "FAIL: $name"
  FAILED=$((FAILED + 1))
  return 1
}

echo "=== Integration Tests ==="
echo ""

test_proxy "HTTP proxy (port $HTTP_PORT)" "http://$PROXY_HOST:$HTTP_PORT" || true
test_proxy "SOCKS5 proxy (port $SOCKS_PORT)" "socks5://$PROXY_HOST:$SOCKS_PORT" || true

echo ""
echo "=== Results: $PASSED passed, $FAILED failed ==="

if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
