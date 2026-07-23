#!/usr/bin/env bash
set -eu
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.test.yml"
PROJECT="openconnectproxyit"           # deterministic Compose project name
NET="${PROJECT}_vpntest"               # default network = <project>_<network>
COMPOSE=(docker compose -p "$PROJECT" -f "$COMPOSE_FILE")
PASSED=0
FAILED=0

pass() { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail() { echo "FAIL: $1"; FAILED=$((FAILED + 1)); }

cleanup() {
  echo "=== Teardown ==="
  "${COMPOSE[@]}" logs --no-color || true
  "${COMPOSE[@]}" down -v --remove-orphans || true
}
trap cleanup EXIT

echo "=== Build images ==="
"${COMPOSE[@]}" build

echo "=== Start ocserv, extract server cert pin ==="
"${COMPOSE[@]}" up -d ocserv

wait_healthy() {
  local container="$1" timeout="${2:-90}" t=0 s
  while [ "$t" -lt "$timeout" ]; do
    s="$(docker inspect --format '{{.State.Health.Status}}' "$container" 2>/dev/null || echo unknown)"
    [ "$s" = "healthy" ] && return 0
    sleep 1; t=$((t + 1))
  done
  return 1
}

if ! wait_healthy test-ocserv 60; then
  echo "ERROR: ocserv did not become healthy"; exit 1
fi

# Compute SPKI pin-sha256 — what OpenConnect uses for --servercert
OPENCONNECT_SERVERCERT="pin-sha256:$(
  docker exec test-ocserv sh -c \
    'openssl x509 -in /etc/ocserv/certs/server.crt -pubkey -noout \
     | openssl pkey -pubin -outform DER \
     | openssl dgst -sha256 -binary \
     | base64'
)"
export OPENCONNECT_SERVERCERT
echo "=== Server cert pin: $OPENCONNECT_SERVERCERT ==="

echo "=== Start proxy services ==="
"${COMPOSE[@]}" up -d

curl_via_proxy() {
  local proxy_url="$1" target="${2:-https://192.168.100.1}"
  docker run --rm --network "$NET" curlimages/curl:latest \
    -sfk --max-time 10 -x "$proxy_url" "$target" >/dev/null
}

# Classify BusyBox nc output without treating every exit 1 as an RST.
# BusyBox emits no text for a refused connection, but uses the same status for
# DNS and other errors, so non-empty unknown output must remain an error.
classify_tcp_probe() {
  local out="$1" rc="$2"
  case "$out" in
    *open*) echo open; return ;;
  esac
  case "$out" in
    *timed*out*|*timeout*) echo timeout; return ;;
  esac
  case "$out" in
    *[Cc]onnection*refused*) echo refused; return ;;
  esac
  if [ "$rc" = "1" ] && [ -z "$out" ]; then
    echo refused
  else
    echo "error: ${out:-nc exited with status $rc}"
  fi
}

# Probe a TCP port via BusyBox nc.
# stdout: one of open | refused | timeout | error:...
tcp_probe() {
  local host="$1" port="$2" out rc
  out=$(docker run --rm --network "$NET" alpine:3.24 \
          sh -c "nc -z -v -w 3 $host $port 2>&1"; echo "rc:$?") 2>/dev/null
  rc="${out##*rc:}"
  out="${out%rc:*}"
  classify_tcp_probe "$out" "$rc"
}

assert_probe() {
  local label="$1" host="$2" port="$3" want="$4" got
  got=$(tcp_probe "$host" "$port")
  if [ "$got" = "$want" ]; then
    pass "$label (got: $got)"
  else
    fail "$label (want: $want, got: $got)"
  fi
}

echo "=== Pre-connect: tunnel never up, ports must refuse (RST) ==="
sleep 3  # allow tunnel-gate to install the rule (TUNNEL_GATE_INTERVAL=1)
assert_probe "preconnect HTTP port refused"  test-openconnect-proxy-preconnect 8888 refused
assert_probe "preconnect SOCKS port refused" test-openconnect-proxy-preconnect 8889 refused

echo "=== Opt-out: TUNNEL_GATE=0 must allow TCP connect even before tunnel up ==="
sleep 1
assert_probe "opt-out HTTP port open"  test-openconnect-proxy-disabled 8888 open
assert_probe "opt-out SOCKS port open" test-openconnect-proxy-disabled 8889 open

echo "=== Happy path: wait for main proxy to be healthy ==="
if wait_healthy test-openconnect-proxy 120; then
  pass "main proxy reached healthy"
else
  fail "main proxy did not reach healthy in 120s"
fi

if curl_via_proxy http://test-openconnect-proxy:8888; then
  pass "HTTP proxy curl"
else
  fail "HTTP proxy curl"
fi
if curl_via_proxy socks5://test-openconnect-proxy:8889; then
  pass "SOCKS proxy curl"
else
  fail "SOCKS proxy curl"
fi

echo "=== Reconnect refusal: kill openconnect, expect refusal within a few seconds ==="
# Use SIGKILL so openconnect exits non-zero, keeping the entrypoint retry loop alive.
# SIGTERM causes a clean exit (rc=0) which exits the `until run` loop and the container.
"${COMPOSE[@]}" exec -T openconnect-proxy pkill -9 openconnect || true
# Gate detects tun0 down within TUNNEL_GATE_INTERVAL (default 2s) and installs REJECT.
# Compose sets RECONNECT_DELAY=30s for this service so the 4s probe window lands
# while the gate is closed and well before the next reconnect attempt.
sleep 4
assert_probe "post-disconnect HTTP port refused" test-openconnect-proxy 8888 refused

echo "=== Daemon-death healthcheck: kill tinyproxy, expect unhealthy ==="
wait_healthy test-openconnect-proxy 120 || true
"${COMPOSE[@]}" exec -T openconnect-proxy pkill tinyproxy || true
t=0
s=unknown
while [ "$t" -lt 20 ]; do
  s="$(docker inspect --format '{{.State.Health.Status}}' test-openconnect-proxy 2>/dev/null || echo unknown)"
  [ "$s" = "unhealthy" ] && break
  sleep 1; t=$((t + 1))
done
if [ "$s" = "unhealthy" ]; then
  pass "container reports unhealthy after tinyproxy dies"
else
  fail "container did not transition to unhealthy (status=$s)"
fi

echo "=== Results: $PASSED passed, $FAILED failed ==="
[ "$FAILED" -eq 0 ]
