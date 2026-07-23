#!/bin/sh

PROXY_PORT="${PROXY_PORT:-8888}"
SOCKS_PORT="${SOCKS_PORT:-8889}"
RECONNECT_DELAY="${RECONNECT_DELAY:-60}"
MAX_RECONNECT_ATTEMPTS="${MAX_RECONNECT_ATTEMPTS:-0}"
TUNNEL_GATE="${TUNNEL_GATE:-1}"

validate_reconnect_settings() {
  case "$MAX_RECONNECT_ATTEMPTS" in
    ''|*[!0-9]*)
      echo "FATAL: MAX_RECONNECT_ATTEMPTS must be a non-negative integer" >&2
      return 1
      ;;
  esac
}

validate_reconnect_settings || exit 1

# Source the gate library. Path is overridable via TUNNEL_GATE_LIB so BATS
# can point at the working tree.
# shellcheck disable=SC1090,SC1091
. "${TUNNEL_GATE_LIB:-/usr/local/bin/tunnel-gate.sh}"

GATE_PID=""
TINYPROXY_PID=""
MICROSOCKS_PID=""

cleanup() {
  status=$?
  trap - EXIT TERM INT
  echo "Shutting down…" >&2
  [ -n "$GATE_PID" ] && kill "$GATE_PID" 2>/dev/null
  kill "$TINYPROXY_PID" "$MICROSOCKS_PID" 2>/dev/null
  wait "$GATE_PID" "$TINYPROXY_PID" "$MICROSOCKS_PID" 2>/dev/null

  if [ "$TUNNEL_GATE" = "1" ]; then
    # Remove the jump rule (matched by exact comment) and the owned chain.
    # shellcheck disable=SC2046
    iptables -D INPUT $(_gate_jump_args) 2>/dev/null
    iptables -F "$GATE_CHAIN" 2>/dev/null
    iptables -X "$GATE_CHAIN" 2>/dev/null
    if [ "${GATE_IPV6_ACTIVE:-0}" = "1" ]; then
      # shellcheck disable=SC2046
      ip6tables -D INPUT $(_gate_jump_args) 2>/dev/null
      ip6tables -F "$GATE_CHAIN" 2>/dev/null
      ip6tables -X "$GATE_CHAIN" 2>/dev/null
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 0' TERM INT

if [ "$TUNNEL_GATE" = "1" ]; then
  if ! gate_init_closed; then
    echo "FATAL: cannot install tunnel-gate REJECT rule; set TUNNEL_GATE=0 to disable, or grant NET_ADMIN" >&2
    exit 1
  fi
fi

sed "s/^Port .*$/Port ${PROXY_PORT}/" -i /etc/tinyproxy.conf
/usr/bin/tinyproxy -c /etc/tinyproxy.conf -d 2>&1 &
TINYPROXY_PID=$!
/usr/local/bin/microsocks -i 0.0.0.0 -p "$SOCKS_PORT" 2>&1 &
MICROSOCKS_PID=$!

if [ "$TUNNEL_GATE" = "1" ]; then
  ( until /usr/local/bin/tunnel-gate.sh; do
      echo "tunnel-gate exited, restarting in 5s" >&2
      sleep 5
    done ) &
  GATE_PID=$!
fi

run () {
  # Decide once (on the first attempt) whether to derive the MFA code from the
  # TOTP secret. An explicit OPENCONNECT_MFA_CODE supplied at startup always
  # takes precedence; otherwise we regenerate from the secret on every retry.
  if [ -z "$OPENCONNECT_MFA_FROM_TOTP" ]; then
    if [ -n "$OPENCONNECT_TOTP_SECRET" ] && [ -z "$OPENCONNECT_MFA_CODE" ]; then
      OPENCONNECT_MFA_FROM_TOTP=1
    else
      OPENCONNECT_MFA_FROM_TOTP=0
    fi
  fi

  if [ "$OPENCONNECT_MFA_FROM_TOTP" = "1" ]; then
    OPENCONNECT_MFA_CODE=$(oathtool --totp --base32 "$OPENCONNECT_TOTP_SECRET")
    export OPENCONNECT_MFA_CODE
    echo "TOTP code generated from secret."
  fi

  if [ -n "$OPENCONNECT_COOKIE_FILE" ] && [ -f "$OPENCONNECT_COOKIE_FILE" ]; then
    OPENCONNECT_COOKIE=$(jq -r '.cookie' "$OPENCONNECT_COOKIE_FILE")
    export OPENCONNECT_COOKIE
  fi

  if [ -n "$VPN_SPLIT" ]; then
    VPN_SLICE_CMD="vpn-slice ${VPN_ROUTES}"
    ALL_OPTIONS="${OPENCONNECT_OPTIONS} --script=\"${VPN_SLICE_CMD}\""
  else
    ALL_OPTIONS="$OPENCONNECT_OPTIONS"
  fi

  if [ -n "$OPENCONNECT_COOKIE" ]; then
    echo "Cookie/token detected. Starting OpenConnect with pre-authenticated session."
    echo "$OPENCONNECT_COOKIE" | \
    eval "openconnect ${ALL_OPTIONS} --cookie-on-stdin \"${OPENCONNECT_URL}\""
  elif [ -z "$OPENCONNECT_PASSWORD" ]; then
    echo "Password not set. Prompting for password..."
    eval "openconnect ${ALL_OPTIONS} -u \"${OPENCONNECT_USER}\" \"${OPENCONNECT_URL}\""
  elif [ -n "$OPENCONNECT_MFA_CODE" ]; then
    echo "Password and MFA detected. Starting OpenConnect with both."
    (echo "$OPENCONNECT_PASSWORD"; echo "$OPENCONNECT_MFA_CODE") | \
    eval "openconnect ${ALL_OPTIONS} -u \"${OPENCONNECT_USER}\" --passwd-on-stdin \"${OPENCONNECT_URL}\""
  elif [ -n "$OPENCONNECT_PASSWORD" ]; then
    echo "Password detected. Starting OpenConnect."
    echo "$OPENCONNECT_PASSWORD" | \
    eval "openconnect ${ALL_OPTIONS} -u \"${OPENCONNECT_USER}\" --passwd-on-stdin \"${OPENCONNECT_URL}\""
  else
    echo "Error: Password and MFA code are both missing!" >&2
    exit 1
  fi
}

run_with_retries() {
  reconnect_attempt=0

  while ! "$@"; do
    if [ "$MAX_RECONNECT_ATTEMPTS" -gt 0 ] \
      && [ "$reconnect_attempt" -ge "$MAX_RECONNECT_ATTEMPTS" ]; then
      echo "OpenConnect exited. Maximum reconnect attempts (${MAX_RECONNECT_ATTEMPTS}) reached; exiting." >&2
      return 1
    fi

    reconnect_attempt=$((reconnect_attempt + 1))
    if [ "$MAX_RECONNECT_ATTEMPTS" -gt 0 ]; then
      echo "OpenConnect exited. Reconnect attempt ${reconnect_attempt}/${MAX_RECONNECT_ATTEMPTS} in ${RECONNECT_DELAY} seconds…" >&2
    else
      echo "OpenConnect exited. Restarting process in ${RECONNECT_DELAY} seconds…" >&2
    fi
    sleep "$RECONNECT_DELAY"
  done
}

run_with_retries run
