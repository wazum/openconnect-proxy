#!/bin/sh

PROXY_PORT="${PROXY_PORT:-8888}"
SOCKS_PORT="${SOCKS_PORT:-8889}"
RECONNECT_DELAY="${RECONNECT_DELAY:-60}"

cleanup() {
  echo "Caught signal, shutting down…" >&2
  kill "$TINYPROXY_PID" "$MICROSOCKS_PID" 2>/dev/null
  wait "$TINYPROXY_PID" "$MICROSOCKS_PID" 2>/dev/null
  exit 0
}
trap cleanup TERM INT

sed "s/^Port .*$/Port ${PROXY_PORT}/" -i /etc/tinyproxy.conf
/usr/bin/tinyproxy -c /etc/tinyproxy.conf -d 2>&1 &
TINYPROXY_PID=$!
/usr/local/bin/microsocks -i 0.0.0.0 -p "$SOCKS_PORT" 2>&1 &
MICROSOCKS_PID=$!

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

until run; do
  echo "OpenConnect exited. Restarting process in ${RECONNECT_DELAY} seconds…" >&2
  sleep "$RECONNECT_DELAY"
done
