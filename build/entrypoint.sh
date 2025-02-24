#!/bin/sh

sed "s/^Port .*$/Port 8888/" -i /etc/tinyproxy.conf
/usr/bin/tinyproxy -c /etc/tinyproxy.conf -d 2>&1 &
/usr/local/bin/microsocks -i 0.0.0.0 -p 8889 2>&1 &

run () {
  if [ -n "$VPN_SPLIT" ]; then
    VPN_SLICE_CMD="vpn-slice ${VPN_ROUTES}"
    ALL_OPTIONS="${OPENCONNECT_OPTIONS} --script=\"${VPN_SLICE_CMD}\""
  else
    ALL_OPTIONS="$OPENCONNECT_OPTIONS"
  fi

  # Ask for password
  if [ -z "$OPENCONNECT_PASSWORD" ]; then
    echo "Password not set. Prompting for password..."
    eval "openconnect ${ALL_OPTIONS} -u \"${OPENCONNECT_USER}\" \"${OPENCONNECT_URL}\""
  # Multi factor authentication (MFA)
  elif [ -n "$OPENCONNECT_PASSWORD" ] && [ -n "$OPENCONNECT_MFA_CODE" ]; then
    echo "Password and MFA detected. Starting OpenConnect with both."
    (echo "$OPENCONNECT_PASSWORD"; echo "$OPENCONNECT_MFA_CODE") | \
    eval "openconnect ${ALL_OPTIONS} -u \"${OPENCONNECT_USER}\" --passwd-on-stdin \"${OPENCONNECT_URL}\""
  # Standard authentication
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
  echo "OpenConnect exited. Restarting process in 60 seconds…" >&2
  sleep 60
done
