#!/bin/sh

# set environment variables if they are not passed
if [[ -z "${HTTPS_PROXY_PORT}" ]]; then
  export HTTPS_PROXY_PORT=8888
fi

if [[ -z "${SOCKS5_PROXY_PORT}" ]]; then
  export SOCKS5_PROXY_PORT=8889
fi

# Set proxy port
sed "s/^Port .*$/Port $HTTPS_PROXY_PORT/" -i /etc/tinyproxy.conf

# Start proxy
tinyproxy -c /etc/tinyproxy.conf

# Start socks5 proxy
/usr/local/bin/microsocks -i 0.0.0.0 -p $SOCKS5_PROXY_PORT &

# Start openconnect
if [[ -z "${OPENCONNECT_PASSWORD}" ]]; then
  # foreground
  openconnect -v -u $OPENCONNECT_USER $OPENCONNECT_OPTIONS $OPENCONNECT_URL
elif [[ ! -z "${OPENCONNECT_PASSWORD}" ]] && [[ ! -z "${OPENCONNECT_PASSWORD_TWO}" ]]; then
  # multi auth
  (echo $OPENCONNECT_PASSWORD; echo $OPENCONNECT_PASSWORD_TWO) | openconnect -v -u $OPENCONNECT_USER $OPENCONNECT_OPTIONS --passwd-on-stdin $OPENCONNECT_URL
elif [[ ! -z "${OPENCONNECT_PASSWORD}" ]]; then
  # auth
  echo $OPENCONNECT_PASSWORD | openconnect -v -u $OPENCONNECT_USER $OPENCONNECT_OPTIONS --passwd-on-stdin $OPENCONNECT_URL
fi
