#!/bin/sh

# Set proxy port
sed "s/^Port .*$/Port $HTTPS_PROXY_PORT/" -i /etc/tinyproxy.conf

# Start proxy
/usr/bin/tinyproxy -c /etc/tinyproxy.conf && echo "HTTP/S proxy listening on $HTTPS_PROXY_PORT"

# Start socks5 proxy
/usr/local/bin/microsocks -i 0.0.0.0 -p $SOCKS5_PROXY_PORT & 
echo "socks5 proxy listening on $SOCKS5_PROXY_PORT"

# Start openconnect
if [[ -z "${OPENCONNECT_PASSWORD}" ]]; then
# Ask for password
  openconnect -v -u $OPENCONNECT_USER $OPENCONNECT_OPTIONS $OPENCONNECT_URL
elif [[ ! -z "${OPENCONNECT_PASSWORD}" ]] && [[ ! -z "${OPENCONNECT_MFA_CODE}" ]]; then
# Multi factor authentication (MFA)
  (echo $OPENCONNECT_PASSWORD; echo $OPENCONNECT_MFA_CODE) | openconnect -v -u $OPENCONNECT_USER $OPENCONNECT_OPTIONS --passwd-on-stdin $OPENCONNECT_URL
elif [[ ! -z "${OPENCONNECT_PASSWORD}" ]]; then
# Standard authentication
  echo $OPENCONNECT_PASSWORD | openconnect -v -u $OPENCONNECT_USER $OPENCONNECT_OPTIONS --passwd-on-stdin $OPENCONNECT_URL
fi
