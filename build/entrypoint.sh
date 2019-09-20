#!/bin/sh

# Set proxy port
sed "s/^Port .*$/Port $HTTPS_PROXY_PORT/" -i /etc/tinyproxy.conf

# Start proxy
tinyproxy -c /etc/tinyproxy.conf

# Start socks5 proxy
/usr/local/bin/microsocks -i 0.0.0.0 -p $SOCKS5_PROXY_PORT &

# Start openconnect with a reconnect timeout of 24 hours
echo "$OPENCONNECT_PASSWORD" | openconnect -v -u $OPENCONNECT_USER --no-dtls --passwd-on-stdin $OPENCONNECT_OPTIONS --reconnect-timeout 86400 $OPENCONNECT_URL
