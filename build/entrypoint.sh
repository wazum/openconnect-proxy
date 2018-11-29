#!/bin/sh

# Set proxy port
sed "s/^Port .*$/Port $PROXY_PORT/" -i /etc/tinyproxy.conf

# Start proxy
tinyproxy -c /etc/tinyproxy.conf

# Start openconnect
echo "$OPENCONNECT_PASSWORD" | openconnect -v -u $OPENCONNECT_USER --no-dtls --passwd-on-stdin $OPENCONNECT_OPTIONS $OPENCONNECT_URL
