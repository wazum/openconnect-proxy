#!/bin/sh
set -e

CERT_DIR="/etc/ocserv/certs"
CA_CN="${CA_CN:-Test VPN CA}"
CA_ORG="${CA_ORG:-Test Org}"
CA_DAYS="${CA_DAYS:-365}"
SRV_CN="${SRV_CN:-vpn.test.local}"
SRV_ORG="${SRV_ORG:-Test Org}"
SRV_DAYS="${SRV_DAYS:-365}"

mkdir -p "$CERT_DIR"

# Generate CA certificate if it doesn't exist
if [ ! -f "$CERT_DIR/ca.crt" ]; then
    echo "Generating CA certificate..."
    openssl genrsa -out "$CERT_DIR/ca-key.pem" 2048
    openssl req -new -x509 -days "$CA_DAYS" -key "$CERT_DIR/ca-key.pem" \
        -out "$CERT_DIR/ca.crt" \
        -subj "/CN=$CA_CN/O=$CA_ORG"
fi

# Generate server certificate if it doesn't exist
if [ ! -f "$CERT_DIR/server.crt" ]; then
    echo "Generating server certificate..."
    openssl genrsa -out "$CERT_DIR/server-key.pem" 2048
    openssl req -new -key "$CERT_DIR/server-key.pem" \
        -out "$CERT_DIR/server.csr" \
        -subj "/CN=$SRV_CN/O=$SRV_ORG"
    openssl x509 -req -days "$SRV_DAYS" \
        -in "$CERT_DIR/server.csr" \
        -CA "$CERT_DIR/ca.crt" \
        -CAkey "$CERT_DIR/ca-key.pem" \
        -CAcreateserial \
        -out "$CERT_DIR/server.crt"
    rm "$CERT_DIR/server.csr"
fi

# Set up test user
echo "Setting up test user..."
echo "test" | /usr/local/bin/ocpasswd -c /etc/ocserv/ocpasswd test

echo "Starting ocserv..."
exec /usr/local/sbin/ocserv -f -d 1
