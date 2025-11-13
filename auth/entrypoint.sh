#!/bin/sh
# Install custom CA certificates if any were mounted, then run the auth script.
if [ -n "$(ls -A /usr/local/share/ca-certificates/ 2>/dev/null)" ]; then
    update-ca-certificates 2>/dev/null
    # Also set the env var so Python/Playwright pick up the system store
    export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
    export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
fi
exec python /app/saml-auth.py "$@"
