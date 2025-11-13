FROM python:3.12-slim-bookworm

RUN pip install --no-cache-dir playwright pyotp pyyaml \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*

# To trust a corporate CA, mount it at runtime:
#   -v ./my-ca.crt:/usr/local/share/ca-certificates/my-ca.crt:ro
# The entrypoint will run update-ca-certificates automatically.
COPY entrypoint.sh /app/entrypoint.sh
COPY saml-auth.py /app/saml-auth.py
COPY providers/ /app/providers/

WORKDIR /app
ENTRYPOINT ["/app/entrypoint.sh"]
