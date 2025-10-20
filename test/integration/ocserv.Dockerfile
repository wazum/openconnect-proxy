# Builder stage - compile ocserv from source
FROM alpine:3.21 AS builder

ARG OCSERV_VER="1.2.2"

RUN apk add --no-cache \
    curl \
    g++ \
    gnutls-dev \
    libev-dev \
    libnl3-dev \
    libseccomp-dev \
    linux-headers \
    linux-pam-dev \
    lz4-dev \
    make \
    readline-dev \
    xz

WORKDIR /ocserv

RUN curl -fL "https://www.infradead.org/ocserv/download/ocserv-${OCSERV_VER}.tar.xz" | tar -xJ --strip-components=1 && \
    ./configure --prefix=/usr/local && \
    make && \
    make install

# Runtime stage
FROM alpine:3.21

RUN apk add --no-cache \
    ca-certificates \
    gnutls \
    libev \
    libnl3 \
    libseccomp \
    lz4-libs \
    linux-pam \
    iptables \
    netcat-openbsd \
    openssl

COPY --from=builder /usr/local/sbin/ocserv /usr/local/sbin/
COPY --from=builder /usr/local/bin/ocpasswd /usr/local/bin/
COPY --from=builder /usr/local/sbin/ocserv-worker /usr/local/sbin/

COPY ocserv.conf /etc/ocserv/ocserv.conf
COPY init-ocserv.sh /usr/local/bin/init-ocserv.sh

RUN mkdir -p /etc/ocserv/certs && \
    chmod +x /usr/local/bin/init-ocserv.sh /usr/local/sbin/ocserv-worker

EXPOSE 443

HEALTHCHECK --interval=5s --timeout=3s --retries=10 --start-period=15s \
    CMD nc -z localhost 443 || exit 1

ENTRYPOINT ["/usr/local/bin/init-ocserv.sh"]
