# Builder stage - compile ocserv from source
FROM alpine:3.24 AS builder

ARG OCSERV_VER="1.6.0"
ARG OCSERV_SHA256="e7893e8781801df1ec751996005f77b7db884305b42e2c1ab41cf56c17516cca"

RUN apk add --no-cache \
    build-base \
    curl \
    gperf \
    gnutls-dev \
    libev-dev \
    linux-headers \
    meson \
    nettle-dev \
    ninja \
    pkgconf \
    protobuf-c-compiler \
    readline-dev \
    xz

WORKDIR /ocserv

RUN curl --retry 5 --retry-all-errors --connect-timeout 15 -fsSL \
        "https://gitlab.com/openconnect/ocserv/-/archive/${OCSERV_VER}/ocserv-${OCSERV_VER}.tar.gz" \
        -o /tmp/ocserv.tar.gz && \
    echo "${OCSERV_SHA256}  /tmp/ocserv.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/ocserv.tar.gz --strip-components=1 && \
    rm /tmp/ocserv.tar.gz && \
    meson setup build \
        --prefix=/usr/local \
        -Dfirewall-script=iptables \
        -Dgeoip=disabled \
        -Dgssapi=disabled \
        -Dlibnl=disabled \
        -Dliboath=disabled \
        -Dlibwrap=disabled \
        -Dlz4=disabled \
        -Dmaxmind=disabled \
        -Dpam=disabled \
        -Dradius=disabled \
        -Dseccomp=disabled \
        -Dsystemd=disabled \
        -Dutmp=disabled && \
    meson compile -C build && \
    meson install -C build

# Runtime stage
FROM alpine:3.24

RUN apk add --no-cache \
    ca-certificates \
    gnutls \
    libev \
    iptables \
    netcat-openbsd \
    nettle \
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
