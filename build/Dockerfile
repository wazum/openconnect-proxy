FROM alpine:edge
MAINTAINER Colby Taperts <colbytaperts@gmail.com>

# openconnect is not yet available on main
RUN apk add --no-cache libcrypto1.1 libssl1.1 libstdc++ --repository http://dl-cdn.alpinelinux.org/alpine/edge/main
RUN apk add --no-cache oath-toolkit-libpskc --repository http://dl-cdn.alpinelinux.org/alpine/edge/community
RUN apk add --no-cache nettle --repository http://dl-cdn.alpinelinux.org/alpine/edge/main
RUN apk add --no-cache openconnect tinyproxy --repository http://dl-cdn.alpinelinux.org/alpine/edge/testing

RUN apk --no-cache add ca-certificates wget && \
    wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub && \
    wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.30-r0/glibc-2.30-r0.apk && \
    apk add glibc-2.30-r0.apk

RUN apk add --no-cache gcc make musl-dev && \
    cd /tmp && \
    wget https://github.com/rofl0r/microsocks/archive/v1.0.1.tar.gz && \
    tar -xzvf v1.0.1.tar.gz && \
    cd microsocks-1.0.1 && \
    make && \
    make install && \
    apk del gcc make musl-dev

# Use an up-to-date version of vpnc-script
# https://www.infradead.org/openconnect/vpnc-script.html
COPY vpnc-script /etc/vpnc/vpnc-script
RUN chmod 755 /etc/vpnc/vpnc-script

COPY tinyproxy.conf /etc/tinyproxy.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
