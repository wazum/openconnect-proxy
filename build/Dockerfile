FROM alpine:3.19
LABEL maintainer="Wolfgang Klinger <wolfgang@wazum.com>"

RUN apk add --no-cache --virtual .build-deps \
        gcc \
        make \
        musl-dev \
        git \
        openssl-dev \
        python3 \
        py3-pip \
        zlib-dev \
    && apk add --no-cache \
        libcrypto3 \
        libssl3 \
        libstdc++ \
        oath-toolkit-libpskc \
        nettle \
        openconnect \
        tinyproxy \
        iptables\
    && git clone --depth=1 --branch v1.0.5 https://github.com/rofl0r/microsocks.git /tmp/microsocks \
    && make -C /tmp/microsocks > /tmp/microsocks_build.log 2>&1 \
    && tail -n 10 /tmp/microsocks_build.log \
    && make -C /tmp/microsocks install \
    && rm -rf /tmp/microsocks \
    && python3 -m venv /tmp/venv \
    && source /tmp/venv/bin/activate \
    && pip install --no-cache-dir pyinstaller \
    && pip install --no-cache-dir "vpn-slice[dnspython,setproctitle]" \
    && pyinstaller --onefile /tmp/venv/bin/vpn-slice \
    && mv dist/vpn-slice /usr/local/bin/ \
    && deactivate \
    && rm -rf /tmp/venv \
    && apk del .build-deps \
    && rm -rf /var/cache/apk/* /root/.cache /tmp/* build/ dist/ *.spec

RUN echo -e '#!/bin/sh\n\
[ "$(grep -c "nameserver 127.0.0.11" /etc/resolv.conf)" -eq 0 ] && \
echo "nameserver 127.0.0.11" >> /etc/resolv.conf\n\
exec "$@"' > /usr/local/bin/fix-dns && chmod +x /usr/local/bin/fix-dns

COPY --chmod=755 vpnc-script /etc/vpnc/vpnc-script
COPY tinyproxy.conf /etc/tinyproxy.conf
COPY --chmod=755 entrypoint.sh /entrypoint.sh

EXPOSE 8888 8889
ENTRYPOINT ["/usr/local/bin/fix-dns", "/entrypoint.sh"]
