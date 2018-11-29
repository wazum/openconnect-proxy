FROM alpine:3.8
MAINTAINER Wolfgang Klinger <wolfgang@wazum.com>

# openconnect is not yet available on main
RUN apk add --no-cache tinyproxy openconnect --repository http://dl-cdn.alpinelinux.org/alpine/edge/testing

COPY tinyproxy.conf /etc/tinyproxy.conf

# https://github.com/gliderlabs/docker-alpine/issues/367
RUN [ ! -e /etc/nsswitch.conf ] && echo 'hosts: files dns' > /etc/nsswitch.conf

# Use an up-to-date version of vpnc-script
COPY vpnc-script /etc/vpnc/vpnc-script
RUN chmod 755 /etc/vpnc/vpnc-script

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
