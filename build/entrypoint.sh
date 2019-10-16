#!/bin/sh

# Copy possibly mounted public key for ssh
if test -f "/tmp/public_key"; then
  cat /tmp/public_key > /root/.ssh/authorized_keys
fi

# Set proxy port
sed "s/^Port .*$/Port 8888/" -i /etc/tinyproxy.conf

# Start proxy
/usr/bin/tinyproxy -c /etc/tinyproxy.conf

# Start socks5 proxy
/usr/local/bin/microsocks -i 0.0.0.0 -p 8889 & 

# Start ssh server
sed -i s/#PermitRootLogin.*/PermitRootLogin\ yes/ /etc/ssh/sshd_config
sed -i s/#AllowTCPForwarding.*/AllowTCPForwarding\ yes/ /etc/ssh/sshd_config
sed -i s/#PermitTunnel.*/PermitTunnel\ yes/ /etc/ssh/sshd_config
sed -i s/#AllowAgentForwarding.*/AllowAgentForwarding\ yes/ /etc/ssh/sshd_config
sed -i s/#GatewayPorts.*/GatewayPorts\ yes/ /etc/ssh/sshd_config
ssh-keygen -A
/usr/sbin/sshd -4 -e

# Start openconnect
if [[ -z "${OPENCONNECT_PASSWORD}" ]]; then
# Ask for password
  openconnect -u $OPENCONNECT_USER $OPENCONNECT_OPTIONS $OPENCONNECT_URL
elif [[ ! -z "${OPENCONNECT_PASSWORD}" ]] && [[ ! -z "${OPENCONNECT_MFA_CODE}" ]]; then
# Multi factor authentication (MFA)
  (echo $OPENCONNECT_PASSWORD; echo $OPENCONNECT_MFA_CODE) | openconnect -u $OPENCONNECT_USER $OPENCONNECT_OPTIONS --passwd-on-stdin $OPENCONNECT_URL
elif [[ ! -z "${OPENCONNECT_PASSWORD}" ]]; then
# Standard authentication
  echo $OPENCONNECT_PASSWORD | openconnect -u $OPENCONNECT_USER $OPENCONNECT_OPTIONS --passwd-on-stdin $OPENCONNECT_URL
fi

