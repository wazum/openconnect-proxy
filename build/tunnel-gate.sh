#!/bin/sh
# shellcheck disable=SC3043  # BusyBox ash supports `local`; image runs Alpine.
# tunnel-gate.sh — guard the proxy ports while the VPN tunnel is down.
# Sourceable library + script entry point.
#
# Env (also honored by callers via `source`):
#   TUNNEL_GATE            1 | 0                       default: 1
#   TUNNEL_GATE_INTERVAL   seconds between reconciles  default: 2
#   TUNNEL_GATE_INTERFACE  interface to watch          default: tun0
#   TUNNEL_GATE_IPV6       auto | 1 | 0                default: auto
#   PROXY_PORT             HTTP proxy port             default: 8888
#   SOCKS_PORT             SOCKS5 proxy port           default: 8889

TUNNEL_GATE="${TUNNEL_GATE:-1}"
TUNNEL_GATE_INTERVAL="${TUNNEL_GATE_INTERVAL:-2}"
TUNNEL_GATE_INTERFACE="${TUNNEL_GATE_INTERFACE:-tun0}"
TUNNEL_GATE_IPV6="${TUNNEL_GATE_IPV6:-auto}"
PROXY_PORT="${PROXY_PORT:-8888}"
SOCKS_PORT="${SOCKS_PORT:-8889}"

# Chain owned by this feature.
GATE_CHAIN="OPENCONNECT_PROXY_GATE"

# Comment tag used on every owned rule so -C/-D match exactly.
GATE_COMMENT="openconnect-proxy-gate"

# Build the jump-rule arg list. Stdout is whitespace-separated tokens.
_gate_jump_args() {
  printf '%s' "-m comment --comment $GATE_COMMENT -j $GATE_CHAIN"
}

# Build the REJECT-rule arg list (without the chain), parameterized on the
# iptables binary's port-set arg (multiport works for both iptables/ip6tables).
_gate_reject_args() {
  printf '%s' "-p tcp -m multiport --dports ${PROXY_PORT},${SOCKS_PORT} -m comment --comment $GATE_COMMENT -j REJECT --reject-with tcp-reset"
}

# Path to the kernel's IPv6 sysctl tree; overridable for tests.
GATE_IPV6_PROC_PATH="${GATE_IPV6_PROC_PATH:-/proc/sys/net/ipv6}"

# Resolve TUNNEL_GATE_IPV6 mode. Caches result in GATE_IPV6_ACTIVE (0|1)
# at first call; subsequent calls short-circuit. Returns 0 unless mode=1
# and IPv6 is unavailable (then logs+returns 1).
# Two-step detection: kernel IPv6 sysctl tree must exist AND ip6tables must
# be able to list its filter table. The proc-path check catches hosts where
# IPv6 is disabled at boot (ipv6.disable=1); the ip6tables check catches
# missing kernel modules or container restrictions.
gate_resolve_ipv6() {
  [ -n "${GATE_IPV6_ACTIVE:-}" ] && return 0
  case "$TUNNEL_GATE_IPV6" in
    0)
      GATE_IPV6_ACTIVE=0
      ;;
    1)
      if [ -d "$GATE_IPV6_PROC_PATH" ] && ip6tables -L -n >/dev/null 2>&1; then
        GATE_IPV6_ACTIVE=1
      else
        echo "tunnel-gate: TUNNEL_GATE_IPV6=1 but IPv6 unavailable" >&2
        return 1
      fi
      ;;
    *) # auto
      if [ -d "$GATE_IPV6_PROC_PATH" ] && ip6tables -L -n >/dev/null 2>&1; then
        GATE_IPV6_ACTIVE=1
      else
        if [ -z "${GATE_IPV6_LOGGED:-}" ]; then
          echo "tunnel-gate: IPv6 support not available, skipping ip6tables programming" >&2
          GATE_IPV6_LOGGED=1
          export GATE_IPV6_LOGGED
        fi
        GATE_IPV6_ACTIVE=0
      fi
      ;;
  esac
  export GATE_IPV6_ACTIVE
  return 0
}

# Create the chain if absent, install the tagged INPUT jump rule if absent.
# Operates on the iptables binary passed in $1 (default: iptables).
gate_ensure_chain() {
  local ipt="${1:-iptables}"

  # -N is non-idempotent in older iptables; tolerate EEXIST. A genuine error
  # (e.g. EPERM) will surface on the subsequent -C/-I calls.
  "$ipt" -N "$GATE_CHAIN" 2>/dev/null || true

  # shellcheck disable=SC2046  # intentional word-splitting on _gate_jump_args
  if ! "$ipt" -C INPUT $(_gate_jump_args) 2>/dev/null; then
    # shellcheck disable=SC2046  # intentional word-splitting on _gate_jump_args
    "$ipt" -I INPUT 1 $(_gate_jump_args)
  fi
}

# Ensure the owned REJECT rule exists at chain position 1. Insert only if
# absent — never flush, so we do not introduce an empty-chain window.
gate_set_closed() {
  local ipt="${1:-iptables}"
  gate_ensure_chain "$ipt"
  # shellcheck disable=SC2046  # intentional word-splitting on _gate_reject_args
  if ! "$ipt" -C "$GATE_CHAIN" $(_gate_reject_args) 2>/dev/null; then
    # shellcheck disable=SC2046  # intentional word-splitting on _gate_reject_args
    "$ipt" -I "$GATE_CHAIN" 1 $(_gate_reject_args)
  fi
}

# Remove the owned REJECT rule. Loop on -D until -C reports absent, so any
# accidental duplicates are cleaned up too.
gate_set_open() {
  local ipt="${1:-iptables}"
  gate_ensure_chain "$ipt"
  # shellcheck disable=SC2046  # intentional word-splitting on _gate_reject_args
  while "$ipt" -C "$GATE_CHAIN" $(_gate_reject_args) 2>/dev/null; do
    # shellcheck disable=SC2046  # intentional word-splitting on _gate_reject_args
    "$ipt" -D "$GATE_CHAIN" $(_gate_reject_args) || break
  done
}

# One reconcile pass. Reads GATE_LAST_STATE for log-suppression; updates it
# in the caller's environment via export.
gate_reconcile_tick() {
  local desired
  gate_resolve_ipv6 || true  # auto-mode skips on failure; mandatory-mode is enforced at init.

  if gate_interface_up "$TUNNEL_GATE_INTERFACE"; then
    desired=open
    gate_set_open iptables
    [ "$GATE_IPV6_ACTIVE" = "1" ] && gate_set_open ip6tables
  else
    desired=closed
    gate_set_closed iptables
    [ "$GATE_IPV6_ACTIVE" = "1" ] && gate_set_closed ip6tables
  fi

  if [ "${GATE_LAST_STATE:-}" != "$desired" ]; then
    echo "tunnel-gate: $TUNNEL_GATE_INTERFACE state -> $desired" >&2
    GATE_LAST_STATE="$desired"
    export GATE_LAST_STATE
  fi
}

# Returns 0 if $1 exists and carries the admin UP flag, non-zero otherwise.
# Parses the flag list because `ip link show ... up` returns 0 even for
# down interfaces on iproute2. Matches UP as a standalone token between
# `<` or `,` and `,` or `>` so it does not false-match LOWER_UP, UPPER_UP,
# or UPLINK.
gate_interface_up() {
  ip -o link show dev "$1" 2>/dev/null | grep -Eq '[<,]UP[,>]'
}

# Install the gate in the closed position. Returns non-zero if any required
# operation fails. Called from entrypoint.sh before the proxies launch.
gate_init_closed() {
  gate_resolve_ipv6 || return 1
  gate_set_closed iptables || return 1
  if [ "$GATE_IPV6_ACTIVE" = "1" ]; then
    gate_set_closed ip6tables || return 1
  fi
  return 0
}

# Run-loop entry. Used when the file is executed as a script.
_gate_main_loop() {
  trap 'exit 0' TERM INT
  while :; do
    gate_reconcile_tick
    sleep "$TUNNEL_GATE_INTERVAL"
  done
}

# Sourced or executed? Only run the main loop in script mode.
case "${0##*/}" in
  tunnel-gate.sh)
    if [ "$TUNNEL_GATE" = "0" ]; then
      echo "tunnel-gate: disabled (TUNNEL_GATE=0)" >&2
      exit 0
    fi
    _gate_main_loop
    ;;
esac
