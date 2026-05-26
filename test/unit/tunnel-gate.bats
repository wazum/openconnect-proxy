#!/usr/bin/env bats

setup() {
  load '../test_helper/bats-support/load'
  load '../test_helper/bats-assert/load'

  PROJECT_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
  GATE_SCRIPT="$PROJECT_ROOT/build/tunnel-gate.sh"

  MOCK_DIR="$(mktemp -d)"
  export MOCK_DIR
  export IPTABLES_LOG="$MOCK_DIR/iptables.log"
  export IP6TABLES_LOG="$MOCK_DIR/ip6tables.log"
  export IP_LOG="$MOCK_DIR/ip.log"

  cat > "$MOCK_DIR/iptables" << 'MOCK'
#!/bin/sh
echo "$@" >> "$IPTABLES_LOG"
exit 0
MOCK
  cat > "$MOCK_DIR/ip6tables" << 'MOCK'
#!/bin/sh
echo "$@" >> "$IP6TABLES_LOG"
case "$1" in -C) exit 1 ;; *) exit 0 ;; esac
MOCK
  cat > "$MOCK_DIR/ip" << 'MOCK'
#!/bin/sh
echo "$@" >> "$IP_LOG"
exit 0
MOCK
  chmod +x "$MOCK_DIR/iptables" "$MOCK_DIR/ip6tables" "$MOCK_DIR/ip"
  export PATH="$MOCK_DIR:$PATH"

  # Default: disable IPv6 detection. Tests that exercise IPv6 modes override
  # TUNNEL_GATE_IPV6 via `export` (NOT the prefix-source form, which does not
  # persist past the `source` call in bash) before sourcing the gate script.
  export TUNNEL_GATE_IPV6=0
  # Clear any IPv6-detection state inherited from prior tests in the same
  # BATS process so each test starts clean.
  unset GATE_IPV6_ACTIVE GATE_IPV6_LOGGED
}

teardown() {
  rm -rf "$MOCK_DIR"
}

@test "TUNNEL_GATE=0 makes the script exit 0 immediately with no iptables/ip6tables calls" {
  TUNNEL_GATE=0 run "$GATE_SCRIPT"
  assert_success
  [ ! -s "$IPTABLES_LOG" ] || { echo "iptables called: $(cat "$IPTABLES_LOG")"; false; }
  [ ! -s "$IP6TABLES_LOG" ] || { echo "ip6tables called: $(cat "$IP6TABLES_LOG")"; false; }
}

# --- gate_interface_up ---

_install_ip_shim() {
  # $1 = exit code, $2 = stdout to emit
  cat > "$MOCK_DIR/ip" << MOCK
#!/bin/sh
echo "\$@" >> "\$IP_LOG"
printf '%s' "$2"
exit $1
MOCK
  chmod +x "$MOCK_DIR/ip"
}

@test "gate_interface_up: returns false when interface is absent" {
  _install_ip_shim 1 ""
  source "$GATE_SCRIPT"
  run gate_interface_up tun0
  assert_failure
}

@test "gate_interface_up: returns false when interface exists but lacks UP flag" {
  _install_ip_shim 0 "1: tun0: <NO-CARRIER,BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN"
  source "$GATE_SCRIPT"
  run gate_interface_up tun0
  assert_failure
}

@test "gate_interface_up: returns true when interface carries the UP flag" {
  _install_ip_shim 0 "1: tun0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP"
  source "$GATE_SCRIPT"
  run gate_interface_up tun0
  assert_success
}

@test "gate_interface_up: does not match UP as a prefix of another flag (e.g. UPLINK)" {
  _install_ip_shim 0 "1: tun0: <UPLINK,BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN"
  source "$GATE_SCRIPT"
  run gate_interface_up tun0
  assert_failure
}

@test "gate_interface_up: does not match LOWER_UP without admin UP" {
  _install_ip_shim 0 "1: tun0: <BROADCAST,MULTICAST,LOWER_UP> mtu 1500 qdisc fq_codel state DOWN"
  source "$GATE_SCRIPT"
  run gate_interface_up tun0
  assert_failure
}

@test "gate_interface_up: does not match UPPER_UP as a suffix of another flag" {
  _install_ip_shim 0 "1: tun0: <BROADCAST,UPPER_UP> mtu 1500 qdisc noop state DOWN"
  source "$GATE_SCRIPT"
  run gate_interface_up tun0
  assert_failure
}

@test "gate_interface_up: matches a real openconnect tun0 flag list" {
  _install_ip_shim 0 "5: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1412 qdisc fq_codel state UNKNOWN"
  source "$GATE_SCRIPT"
  run gate_interface_up tun0
  assert_success
}

# --- gate_ensure_chain ---

_install_iptables_shim() {
  # First arg: exit code for the `-C` check (0 = exists, 1 = absent).
  # All calls are logged. Other operations always succeed.
  cat > "$MOCK_DIR/iptables" << MOCK
#!/bin/sh
echo "\$@" >> "\$IPTABLES_LOG"
case "\$1" in
  -C) exit $1 ;;
  *)  exit 0 ;;
esac
MOCK
  chmod +x "$MOCK_DIR/iptables"
}

@test "gate_ensure_chain: creates chain and installs tagged jump rule when both absent" {
  _install_iptables_shim 1
  source "$GATE_SCRIPT"
  run gate_ensure_chain
  assert_success

  # Chain creation attempted (-N may "fail" if exists; ignore exit, just assert call):
  run grep -F -- '-N OPENCONNECT_PROXY_GATE' "$IPTABLES_LOG"
  assert_success

  # Jump-rule presence checked with the exact comment:
  run grep -F -- '-C INPUT -m comment --comment openconnect-proxy-gate -j OPENCONNECT_PROXY_GATE' "$IPTABLES_LOG"
  assert_success

  # Jump rule inserted at INPUT position 1 with the exact comment:
  run grep -F -- '-I INPUT 1 -m comment --comment openconnect-proxy-gate -j OPENCONNECT_PROXY_GATE' "$IPTABLES_LOG"
  assert_success
}

@test "gate_ensure_chain: does not re-insert jump rule when -C reports present" {
  _install_iptables_shim 0
  source "$GATE_SCRIPT"
  run gate_ensure_chain
  assert_success

  run grep -F -- '-I INPUT 1 -m comment --comment openconnect-proxy-gate -j OPENCONNECT_PROXY_GATE' "$IPTABLES_LOG"
  assert_failure
}

# --- gate_set_closed / gate_set_open ---

@test "gate_set_closed: inserts REJECT at position 1 when absent (no flush)" {
  # Every -C returns 1 (rule absent), everything else 0.
  cat > "$MOCK_DIR/iptables" << 'MOCK'
#!/bin/sh
echo "$@" >> "$IPTABLES_LOG"
case "$1" in
  -C) exit 1 ;;
  *)  exit 0 ;;
esac
MOCK
  chmod +x "$MOCK_DIR/iptables"
  source "$GATE_SCRIPT"
  run gate_set_closed
  assert_success

  # REJECT must be inserted at position 1 with the exact spec:
  run grep -F -- '-I OPENCONNECT_PROXY_GATE 1 -p tcp -m multiport --dports 8888,8889 -m comment --comment openconnect-proxy-gate -j REJECT --reject-with tcp-reset' "$IPTABLES_LOG"
  assert_success

  # Never -F:
  run grep -F -- '-F' "$IPTABLES_LOG"
  assert_failure
}

@test "gate_set_closed: does NOT re-insert REJECT when -C reports present" {
  cat > "$MOCK_DIR/iptables" << 'MOCK'
#!/bin/sh
echo "$@" >> "$IPTABLES_LOG"
exit 0
MOCK
  chmod +x "$MOCK_DIR/iptables"
  source "$GATE_SCRIPT"
  run gate_set_closed
  assert_success

  # No -I against the gate chain:
  run grep -F -- '-I OPENCONNECT_PROXY_GATE' "$IPTABLES_LOG"
  assert_failure
}

@test "gate_set_open: removes REJECT via -D loop, never flushes" {
  # -C returns 0 twice (rule present, then duplicate present), then 1 (gone).
  STATE_FILE="$MOCK_DIR/state"
  echo 0 > "$STATE_FILE"
  cat > "$MOCK_DIR/iptables" << MOCK
#!/bin/sh
echo "\$@" >> "\$IPTABLES_LOG"
case "\$1" in
  -C)
    if [ "\$2" = "OPENCONNECT_PROXY_GATE" ]; then
      N=\$(cat "$STATE_FILE")
      if [ "\$N" -lt 2 ]; then
        echo \$((N + 1)) > "$STATE_FILE"
        exit 0
      fi
      exit 1
    fi
    exit 0
    ;;
  *) exit 0 ;;
esac
MOCK
  chmod +x "$MOCK_DIR/iptables"
  source "$GATE_SCRIPT"
  run gate_set_open
  assert_success

  # Two -D calls expected (one per present rule):
  run grep -c -F -- '-D OPENCONNECT_PROXY_GATE' "$IPTABLES_LOG"
  assert_success
  assert_output "2"

  # Never -F:
  run grep -F -- '-F' "$IPTABLES_LOG"
  assert_failure
}

@test "gate_set_open: no-op when chain has no REJECT rule" {
  # -C against the gate chain always reports absent (rule never present);
  # any other call succeeds.
  cat > "$MOCK_DIR/iptables" << 'MOCK'
#!/bin/sh
echo "$@" >> "$IPTABLES_LOG"
case "$1 $2" in
  "-C OPENCONNECT_PROXY_GATE") exit 1 ;;
  *)                            exit 0 ;;
esac
MOCK
  chmod +x "$MOCK_DIR/iptables"
  source "$GATE_SCRIPT"
  run gate_set_open
  assert_success

  # No -D against the gate chain — nothing to remove.
  run grep -F -- '-D OPENCONNECT_PROXY_GATE' "$IPTABLES_LOG"
  assert_failure

  # And no -F either.
  run grep -F -- '-F' "$IPTABLES_LOG"
  assert_failure
}

# --- gate_reconcile_tick ---

@test "gate_reconcile_tick: closed on interface absent, logs 'closed' on first transition" {
  _install_ip_shim 1 ""
  cat > "$MOCK_DIR/iptables" << 'MOCK'
#!/bin/sh
echo "$@" >> "$IPTABLES_LOG"
case "$1" in -C) exit 1 ;; *) exit 0 ;; esac
MOCK
  chmod +x "$MOCK_DIR/iptables"
  source "$GATE_SCRIPT"

  run gate_reconcile_tick
  assert_success
  assert_output --partial "tunnel-gate: tun0 state -> closed"

  # REJECT was inserted:
  run grep -F -- '-I OPENCONNECT_PROXY_GATE 1' "$IPTABLES_LOG"
  assert_success
}

@test "gate_reconcile_tick: open on interface up, second tick at same state is silent" {
  _install_ip_shim 0 "1: tun0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500"
  cat > "$MOCK_DIR/iptables" << 'MOCK'
#!/bin/sh
echo "$@" >> "$IPTABLES_LOG"
case "$1" in -C) exit 1 ;; *) exit 0 ;; esac
MOCK
  chmod +x "$MOCK_DIR/iptables"
  source "$GATE_SCRIPT"

  # First tick: transition unknown -> open, must log.
  run gate_reconcile_tick
  assert_success
  assert_output --partial "tunnel-gate: tun0 state -> open"

  # Second tick: state unchanged, must be silent.
  export GATE_LAST_STATE=open
  run gate_reconcile_tick
  assert_success
  assert_output ""
}

@test "gate_reconcile_tick: heals external INPUT flush by reinstalling jump rule" {
  _install_ip_shim 1 ""
  # First call sequence simulates the chain/jump absent after an external flush.
  # All -C return 1 (absent), other ops succeed.
  cat > "$MOCK_DIR/iptables" << 'MOCK'
#!/bin/sh
echo "$@" >> "$IPTABLES_LOG"
case "$1" in -C) exit 1 ;; *) exit 0 ;; esac
MOCK
  chmod +x "$MOCK_DIR/iptables"
  source "$GATE_SCRIPT"

  run gate_reconcile_tick
  assert_success

  # Jump rule was (re)installed:
  run grep -F -- '-I INPUT 1 -m comment --comment openconnect-proxy-gate -j OPENCONNECT_PROXY_GATE' "$IPTABLES_LOG"
  assert_success
}

# --- IPv6 modes ---

@test "TUNNEL_GATE_IPV6=auto + IPv6 absent: only iptables programmed, single skip log" {
  _install_ip_shim 1 ""
  cat > "$MOCK_DIR/iptables" << 'MOCK'
#!/bin/sh
echo "$@" >> "$IPTABLES_LOG"
case "$1" in -C) exit 1 ;; *) exit 0 ;; esac
MOCK
  # ip6tables shim fails — IPv6 detection should NOT call iptables ops via it.
  cat > "$MOCK_DIR/ip6tables" << 'MOCK'
#!/bin/sh
echo "$@" >> "$IP6TABLES_LOG"
exit 1
MOCK
  chmod +x "$MOCK_DIR/iptables" "$MOCK_DIR/ip6tables"

  export GATE_IPV6_PROC_PATH="$MOCK_DIR/no-ipv6"  # path absent on purpose
  export TUNNEL_GATE_IPV6=auto
  source "$GATE_SCRIPT"
  run gate_reconcile_tick
  assert_success
  assert_output --partial "IPv6 support not available"

  # ip6tables was only called for the detection probe (-L), if at all:
  if [ -s "$IP6TABLES_LOG" ]; then
    run grep -F -- '-I' "$IP6TABLES_LOG"
    assert_failure
    run grep -F -- '-N' "$IP6TABLES_LOG"
    assert_failure
  fi

  # Skip log fires exactly once across multiple ticks (cache hit on tick 2).
  # Must call both ticks in the same shell so GATE_IPV6_ACTIVE persists; BATS
  # `run` spawns a subshell, which would discard the cached state.
  GATE_LAST_STATE=closed  # suppress state-change log noise
  log_capture="$MOCK_DIR/ipv6.log"
  gate_reconcile_tick 2>"$log_capture"
  gate_reconcile_tick 2>>"$log_capture"
  count=$(grep -c "IPv6 support not available" "$log_capture" || true)
  [ "$count" = "1" ] || { echo "expected 1 skip log, got $count: $(cat "$log_capture")"; false; }
}

@test "TUNNEL_GATE_IPV6=auto + IPv6 present: both iptables and ip6tables programmed" {
  _install_ip_shim 1 ""
  cat > "$MOCK_DIR/iptables" << 'MOCK'
#!/bin/sh
echo "$@" >> "$IPTABLES_LOG"
case "$1" in -C) exit 1 ;; *) exit 0 ;; esac
MOCK
  cat > "$MOCK_DIR/ip6tables" << 'MOCK'
#!/bin/sh
echo "$@" >> "$IP6TABLES_LOG"
case "$1" in -C) exit 1 ;; -L) exit 0 ;; *) exit 0 ;; esac
MOCK
  chmod +x "$MOCK_DIR/iptables" "$MOCK_DIR/ip6tables"

  # Point GATE_IPV6_PROC_PATH at any existing directory to simulate "IPv6
  # sysctl tree present". The shim's ip6tables -L returns 0, so detection
  # passes both checks.
  export GATE_IPV6_PROC_PATH="$MOCK_DIR"
  export TUNNEL_GATE_IPV6=auto
  source "$GATE_SCRIPT"
  run gate_reconcile_tick
  assert_success

  run grep -F -- '-I OPENCONNECT_PROXY_GATE 1' "$IPTABLES_LOG"
  assert_success
  run grep -F -- '-I OPENCONNECT_PROXY_GATE 1' "$IP6TABLES_LOG"
  assert_success
}

@test "TUNNEL_GATE_IPV6=0 + IPv6 present: only iptables programmed" {
  _install_ip_shim 1 ""
  cat > "$MOCK_DIR/iptables" << 'MOCK'
#!/bin/sh
echo "$@" >> "$IPTABLES_LOG"
case "$1" in -C) exit 1 ;; *) exit 0 ;; esac
MOCK
  cat > "$MOCK_DIR/ip6tables" << 'MOCK'
#!/bin/sh
echo "$@" >> "$IP6TABLES_LOG"
exit 0
MOCK
  chmod +x "$MOCK_DIR/iptables" "$MOCK_DIR/ip6tables"

  export GATE_IPV6_PROC_PATH="$MOCK_DIR"
  export TUNNEL_GATE_IPV6=0
  source "$GATE_SCRIPT"
  run gate_reconcile_tick
  assert_success

  [ ! -s "$IP6TABLES_LOG" ] || { echo "ip6tables called: $(cat "$IP6TABLES_LOG")"; false; }
}

@test "TUNNEL_GATE_IPV6=1 + IPv6 unavailable: gate_resolve_ipv6 returns non-zero" {
  cat > "$MOCK_DIR/ip6tables" << 'MOCK'
#!/bin/sh
echo "$@" >> "$IP6TABLES_LOG"
exit 1
MOCK
  chmod +x "$MOCK_DIR/ip6tables"

  export GATE_IPV6_PROC_PATH="$MOCK_DIR/no-ipv6"  # absent
  export TUNNEL_GATE_IPV6=1
  source "$GATE_SCRIPT"
  run gate_resolve_ipv6
  assert_failure
  assert_output --partial "TUNNEL_GATE_IPV6=1 but IPv6 unavailable"
}

# --- gate_init_closed ---

@test "gate_init_closed: IPv4 success returns 0 and inserts REJECT" {
  cat > "$MOCK_DIR/iptables" << 'MOCK'
#!/bin/sh
echo "$@" >> "$IPTABLES_LOG"
case "$1" in -C) exit 1 ;; *) exit 0 ;; esac
MOCK
  cat > "$MOCK_DIR/ip6tables" << 'MOCK'
#!/bin/sh
echo "$@" >> "$IP6TABLES_LOG"
exit 1
MOCK
  chmod +x "$MOCK_DIR/iptables" "$MOCK_DIR/ip6tables"

  export GATE_IPV6_PROC_PATH="$MOCK_DIR/no-ipv6"
  export TUNNEL_GATE_IPV6=auto
  source "$GATE_SCRIPT"
  run gate_init_closed
  assert_success

  run grep -F -- '-I OPENCONNECT_PROXY_GATE 1' "$IPTABLES_LOG"
  assert_success
}

@test "gate_init_closed: IPv4 failure returns non-zero" {
  cat > "$MOCK_DIR/iptables" << 'MOCK'
#!/bin/sh
echo "$@" >> "$IPTABLES_LOG"
exit 1
MOCK
  chmod +x "$MOCK_DIR/iptables"

  export GATE_IPV6_PROC_PATH="$MOCK_DIR/no-ipv6"
  export TUNNEL_GATE_IPV6=auto
  source "$GATE_SCRIPT"
  run gate_init_closed
  assert_failure
}

# --- entrypoint integration: fail-closed startup ---

@test "entrypoint: initial gate-close failure exits non-zero before proxies launch" {
  ENTRYPOINT="$PROJECT_ROOT/build/entrypoint.sh"

  # iptables shim that fails every call.
  cat > "$MOCK_DIR/iptables" << 'MOCK'
#!/bin/sh
echo "$@" >> "$IPTABLES_LOG"
exit 1
MOCK
  TINYPROXY_INVOKED="$MOCK_DIR/tinyproxy_called"
  MICROSOCKS_INVOKED="$MOCK_DIR/microsocks_called"
  cat > "$MOCK_DIR/tinyproxy" << MOCK
#!/bin/sh
touch "$TINYPROXY_INVOKED"
exit 0
MOCK
  cat > "$MOCK_DIR/microsocks" << MOCK
#!/bin/sh
touch "$MICROSOCKS_INVOKED"
exit 0
MOCK
  cat > "$MOCK_DIR/openconnect" << 'MOCK'
#!/bin/sh
exit 0
MOCK
  cat > "$MOCK_DIR/sed" << 'MOCK'
#!/bin/sh
exit 0
MOCK
  chmod +x "$MOCK_DIR"/*

  export OPENCONNECT_URL="vpn.test"
  export OPENCONNECT_USER="user"
  export OPENCONNECT_PASSWORD="pw"
  export TUNNEL_GATE=1
  export TUNNEL_GATE_IPV6=0  # keep IPv6 path quiet
  export GATE_IPV6_PROC_PATH="$MOCK_DIR/no-ipv6"
  export TUNNEL_GATE_LIB="$PROJECT_ROOT/build/tunnel-gate.sh"

  run "$ENTRYPOINT"
  assert_failure
  [ ! -f "$TINYPROXY_INVOKED" ] || { echo "tinyproxy was launched"; false; }
  [ ! -f "$MICROSOCKS_INVOKED" ] || { echo "microsocks was launched"; false; }
}

@test "entrypoint cleanup: -D INPUT uses exact owned spec so user rules are untouched" {
  # Mocks that succeed; we just want to inspect the -D INPUT call shape.
  cat > "$MOCK_DIR/iptables" << 'MOCK'
#!/bin/sh
echo "$@" >> "$IPTABLES_LOG"
exit 0
MOCK
  cat > "$MOCK_DIR/ip6tables" << 'MOCK'
#!/bin/sh
echo "$@" >> "$IP6TABLES_LOG"
exit 0
MOCK
  chmod +x "$MOCK_DIR/iptables" "$MOCK_DIR/ip6tables"

  export TUNNEL_GATE=1
  export TUNNEL_GATE_IPV6=0
  export GATE_IPV6_PROC_PATH="$MOCK_DIR/no-ipv6"
  source "$PROJECT_ROOT/build/tunnel-gate.sh"

  # Simulate the entrypoint's cleanup -D INPUT call directly.
  # shellcheck disable=SC2046
  iptables -D INPUT $(_gate_jump_args) 2>/dev/null || true

  # Must include the exact comment — that's what protects user rules.
  run grep -F -- '-D INPUT -m comment --comment openconnect-proxy-gate -j OPENCONNECT_PROXY_GATE' "$IPTABLES_LOG"
  assert_success

  # Any -D INPUT in the log must include the gate comment:
  run sh -c 'grep -F -- "-D INPUT" "$IPTABLES_LOG" | grep -vF -- "-m comment --comment openconnect-proxy-gate"'
  assert_failure  # grep -v should find nothing (any -D INPUT line MUST have the comment)
}

@test "entrypoint: a normal OpenConnect exit removes the gate rules" {
  ENTRYPOINT="$MOCK_DIR/entrypoint.sh"
  sed \
    -e "s#/usr/bin/tinyproxy#$MOCK_DIR/tinyproxy#g" \
    -e "s#/usr/local/bin/microsocks#$MOCK_DIR/microsocks#g" \
    -e "s#/usr/local/bin/tunnel-gate.sh#$MOCK_DIR/tunnel-gate.sh#g" \
    "$PROJECT_ROOT/build/entrypoint.sh" > "$ENTRYPOINT"

  cat > "$MOCK_DIR/iptables" << 'MOCK'
#!/bin/sh
echo "$@" >> "$IPTABLES_LOG"
case "$1" in
  -C) exit 1 ;;
  *) exit 0 ;;
esac
MOCK
  cat > "$MOCK_DIR/tinyproxy" << 'MOCK'
#!/bin/sh
exit 0
MOCK
  cat > "$MOCK_DIR/microsocks" << 'MOCK'
#!/bin/sh
exit 0
MOCK
  cat > "$MOCK_DIR/tunnel-gate.sh" << 'MOCK'
#!/bin/sh
exit 0
MOCK
  cat > "$MOCK_DIR/openconnect" << 'MOCK'
#!/bin/sh
exit 0
MOCK
  cat > "$MOCK_DIR/sed" << 'MOCK'
#!/bin/sh
exit 0
MOCK
  chmod +x "$ENTRYPOINT" "$MOCK_DIR"/*

  export OPENCONNECT_URL="vpn.test"
  export OPENCONNECT_USER="user"
  export OPENCONNECT_PASSWORD="pw"
  export TUNNEL_GATE=1
  export TUNNEL_GATE_IPV6=0
  export TUNNEL_GATE_LIB="$PROJECT_ROOT/build/tunnel-gate.sh"

  run "$ENTRYPOINT"
  assert_success

  run grep -F -- '-D INPUT -m comment --comment openconnect-proxy-gate -j OPENCONNECT_PROXY_GATE' "$IPTABLES_LOG"
  assert_success
  run grep -F -- '-F OPENCONNECT_PROXY_GATE' "$IPTABLES_LOG"
  assert_success
  run grep -F -- '-X OPENCONNECT_PROXY_GATE' "$IPTABLES_LOG"
  assert_success
}
