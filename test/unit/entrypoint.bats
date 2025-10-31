#!/usr/bin/env bats

setup() {
  load '../test_helper/bats-support/load'
  load '../test_helper/bats-assert/load'

  PROJECT_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
  MOCK_DIR="$(mktemp -d)"

  export MOCK_ARGS_FILE="$MOCK_DIR/openconnect_args"
  export MOCK_STDIN_FILE="$MOCK_DIR/openconnect_stdin"

  cat > "$MOCK_DIR/openconnect" << 'MOCK'
#!/bin/sh
echo "$@" > "$MOCK_ARGS_FILE"
if [ -t 0 ]; then
  : > "$MOCK_STDIN_FILE"
else
  cat > "$MOCK_STDIN_FILE"
fi
exit 0
MOCK
  chmod +x "$MOCK_DIR/openconnect"
  export PATH="$MOCK_DIR:$PATH"

  # Extract the run() function from entrypoint.sh, renamed to vpn_run to avoid
  # conflicting with BATS's built-in run command
  eval "$(sed -n '/^run () {/,/^}/p' "$PROJECT_ROOT/build/entrypoint.sh" | sed 's/^run ()/vpn_run()/')"

  cat > "$MOCK_DIR/jq" << 'MOCK'
#!/bin/sh
if [ "$1" = "-r" ] && [ "$2" = ".cookie" ]; then
  cat "$3" | sed -n 's/.*"cookie": *"\([^"]*\)".*/\1/p'
fi
MOCK
  chmod +x "$MOCK_DIR/jq"

  export OPENCONNECT_USER="testuser"
  export OPENCONNECT_URL="vpn.example.com"
  unset OPENCONNECT_PASSWORD
  unset OPENCONNECT_MFA_CODE
  unset OPENCONNECT_OPTIONS
  unset OPENCONNECT_COOKIE
  unset OPENCONNECT_COOKIE_FILE
  unset VPN_SPLIT
  unset VPN_ROUTES
}

teardown() {
  rm -rf "$MOCK_DIR"
}

# --- Password modes ---

@test "interactive mode when password is not set" {
  run vpn_run
  assert_success
  assert_output --partial "Password not set. Prompting for password..."

  args="$(cat "$MOCK_ARGS_FILE")"
  assert_equal "$args" "-u testuser vpn.example.com"
}

@test "password-only mode pipes password via --passwd-on-stdin" {
  export OPENCONNECT_PASSWORD="secret123"

  run vpn_run
  assert_success
  assert_output --partial "Password detected. Starting OpenConnect."

  args="$(cat "$MOCK_ARGS_FILE")"
  assert_equal "$args" "-u testuser --passwd-on-stdin vpn.example.com"

  stdin_content="$(cat "$MOCK_STDIN_FILE")"
  assert_equal "$stdin_content" "secret123"
}

@test "MFA mode pipes password and MFA code" {
  export OPENCONNECT_PASSWORD="secret123"
  export OPENCONNECT_MFA_CODE="654321"

  run vpn_run
  assert_success
  assert_output --partial "Password and MFA detected."

  args="$(cat "$MOCK_ARGS_FILE")"
  assert_equal "$args" "-u testuser --passwd-on-stdin vpn.example.com"

  stdin_content="$(cat "$MOCK_STDIN_FILE")"
  expected="$(printf 'secret123\n654321')"
  assert_equal "$stdin_content" "$expected"
}

# --- Cookie auth ---

@test "cookie mode uses --cookie-on-stdin when OPENCONNECT_COOKIE is set" {
  export OPENCONNECT_COOKIE="webvpn=ABC123DEF456"

  run vpn_run
  assert_success
  assert_output --partial "Cookie/token detected."

  args="$(cat "$MOCK_ARGS_FILE")"
  assert_equal "$args" "--cookie-on-stdin vpn.example.com"

  stdin_content="$(cat "$MOCK_STDIN_FILE")"
  assert_equal "$stdin_content" "webvpn=ABC123DEF456"
}

@test "cookie mode does not pass -u username flag" {
  export OPENCONNECT_COOKIE="webvpn=ABC123DEF456"

  run vpn_run
  assert_success

  args="$(cat "$MOCK_ARGS_FILE")"
  refute_output --partial "-u testuser"
}

@test "cookie mode with custom options passes them through" {
  export OPENCONNECT_COOKIE="webvpn=ABC123DEF456"
  export OPENCONNECT_OPTIONS="--protocol=anyconnect --servercert pin-sha256:abc"

  run vpn_run
  assert_success

  args="$(cat "$MOCK_ARGS_FILE")"
  assert_equal "$args" "--protocol=anyconnect --servercert pin-sha256:abc --cookie-on-stdin vpn.example.com"
}

@test "cookie file mode reads cookie from JSON file" {
  cookie_file="$MOCK_DIR/cookie.json"
  echo '{"cookie": "webvpn=FROM_FILE_789", "host": "vpn.example.com"}' > "$cookie_file"
  export OPENCONNECT_COOKIE_FILE="$cookie_file"

  run vpn_run
  assert_success
  assert_output --partial "Cookie/token detected."

  stdin_content="$(cat "$MOCK_STDIN_FILE")"
  assert_equal "$stdin_content" "webvpn=FROM_FILE_789"
}

@test "cookie takes precedence over password auth" {
  export OPENCONNECT_COOKIE="webvpn=PRIORITY"
  export OPENCONNECT_PASSWORD="secret123"

  run vpn_run
  assert_success
  assert_output --partial "Cookie/token detected."
  refute_output --partial "Password detected."
}

@test "cookie file is ignored when file does not exist" {
  export OPENCONNECT_COOKIE_FILE="/nonexistent/cookie.json"
  export OPENCONNECT_PASSWORD="secret123"

  run vpn_run
  assert_success
  assert_output --partial "Password detected."
}

# --- OPENCONNECT_OPTIONS ---

@test "custom options are passed through in password mode" {
  export OPENCONNECT_PASSWORD="secret123"
  export OPENCONNECT_OPTIONS="--authgroup MyGroup --protocol=gp"

  run vpn_run
  assert_success

  args="$(cat "$MOCK_ARGS_FILE")"
  assert_equal "$args" "--authgroup MyGroup --protocol=gp -u testuser --passwd-on-stdin vpn.example.com"
}

@test "custom options are passed through in interactive mode" {
  export OPENCONNECT_OPTIONS="--servercert pin-sha256:abc123"

  run vpn_run
  assert_success

  args="$(cat "$MOCK_ARGS_FILE")"
  assert_equal "$args" "--servercert pin-sha256:abc123 -u testuser vpn.example.com"
}

# --- VPN split ---

@test "VPN_SPLIT injects vpn-slice as script option" {
  export OPENCONNECT_PASSWORD="secret123"
  export VPN_SPLIT=1
  export VPN_ROUTES="10.0.0.0/8 172.16.0.0/12"

  run vpn_run
  assert_success

  args="$(cat "$MOCK_ARGS_FILE")"
  assert_equal "$args" "--script=vpn-slice 10.0.0.0/8 172.16.0.0/12 -u testuser --passwd-on-stdin vpn.example.com"
}

@test "VPN_SPLIT with custom options combines correctly" {
  export OPENCONNECT_PASSWORD="secret123"
  export VPN_SPLIT=1
  export VPN_ROUTES="10.0.0.0/8"
  export OPENCONNECT_OPTIONS="--protocol=anyconnect"

  run vpn_run
  assert_success

  args="$(cat "$MOCK_ARGS_FILE")"
  assert_equal "$args" "--protocol=anyconnect --script=vpn-slice 10.0.0.0/8 -u testuser --passwd-on-stdin vpn.example.com"
}

# --- Configurable ports and delay ---

@test "PROXY_PORT defaults to 8888" {
  run grep 'PROXY_PORT=' "$PROJECT_ROOT/build/entrypoint.sh"
  assert_success
  assert_output --partial ':-8888'
}

@test "SOCKS_PORT defaults to 8889" {
  run grep 'SOCKS_PORT=' "$PROJECT_ROOT/build/entrypoint.sh"
  assert_success
  assert_output --partial ':-8889'
}

@test "RECONNECT_DELAY defaults to 60" {
  run grep 'RECONNECT_DELAY=' "$PROJECT_ROOT/build/entrypoint.sh"
  assert_success
  assert_output --partial ':-60'
}

@test "PROXY_PORT is used in tinyproxy sed and HEALTHCHECK" {
  count="$(grep -c 'PROXY_PORT' "$PROJECT_ROOT/build/entrypoint.sh")"
  [ "$count" -ge 2 ]
}

@test "SOCKS_PORT is used in microsocks startup" {
  run grep 'microsocks.*SOCKS_PORT' "$PROJECT_ROOT/build/entrypoint.sh"
  assert_success
}

# --- Signal handling ---

@test "entrypoint.sh traps TERM and INT signals" {
  run grep 'trap cleanup TERM INT' "$PROJECT_ROOT/build/entrypoint.sh"
  assert_success
}

@test "cleanup function kills proxy PIDs" {
  run grep -A3 'cleanup()' "$PROJECT_ROOT/build/entrypoint.sh"
  assert_output --partial 'TINYPROXY_PID'
  assert_output --partial 'MICROSOCKS_PID'
}
