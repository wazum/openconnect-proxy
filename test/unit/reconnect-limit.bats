#!/usr/bin/env bats

setup() {
  load '../test_helper/bats-support/load'
  load '../test_helper/bats-assert/load'

  PROJECT_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
  ENTRYPOINT="$PROJECT_ROOT/build/entrypoint.sh"
  ATTEMPT_FILE="$BATS_TEST_TMPDIR/attempts"

  eval "$(sed -n '/^validate_reconnect_settings()/,/^}/p' "$ENTRYPOINT")"
  eval "$(sed -n '/^run_with_retries()/,/^}/p' "$ENTRYPOINT")"

  export RECONNECT_DELAY=0
  export MAX_RECONNECT_ATTEMPTS=0
  export SUCCEED_ON_ATTEMPT=0
  echo 0 > "$ATTEMPT_FILE"
}

fake_openconnect() {
  attempt="$(cat "$ATTEMPT_FILE")"
  attempt=$((attempt + 1))
  echo "$attempt" > "$ATTEMPT_FILE"

  if [ "$SUCCEED_ON_ATTEMPT" -gt 0 ] && [ "$attempt" -ge "$SUCCEED_ON_ATTEMPT" ]; then
    return 0
  fi
  return 1
}

@test "zero keeps retries unlimited until OpenConnect succeeds" {
  export MAX_RECONNECT_ATTEMPTS=0
  export SUCCEED_ON_ATTEMPT=4

  run run_with_retries fake_openconnect
  assert_success
  assert_equal "$(cat "$ATTEMPT_FILE")" "4"
  refute_output --partial "Maximum reconnect attempts"
}

@test "limit N permits N retries after the initial attempt" {
  export MAX_RECONNECT_ATTEMPTS=2

  run run_with_retries fake_openconnect
  assert_failure
  assert_equal "$(cat "$ATTEMPT_FILE")" "3"
  assert_output --partial "Maximum reconnect attempts (2) reached"
}

@test "success on the final permitted retry is accepted" {
  export MAX_RECONNECT_ATTEMPTS=2
  export SUCCEED_ON_ATTEMPT=3

  run run_with_retries fake_openconnect
  assert_success
  assert_equal "$(cat "$ATTEMPT_FILE")" "3"
}

@test "retry log includes the bounded attempt number" {
  export MAX_RECONNECT_ATTEMPTS=2
  export SUCCEED_ON_ATTEMPT=2

  run run_with_retries fake_openconnect
  assert_success
  assert_output --partial "Reconnect attempt 1/2 in 0 seconds"
}

@test "accepts zero and positive integer limits" {
  MAX_RECONNECT_ATTEMPTS=0 run validate_reconnect_settings
  assert_success

  MAX_RECONNECT_ATTEMPTS=3 run validate_reconnect_settings
  assert_success
}

@test "rejects negative and non-numeric limits" {
  MAX_RECONNECT_ATTEMPTS=-1 run validate_reconnect_settings
  assert_failure
  assert_output --partial "MAX_RECONNECT_ATTEMPTS must be a non-negative integer"

  MAX_RECONNECT_ATTEMPTS=three run validate_reconnect_settings
  assert_failure
  assert_output --partial "MAX_RECONNECT_ATTEMPTS must be a non-negative integer"
}

@test "entrypoint wires the configured limit into OpenConnect execution" {
  test_entrypoint="$BATS_TEST_TMPDIR/entrypoint.sh"
  system_sed="$(command -v sed)"
  "$system_sed" \
    -e "s#/usr/bin/tinyproxy#$BATS_TEST_TMPDIR/tinyproxy#g" \
    -e "s#/usr/local/bin/microsocks#$BATS_TEST_TMPDIR/microsocks#g" \
    "$ENTRYPOINT" > "$test_entrypoint"

  cat > "$BATS_TEST_TMPDIR/tinyproxy" << 'MOCK'
#!/bin/sh
exit 0
MOCK
  cat > "$BATS_TEST_TMPDIR/microsocks" << 'MOCK'
#!/bin/sh
exit 0
MOCK
  cat > "$BATS_TEST_TMPDIR/openconnect" << 'MOCK'
#!/bin/sh
attempt="$(cat "$ATTEMPT_FILE")"
echo $((attempt + 1)) > "$ATTEMPT_FILE"
exit 1
MOCK
  cat > "$BATS_TEST_TMPDIR/sed" << 'MOCK'
#!/bin/sh
exit 0
MOCK
  chmod +x "$test_entrypoint" "$BATS_TEST_TMPDIR/tinyproxy" \
    "$BATS_TEST_TMPDIR/microsocks" "$BATS_TEST_TMPDIR/openconnect" \
    "$BATS_TEST_TMPDIR/sed"

  export PATH="$BATS_TEST_TMPDIR:$PATH"
  export ATTEMPT_FILE
  export OPENCONNECT_URL="vpn.test"
  export OPENCONNECT_USER="user"
  export OPENCONNECT_PASSWORD="pw"
  export TUNNEL_GATE=0
  export TUNNEL_GATE_LIB="$PROJECT_ROOT/build/tunnel-gate.sh"
  export MAX_RECONNECT_ATTEMPTS=2

  run "$test_entrypoint"
  assert_failure
  assert_equal "$(cat "$ATTEMPT_FILE")" "3"
  assert_output --partial "Maximum reconnect attempts (2) reached"
}
