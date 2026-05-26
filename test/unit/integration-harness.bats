#!/usr/bin/env bats

setup() {
  load '../test_helper/bats-support/load'
  load '../test_helper/bats-assert/load'

  PROJECT_ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
  eval "$(sed -n '/^classify_tcp_probe()/,/^}/p' "$PROJECT_ROOT/test/integration/run.sh")"
}

@test "classifies BusyBox open output" {
  run classify_tcp_probe "proxy:8888 open" 0
  assert_success
  assert_output "open"
}

@test "classifies BusyBox empty exit 1 as refused" {
  run classify_tcp_probe "" 1
  assert_success
  assert_output "refused"
}

@test "classifies explicit connection-refused output" {
  run classify_tcp_probe "nc: connect to proxy port 8888 (tcp) failed: Connection refused" 1
  assert_success
  assert_output "refused"
}

@test "classifies BusyBox timeout output as timeout" {
  run classify_tcp_probe "nc: 203.0.113.1 (203.0.113.1:8888): Operation timed out" 1
  assert_success
  assert_output "timeout"
}

@test "does not classify a DNS failure as refused" {
  run classify_tcp_probe "nc: bad address 'missing-container'" 1
  assert_success
  assert_output "error: nc: bad address 'missing-container'"
}
