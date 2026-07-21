#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/tools/oxide-conformance-ssh.sh"
TMP="$(mktemp -d /tmp/oxide-conformance-test-XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/cargo" <<'EOF'
#!/usr/bin/env bash
case " $* " in
  *' rootfs '*)
    [ "${CONFORMANCE_TEST_SIGNAL:-0}" = 1 ] && kill -TERM "$PPID"
    exit 23
    ;;
esac
exit 99
EOF
chmod +x "$TMP/cargo"

assert_result() {
    local id="$1" phase="$2" exit_status="$3" signal="$4" record
    record="$ROOT/target/network-conformance/$id/harness.json"
    test -f "$record"
    grep -F '"phase":"'"$phase"'"' "$record" >/dev/null
    grep -F '"terminal":true' "$record" >/dev/null
    grep -F '"exit":'"$exit_status" "$record" >/dev/null
    grep -F '"signal":'"$signal" "$record" >/dev/null
    grep -F '"qemu_started":false' "$record" >/dev/null
}

id_fail="conformance-preqemu-fail-$$"
set +e
(cd "$ROOT" && PATH="$TMP:$PATH" OXIDE_CONFORMANCE_RUN_ID="$id_fail" "$SCRIPT" x86_64 t_mmsg 180) >/dev/null 2>&1
status=$?
set -e
test "$status" -eq 23
assert_result "$id_fail" rootfs 23 null

id_term="conformance-preqemu-term-$$"
set +e
(cd "$ROOT" && PATH="$TMP:$PATH" CONFORMANCE_TEST_SIGNAL=1 OXIDE_CONFORMANCE_RUN_ID="$id_term" "$SCRIPT" x86_64 t_mmsg 180) >/dev/null 2>&1
status=$?
set -e
test "$status" -eq 143
assert_result "$id_term" rootfs 143 '"TERM"'
