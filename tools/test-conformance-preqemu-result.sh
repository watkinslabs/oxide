#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/tools/oxide-conformance-ssh.sh"
TMP="$(mktemp -d /tmp/oxide-conformance-test-XXXXXX)"
trap ':' EXIT

cat > "$TMP/cargo" <<'EOF'
#!/usr/bin/env bash
case " $* " in
  *' rootfs '*)
    if [ "${CONFORMANCE_TEST_PREQEMU_FAIL:-0}" = 1 ]; then
        [ "${CONFORMANCE_TEST_SIGNAL:-0}" = 1 ] && kill -TERM "$PPID"
        exit 23
    fi
    ;;
  *' grub '*)
    if [ "${CONFORMANCE_TEST_LAUNCH:-dead}" = dead ]; then exit 0; fi
    while [ "$#" -gt 0 ]; do
        if [ "$1" = --id ]; then run_id="$2"; fi
        if [ "$1" = --arch ]; then arch="$2"; fi
        shift
    done
    if [ "${CONFORMANCE_TEST_LAUNCH:-dead}" = pidfile; then
        mkdir -p "target/builds/$run_id"
        (exec -a "qemu-system-$arch target/builds/$run_id/" sleep "$CONFORMANCE_TEST_QEMU_SECONDS") &
        qpid="$!"
        printf '%s\n' "$qpid" > "target/builds/$run_id/qemu-$arch.pid"
        [ -z "${CONFORMANCE_TEST_LAUNCH_LOG:-}" ] || printf '%s %s\n' "$run_id" "$qpid" >> "$CONFORMANCE_TEST_LAUNCH_LOG"
        exit 0
    fi
    exec -a "qemu-system-$arch target/builds/$run_id/" sleep "$CONFORMANCE_TEST_QEMU_SECONDS"
    ;;
esac
exit 0
EOF
chmod +x "$TMP/cargo"

cat > "$TMP/debugfs" <<'EOF'
#!/usr/bin/env bash
case " $* " in
  *'dump /etc/passwd /tmp/oxide-conformance-passwd-dump'*)
    printf 'oxide:x:1000:1000::/home/oxide:/bin/sh\n' > /tmp/oxide-conformance-passwd-dump
    ;;
esac
EOF
chmod +x "$TMP/debugfs"

cat > "$TMP/ssh-keygen" <<'EOF'
#!/usr/bin/env bash
while [ "$#" -gt 0 ]; do
    if [ "$1" = -f ]; then key="$2"; break; fi
    shift
done
: > "$key"
: > "${key}.pub"
EOF
chmod +x "$TMP/ssh-keygen"

cat > "$TMP/ssh-keyscan" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod +x "$TMP/ssh-keyscan"

assert_result() {
    local id="$1" phase="$2" exit_status="$3" signal="$4" record
    record="$(find "$ROOT/target/network-conformance" -maxdepth 2 -type f -name harness.json -path "$ROOT/target/network-conformance/${id}.*/*" -print -quit)"
    test -n "$record"
    test -f "$record"
    grep -F '"phase":"'"$phase"'"' "$record" >/dev/null
    grep -F '"terminal":true' "$record" >/dev/null
    grep -F '"exit":'"$exit_status" "$record" >/dev/null
    grep -F '"signal":'"$signal" "$record" >/dev/null
    grep -F '"qemu_started":false' "$record" >/dev/null
}

id_fail="conformance-preqemu-fail-$$"
set +e
(cd "$ROOT" && PATH="$TMP:$PATH" CONFORMANCE_TEST_PREQEMU_FAIL=1 OXIDE_CONFORMANCE_RUN_ID="$id_fail" "$SCRIPT" x86_64 t_mmsg 180) >/dev/null 2>&1
status=$?
set -e
test "$status" -eq 23
assert_result "$id_fail" rootfs 23 null

id_term="conformance-preqemu-term-$$"
set +e
(cd "$ROOT" && PATH="$TMP:$PATH" CONFORMANCE_TEST_PREQEMU_FAIL=1 CONFORMANCE_TEST_SIGNAL=1 OXIDE_CONFORMANCE_RUN_ID="$id_term" "$SCRIPT" x86_64 t_mmsg 180) >/dev/null 2>&1
status=$?
set -e
test "$status" -eq 143
assert_result "$id_term" rootfs 143 '"TERM"'

assert_qemu_terminal() {
    local id="$1" cause="$2" record
    record="$(find "$ROOT/target/network-conformance" -maxdepth 2 -type f -name harness.json -path "$ROOT/target/network-conformance/${id}.*/*" -print -quit)"
    test -n "$record"
    test -f "$record"
    grep -F '"phase":"qemu"' "$record" >/dev/null
    grep -F '"terminal":true' "$record" >/dev/null
    grep -F '"exit":1' "$record" >/dev/null
    if [ "$cause" = null ]; then
        grep -F '"cause":null' "$record" >/dev/null
    else
        grep -F '"cause":"'"$cause"'"' "$record" >/dev/null
    fi
    grep -F '"qemu_started":true' "$record" >/dev/null
}

DEAD_LAUNCH_TIMEOUT_SECONDS=10
id_dead="conformance-liveness-dead-$$"
started="$(date +%s)"
set +e
(cd "$ROOT" && PATH="$TMP:$PATH" CONFORMANCE_TEST_LAUNCH=dead OXIDE_CONFORMANCE_RUN_ID="$id_dead" "$SCRIPT" x86_64 t_mmsg "$DEAD_LAUNCH_TIMEOUT_SECONDS") >"$TMP/dead.out" 2>&1
status=$?
set -e
elapsed=$(( $(date +%s) - started ))
test "$status" -eq 1
test "$elapsed" -lt "$DEAD_LAUNCH_TIMEOUT_SECONDS"
grep -F 'SSH readiness failed: launcher and QEMU exited' "$TMP/dead.out" >/dev/null
assert_qemu_terminal "$id_dead" 'SSH readiness: launcher and QEMU exited'

LIVE_GATE_TIMEOUT_SECONDS=1
LIVE_QEMU_SECONDS=5
id_live="conformance-liveness-live-$$"
started="$(date +%s)"
set +e
(cd "$ROOT" && PATH="$TMP:$PATH" CONFORMANCE_TEST_LAUNCH=live CONFORMANCE_TEST_QEMU_SECONDS="$LIVE_QEMU_SECONDS" OXIDE_CONFORMANCE_RUN_ID="$id_live" "$SCRIPT" x86_64 t_mmsg "$LIVE_GATE_TIMEOUT_SECONDS") >"$TMP/live.out" 2>&1
status=$?
set -e
elapsed=$(( $(date +%s) - started ))
test "$status" -eq 1
test "$elapsed" -ge "$LIVE_GATE_TIMEOUT_SECONDS"
grep -F 'oxide-conformance: SSH timeout' "$TMP/live.out" >/dev/null
if grep -F 'launcher and QEMU exited' "$TMP/live.out" >/dev/null; then exit 1; fi
assert_qemu_terminal "$id_live" null

id_pidfile="conformance-liveness-pidfile-$$"
started="$(date +%s)"
set +e
(cd "$ROOT" && PATH="$TMP:$PATH" CONFORMANCE_TEST_LAUNCH=pidfile CONFORMANCE_TEST_QEMU_SECONDS="$LIVE_QEMU_SECONDS" OXIDE_CONFORMANCE_RUN_ID="$id_pidfile" "$SCRIPT" x86_64 t_mmsg "$LIVE_GATE_TIMEOUT_SECONDS") >"$TMP/pidfile.out" 2>&1
status=$?
set -e
elapsed=$(( $(date +%s) - started ))
test "$status" -eq 1
test "$elapsed" -ge "$LIVE_GATE_TIMEOUT_SECONDS"
grep -F 'oxide-conformance: SSH timeout' "$TMP/pidfile.out" >/dev/null
if grep -F 'launcher and QEMU exited' "$TMP/pidfile.out" >/dev/null; then exit 1; fi
assert_qemu_terminal "$id_pidfile" null

# Reusing a requested label creates two distinct reserved build namespaces.
# Let the older watchdog expire after the newer launch; it must terminate only
# its own aarch64 QEMU, leaving the newer VM alive for its full budget.
REUSED_LABEL="conformance-reused-label-$$"
REUSED_OVERLAP_SECONDS=1
REUSED_OLD_TIMEOUT=2
REUSED_NEW_TIMEOUT=5
REUSED_QEMU_SECONDS=8
set +e
(cd "$ROOT" && PATH="$TMP:$PATH" CONFORMANCE_TEST_LAUNCH=pidfile CONFORMANCE_TEST_QEMU_SECONDS="$REUSED_QEMU_SECONDS" OXIDE_CONFORMANCE_RUN_ID="$REUSED_LABEL" "$SCRIPT" aarch64 t_mmsg "$REUSED_OLD_TIMEOUT") >"$TMP/reused-old.out" 2>&1 &
old_runner=$!
sleep "$REUSED_OVERLAP_SECONDS"
(cd "$ROOT" && PATH="$TMP:$PATH" CONFORMANCE_TEST_LAUNCH=pidfile CONFORMANCE_TEST_QEMU_SECONDS="$REUSED_QEMU_SECONDS" OXIDE_CONFORMANCE_RUN_ID="$REUSED_LABEL" "$SCRIPT" aarch64 t_mmsg "$REUSED_NEW_TIMEOUT") >"$TMP/reused-new.out" 2>&1 &
new_runner=$!
wait "$old_runner"
old_status=$?
set -e
test "$old_status" -eq 1
new_pidfile="$(ls -t "$ROOT"/target/builds/"${REUSED_LABEL}".*/qemu-aarch64.pid | head -n 1)"
new_qpid="$(cat "$new_pidfile")"
kill -0 "$new_qpid"
wait "$new_runner" || true
