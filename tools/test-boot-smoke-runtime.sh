#!/usr/bin/env bash
# Hosted contract test for boot-smoke's build/runtime boundary. The mock make
# never invokes QEMU: it models image preparation and a prebuilt-image QEMU
# launcher with controlled sleeps/exits.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d /tmp/oxide-test-boot-smoke-runtime-XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
MOCK_MAKE="$TMP/make"

cat >"$MOCK_MAKE" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
target="${!#}"
printf 'mock make target=%s\n' "$target"
case "$target" in
    qemu-x86-image)
        sleep "${MOCK_BUILD_SLEEP:-0}"
        [ "${MOCK_BUILD_FAIL:-0}" != 1 ] || exit 17
        ;;
    qemu-x86-existing)
        printf 'mock qemu launched\n'
        [ -z "${MOCK_QEMU_LOG:-}" ] || printf '%s\n' "$MOCK_QEMU_LOG"
        [ "${MOCK_QEMU_EARLY_EXIT:-0}" != 1 ] || exit 18
        printf '%s\n' "$$" >"$SMOKE_QEMU_PIDFILE"
        sleep "${MOCK_QEMU_SLEEP:-0}"
        ;;
    *) printf 'unexpected target: %s\n' "$target" >&2; exit 19 ;;
esac
EOF
chmod +x "$MOCK_MAKE"

run_smoke() {
    local name="$1"
    shift
    local log="$TMP/$name.log"
    set +e
    env SMOKE_MAKE="$MOCK_MAKE" SMOKE_QEMU_PIDFILE="$TMP/$name.pid" OXIDE_SMOKE_ATTEMPTS=1 \
        SMOKE_MARKER=never SMOKE_ALIVE_PROBE= SMOKE_RX_MARKER= \
        SMOKE_KEEP_LOG="$log" "$@" \
        "$ROOT/tools/boot-smoke.sh" x86 1 >"$TMP/$name.out" 2>&1
    RUN_STATUS=$?
    set -e
    RUN_LOG="$log"
    RUN_OUT="$TMP/$name.out"
}

# A build longer than the one-second runtime limit completes. The following
# live launcher, not the build, consumes that limit and gets a timeout label.
start="$(date +%s)"
run_smoke delayed-build MOCK_BUILD_SLEEP=2 MOCK_QEMU_SLEEP=3
elapsed=$(( $(date +%s) - start ))
[ "$RUN_STATUS" -eq 1 ]
[ "$elapsed" -ge 3 ]
grep -q 'image preparation complete' "$RUN_OUT"
grep -q 'timeout after 1s' "$RUN_OUT"
grep -q 'mock qemu launched' "$RUN_LOG"

# A launcher that exits before a guest can run is not a runtime timeout, and
# its captured log remains available.
run_smoke early-exit MOCK_QEMU_EARLY_EXIT=1
[ "$RUN_STATUS" -eq 1 ]
grep -q 'qemu exited before it started' "$RUN_OUT"
grep -q 'mock qemu launched' "$RUN_LOG"

# A still-live launcher with no proof reaches the runtime deadline and keeps
# the exact serial/build log for diagnosis.
run_smoke runtime-timeout MOCK_QEMU_SLEEP=3
[ "$RUN_STATUS" -eq 1 ]
grep -q 'timeout after 1s' "$RUN_OUT"
grep -q 'mock qemu launched' "$RUN_LOG"

# A successful guest keeps the same exact serial log. This is the supported
# replacement for redirecting `make qemu-*`, whose stdout is not the guest's
# early serial stream.
run_smoke successful MOCK_QEMU_LOG='guest reached ready' MOCK_QEMU_SLEEP=3 \
    SMOKE_MARKER='guest reached ready' SMOKE_KEEP_LOG_DIR="$TMP/success-attempts"
[ "$RUN_STATUS" -eq 0 ]
grep -q 'guest reached ready' "$RUN_LOG"
grep -q 'guest reached ready' "$TMP/success-attempts/x86-attempt-1-pass.log"
grep -q 'PASS' "$RUN_OUT"

# Preparation failures have their own exit class and retained build output.
run_smoke build-failure MOCK_BUILD_FAIL=1
[ "$RUN_STATUS" -eq 2 ]
grep -q 'image preparation failed before QEMU started' "$RUN_OUT"
grep -q 'mock make target=qemu-x86-image' "$RUN_LOG"

# A serial debug shell may answer before PID 1 later dies. That is never a
# usable boot, so the harness must fail on the init-fatal marker rather than
# accept any earlier liveness proof.
run_smoke init-fatal MOCK_QEMU_LOG='systemd[1]: segfault at deadbeef' MOCK_QEMU_SLEEP=3
[ "$RUN_STATUS" -eq 1 ]
grep -q 'KERNEL FAULT' "$RUN_OUT"
grep -q 'systemd\[1\]: segfault' "$RUN_LOG"

echo 'test-boot-smoke-runtime: PASS'
