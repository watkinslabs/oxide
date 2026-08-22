#!/usr/bin/env bash
# Focused RED/GREEN control for test-build-check's first-pass diagnostics.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"

cat >"$tmp/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -eu
if [ "${1:-}" = metadata ]; then
    printf '%s\n' '{"packages":[{"name":"diagnostic-fixture"}]}'
    exit 0
fi
count=0
[ ! -f "$FAKE_CARGO_COUNT" ] || count="$(cat "$FAKE_CARGO_COUNT")"
count=$((count + 1))
printf '%s\n' "$count" >"$FAKE_CARGO_COUNT"
if [ "$count" -eq 1 ]; then
    echo "error: couldn't create a temp dir: No such file or directory (os error 2)" >&2
    exit 1
fi
exit 0
EOF
chmod +x "$tmp/bin/cargo"

set +e
output="$(PATH="$tmp/bin:$PATH" FAKE_CARGO_COUNT="$tmp/count" \
    TEST_BUILD_CHECK_JOBS=1 "$root/tools/test-build-check.sh" 2>&1)"
status=$?
set -e

[ "$status" -ne 0 ] || {
    echo "test-build-check-selftest: expected the first pass to fail" >&2
    exit 1
}
case "$output" in
    *"couldn't create a temp dir"*) ;;
    *)
        echo "test-build-check-selftest: original diagnostic was lost" >&2
        printf '%s\n' "$output" >&2
        exit 1
        ;;
esac
case "$output" in
    *"infrastructure failure: target directory vanished"*) ;;
    *)
        echo "test-build-check-selftest: vanished target directory was not classified" >&2
        printf '%s\n' "$output" >&2
        exit 1
        ;;
esac

echo "test-build-check-selftest: PASS"
