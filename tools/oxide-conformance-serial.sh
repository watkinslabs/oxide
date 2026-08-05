#!/usr/bin/env bash
# Run conformance probes through a serial completion marker and disk frames.
# This keeps target execution independent of guest networking while retaining
# the same manifest, host oracle, uid, argv and byte-exact result comparison.
set -euo pipefail

ARCH="${1:-aarch64}"
TESTS="${2:-t_mmsg}"
TIMEOUT="${3:-180}"
QEMU_TIMEOUT_MAX=180
GUEST_USER="${OXIDE_CONFORMANCE_USER:-oxide}"
case "$ARCH" in
    x86_64) QEMU_ARCH=x86_64 ;;
    aarch64) QEMU_ARCH=aarch64 ;;
    *) echo "usage: $0 <x86_64|aarch64> <test[,test...]> [timeout]" >&2; exit 2 ;;
esac
if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || [ "$TIMEOUT" -eq 0 ] || [ "$TIMEOUT" -gt "$QEMU_TIMEOUT_MAX" ]; then
    echo "oxide-conformance: timeout must be 1..$QEMU_TIMEOUT_MAX seconds" >&2
    exit 2
fi

RUN_LABEL="${OXIDE_CONFORMANCE_RUN_ID:-conformance-serial-${ARCH}}"
case "$RUN_LABEL" in
    ''|.|..|*[!A-Za-z0-9._-]*)
        echo "oxide-conformance: run label must use [A-Za-z0-9._-], not . or .." >&2
        exit 2
        ;;
esac
MANIFEST="tools/network-conformance-manifest.tsv"
test -f "$MANIFEST" || { echo "oxide-conformance: missing $MANIFEST" >&2; exit 2; }
mkdir -p target/builds
BUILD_DIR="$(mktemp -d "target/builds/${RUN_LABEL}.XXXXXX")"
ID="${BUILD_DIR##*/}"
FRAME_DIR="target/network-conformance/$ID"
mkdir -p "$FRAME_DIR"
LOG="$(mktemp /tmp/oxide-conformance-serial-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-conformance-serial-XXXXXX.pid)"
QEMU_PIDFILE="target/builds/$ID/qemu-$QEMU_ARCH.pid"
RUNNER="$(mktemp /tmp/oxide-conformance-runner-XXXXXX)"
SERVICE="$(mktemp /tmp/oxide-conformance-service-XXXXXX)"
TARGET="$(mktemp /tmp/oxide-conformance-target-XXXXXX)"
RESULT_DIR="/var/lib/oxide-conformance"
QEMU_FEATURES="${OXIDE_QEMU_FEATURES-debug-sshd}"
QEMU_WATCHDOG=""
TERMINAL=false
PHASE=init

write_harness() {
    local terminal="$1" status="$2" tmp
    tmp="$(mktemp "$FRAME_DIR/.harness.XXXXXX")"
    printf '{"schema":1,"kind":"harness","phase":"%s","transport":"serial-disk","terminal":%s,"exit":%s}\n' \
        "$PHASE" "$terminal" "$status" > "$tmp"
    mv -f "$tmp" "$FRAME_DIR/harness.json"
}
qemu_owned() {
    local qpid="$1" cmd
    [ -r "/proc/$qpid/cmdline" ] || return 1
    cmd="$(tr '\0' ' ' < "/proc/$qpid/cmdline")"
    case "$cmd" in
        *"qemu-system-${QEMU_ARCH}"*"target/builds/${ID}/"*) return 0 ;;
        *) return 1 ;;
    esac
}
stop_qemu() {
    local qpid
    qpid="$(cat "$QEMU_PIDFILE" 2>/dev/null || true)"
    [[ "$qpid" =~ ^[0-9]+$ ]] || return
    qemu_owned "$qpid" || return
    kill -TERM "$qpid" 2>/dev/null || true
}
launcher_owned() {
    local pid="$1" start="$2" now
    [[ "$pid" =~ ^[0-9]+$ && "$start" =~ ^[0-9]+$ ]] || return 1
    [ -r "/proc/$pid/stat" ] || return 1
    now="$(awk '{print $22}' "/proc/$pid/stat")"
    [ "$now" = "$start" ]
}
stop_launcher() {
    local pid start
    read -r pid start < "$PIDFILE" 2>/dev/null || return
    launcher_owned "$pid" "$start" || return
    kill -TERM "$pid" 2>/dev/null || true
}
cleanup() {
    local status=$?
    if [ "$TERMINAL" = false ]; then write_harness true "$status"; fi
    stop_qemu
    stop_launcher
    [ -z "$QEMU_WATCHDOG" ] || kill -TERM "$QEMU_WATCHDOG" 2>/dev/null || true
    rm -f "$PIDFILE" "$RUNNER" "$SERVICE" "$TARGET"
    if [ -n "${OXIDE_CONFORMANCE_DEBUG:-}" ]; then
        echo "oxide-conformance: retained serial log=$LOG" >&2
    else
        rm -f "$LOG"
    fi
}
trap cleanup EXIT

probe_meta() {
    awk -F '\t' -v probe="$1" '$1 !~ /^#/ && $4 == probe {
        argv = NF >= 10 ? $7 : "-"
        uid = NF >= 10 ? $8 : "unprivileged"
        policy = NF >= 10 ? $9 : "differential"
        stdout = NF >= 10 ? $10 : "-"
        print $1 "\t" $2 "\t" $3 "\t" $5 "\t" argv "\t" uid "\t" policy "\t" stdout
        found=1
    } END { exit !found }' "$MANIFEST"
}
probe_contract() {
    awk -F '\t' 'NR == 1 { argv = $5; uid = $6; policy = $7; stdout = $8; next }
        $5 != argv || $6 != uid || $7 != policy || $8 != stdout { exit 1 }
        END { if (NR == 0) exit 1; print argv "\t" uid "\t" policy "\t" stdout }'
}
parse_probe_argv() {
    local encoded="$1" argument
    PROBE_ARGV=()
    [ "$encoded" = - ] && return 0
    IFS=, read -r -a PROBE_ARGV <<< "$encoded"
    [ "${#PROBE_ARGV[@]}" -gt 0 ] || return 1
    for argument in "${PROBE_ARGV[@]}"; do
        [[ "$argument" =~ ^[[:alnum:]_.=+:-]+$ ]] || return 1
    done
}
guest_command() {
    local uid="$1" guest="$2" argument command
    command="env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC HOME=/ '$guest'"
    for argument in "${PROBE_ARGV[@]}"; do command+=" '$argument'"; done
    case "$uid" in
        unprivileged) printf "runuser -u '%s' -- %s" "$GUEST_USER" "$command" ;;
        root) printf '%s' "$command" ;;
        *) return 1 ;;
    esac
}
frame_b64() { base64 -w 0 "$1"; }
debugfs_write() {
    local src="$1" dst="$2" mode="$3" image="target/builds/$ID/root-$QEMU_ARCH.img"
    debugfs -w -R "rm $dst" "$image" >/dev/null 2>&1 || true
    debugfs -w -R "write $src $dst" "$image" >/dev/null
    debugfs -w -R "sif $dst mode $mode" "$image" >/dev/null
}

echo "oxide-conformance: prepare arch=$ARCH tests=$TESTS id=$ID transport=serial-disk"
PHASE=rootfs; write_harness false 0
cargo run -q -p xtask -- rootfs --arch "$QEMU_ARCH" --id "$ID"
PHASE=host-oracle; write_harness false 0
cargo run -q -p xtask -- conformance --arch "$ARCH" --tests "$TESTS" --inject "$TESTS" --id "$ID"

printf '%s\n' '#!/usr/bin/env bash' 'set -eu' "mkdir -p '$RESULT_DIR'" > "$RUNNER"
for name in ${TESTS//,/ }; do
    [[ "$name" =~ ^[[:alnum:]_]+$ ]] || { echo "oxide-conformance: unsafe test name $name" >&2; exit 2; }
    meta="$(probe_meta "$name")" || { echo "oxide-conformance: probe $name absent from $MANIFEST" >&2; exit 2; }
    contract="$(printf '%s\n' "$meta" | probe_contract)" || {
        echo "oxide-conformance: probe $name has no uniform execution contract" >&2; exit 2;
    }
    IFS=$'\t' read -r argv_spec probe_uid output_policy expected_stdout <<< "$contract"
    parse_probe_argv "$argv_spec" || { echo "oxide-conformance: invalid argv contract for $name" >&2; exit 2; }
    command="$(guest_command "$probe_uid" "/usr/local/bin/oxide-conformance-$name")" || {
        echo "oxide-conformance: invalid uid contract for $name" >&2; exit 2;
    }
    case "$output_policy" in differential|target-pass-exact) ;; *) exit 2 ;; esac
    printf '%s\n' \
        'set +e' \
        "$command >'$RESULT_DIR/$name.stdout' 2>'$RESULT_DIR/$name.stderr'" \
        'status=$?' \
        'set -e' \
        "printf '%s\\n' \"\$status\" >'$RESULT_DIR/$name.status'" >> "$RUNNER"
done
printf '%s\n' 'sync' >> "$RUNNER"
printf '%s\n' \
    '[Unit]' \
    'Description=Oxide serial conformance runner' \
    'DefaultDependencies=no' \
    'Before=shutdown.target' \
    'Conflicts=shutdown.target' \
    '[Service]' \
    'Type=oneshot' \
    'ExecStart=/usr/local/bin/oxide-conformance-serial-runner' \
    'StandardOutput=journal+console' \
    'StandardError=journal+console' > "$SERVICE"
printf '%s\n' \
    '[Unit]' \
    'Description=Oxide serial conformance target' \
    'DefaultDependencies=no' \
    'Wants=oxide-conformance-serial.service' \
    'After=oxide-conformance-serial.service' > "$TARGET"
debugfs_write "$RUNNER" /usr/local/bin/oxide-conformance-serial-runner 0100755
debugfs_write "$SERVICE" /etc/systemd/system/oxide-conformance-serial.service 0100644
debugfs_write "$TARGET" /etc/systemd/system/oxide-conformance-serial.target 0100644
image="target/builds/$ID/root-$QEMU_ARCH.img"
debugfs -w -R 'rm /etc/systemd/system/default.target' "$image" >/dev/null 2>&1 || true
debugfs -w -R 'symlink /etc/systemd/system/default.target oxide-conformance-serial.target' "$image" >/dev/null

PHASE=image; write_harness false 0
image_args=(run -q -p xtask -- image --arch "$QEMU_ARCH" --id "$ID")
if [ -n "$QEMU_FEATURES" ]; then image_args+=(--features "$QEMU_FEATURES"); fi
OXIDE_SKIP_ROOTFS=1 cargo "${image_args[@]}"

OXIDE_SKIP_ROOTFS=1 OXIDE_QEMU_HEADLESS=1 \
    setsid bash -c "exec cargo run -q -p xtask -- grub --arch $QEMU_ARCH --id $ID --run-existing > '$LOG' 2>&1 < /dev/null" &
launcher_pid=$!
launcher_start="$(awk '{print $22}' "/proc/$launcher_pid/stat" 2>/dev/null || true)"
printf '%s %s\n' "$launcher_pid" "$launcher_start" > "$PIDFILE"
PHASE=qemu; write_harness false 0
(
    sleep "$TIMEOUT"
    stop_qemu
    stop_launcher
) &
QEMU_WATCHDOG=$!
deadline=$(( $(date +%s) + TIMEOUT ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    grep -q 'oxide-conformance-serial.service: Deactivated successfully' "$LOG" 2>/dev/null && break
    if ! launcher_owned "$launcher_pid" "$launcher_start" && ! [ -r "$QEMU_PIDFILE" ]; then
        echo "oxide-conformance: serial runner exited before completion" >&2
        tail -80 "$LOG" >&2
        exit 1
    fi
    sleep 1
done
if ! grep -q 'oxide-conformance-serial.service: Deactivated successfully' "$LOG" 2>/dev/null; then
    echo "oxide-conformance: serial completion timeout" >&2
    tail -80 "$LOG" >&2
    exit 1
fi
stop_qemu
wait "$launcher_pid" 2>/dev/null || true

PHASE=compare; write_harness false 0
for name in ${TESTS//,/ }; do
    meta="$(probe_meta "$name")"
    rows="$(printf '%s\n' "$meta" | awk -F '\t' '{ if (NR > 1) printf ","; printf $1 }')"
    syscalls="$(printf '%s\n' "$meta" | awk -F '\t' '{ if (NR > 1) printf ","; printf $2 }')"
    families="$(printf '%s\n' "$meta" | awk -F '\t' '{ if (NR > 1) printf ";"; printf $3 }')"
    states="$(printf '%s\n' "$meta" | awk -F '\t' '{ if (NR > 1) printf ","; printf $4 }')"
    contract="$(printf '%s\n' "$meta" | probe_contract)"
    IFS=$'\t' read -r argv_spec probe_uid output_policy expected_stdout <<< "$contract"
    parse_probe_argv "$argv_spec"
    expected_out="$(mktemp /tmp/oxide-conformance-expected-out-XXXXXX)"
    expected_err="$(mktemp /tmp/oxide-conformance-expected-err-XXXXXX)"
    guest_out="$(mktemp /tmp/oxide-conformance-guest-out-XXXXXX)"
    guest_err="$(mktemp /tmp/oxide-conformance-guest-err-XXXXXX)"
    guest_status_file="$(mktemp /tmp/oxide-conformance-guest-status-XXXXXX)"
    if [ "$output_policy" = differential ]; then
        set +e
        env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC HOME=/ \
            "target/glibc-conf/${name}.host" "${PROBE_ARGV[@]}" >"$expected_out" 2>"$expected_err"
        expected_status=$?
        set -e
    else
        printf '%s\n' "$expected_stdout" > "$expected_out"
        : > "$expected_err"
        expected_status=0
    fi
    debugfs -R "dump $RESULT_DIR/$name.stdout $guest_out" "$image" >/dev/null
    debugfs -R "dump $RESULT_DIR/$name.stderr $guest_err" "$image" >/dev/null
    debugfs -R "dump $RESULT_DIR/$name.status $guest_status_file" "$image" >/dev/null
    guest_status="$(tr -d '\r\n' < "$guest_status_file")"
    [[ "$guest_status" =~ ^[0-9]+$ ]] || { echo "oxide-conformance: invalid guest status for $name" >&2; exit 1; }
    if cmp -s "$expected_out" "$guest_out" && cmp -s "$expected_err" "$guest_err" && [ "$expected_status" -eq "$guest_status" ]; then
        match=true
    else
        match=false
    fi
    expected_out_b64="$(frame_b64 "$expected_out")"
    expected_err_b64="$(frame_b64 "$expected_err")"
    guest_out_b64="$(frame_b64 "$guest_out")"
    guest_err_b64="$(frame_b64 "$guest_err")"
    if [ "$output_policy" = differential ]; then
        printf '{"schema":1,"arch":"%s","probe":"%s","rows":"%s","syscalls":"%s","families":"%s","states":"%s","output_policy":"%s","result_transport":"serial-disk","host":{"exit":%s,"stdout_b64":"%s","stderr_b64":"%s"},"guest":{"exit":%s,"stdout_b64":"%s","stderr_b64":"%s"},"match":%s}\n' \
            "$ARCH" "$name" "$rows" "$syscalls" "$families" "$states" "$output_policy" \
            "$expected_status" "$expected_out_b64" "$expected_err_b64" \
            "$guest_status" "$guest_out_b64" "$guest_err_b64" "$match" > "$FRAME_DIR/$name.json"
    else
        printf '{"schema":1,"arch":"%s","probe":"%s","rows":"%s","syscalls":"%s","families":"%s","states":"%s","output_policy":"%s","result_transport":"serial-disk","host":null,"guest":{"exit":%s,"stdout_b64":"%s","stderr_b64":"%s"},"match":%s}\n' \
            "$ARCH" "$name" "$rows" "$syscalls" "$families" "$states" "$output_policy" \
            "$guest_status" "$guest_out_b64" "$guest_err_b64" "$match" > "$FRAME_DIR/$name.json"
    fi
    if [ "$match" != true ]; then
        echo "oxide-conformance: FAIL $name (result mismatch)" >&2
        printf 'host exit: %s\nguest exit: %s\n' "$expected_status" "$guest_status" >&2
        printf 'host stdout:\n' >&2; cat "$expected_out" >&2
        printf 'guest stdout:\n' >&2; cat "$guest_out" >&2
        printf 'host stderr:\n' >&2; cat "$expected_err" >&2
        printf 'guest stderr:\n' >&2; cat "$guest_err" >&2
        exit 1
    fi
    rm -f "$expected_out" "$expected_err" "$guest_out" "$guest_err" "$guest_status_file"
    echo "oxide-conformance: PASS $name frame=$FRAME_DIR/$name.json"
done
TERMINAL=true
write_harness true 0
echo "oxide-conformance: PASS arch=$ARCH tests=$TESTS frames=$FRAME_DIR transport=serial-disk"
