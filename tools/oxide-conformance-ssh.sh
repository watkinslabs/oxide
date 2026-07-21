#!/usr/bin/env bash
# Run selected glibc conformance artifacts inside an Oxide QEMU guest.
# Requires sshpass, debugfs, and a packed glibc image from ../images.
set -euo pipefail

ARCH="${1:-x86_64}"
TESTS="${2:-t_mmsg}"
QEMU_TIMEOUT_DEFAULT=180
QEMU_TIMEOUT_MAX=180
TIMEOUT="${3:-$QEMU_TIMEOUT_DEFAULT}"
GUEST_USER="${OXIDE_CONFORMANCE_USER:-oxide}"
GUEST_HOME="/home/$GUEST_USER"
case "$ARCH" in
    x86_64) QEMU_ARCH=x86_64; GUEST_TRIPLE=x86_64-unknown-linux-gnu ;;
    aarch64) QEMU_ARCH=aarch64; GUEST_TRIPLE=aarch64-unknown-linux-gnu ;;
    *) echo "usage: $0 <x86_64|aarch64> <test[,test...]> [timeout]" >&2; exit 2 ;;
esac
if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || [ "$TIMEOUT" -eq 0 ] || [ "$TIMEOUT" -gt "$QEMU_TIMEOUT_MAX" ]; then
    echo "oxide-conformance: timeout must be 1..$QEMU_TIMEOUT_MAX seconds" >&2
    exit 2
fi

RUN_LABEL="${OXIDE_CONFORMANCE_RUN_ID:-conformance-${ARCH}}"
case "$RUN_LABEL" in
    ''|.|..|*[!A-Za-z0-9._-]*)
        echo "oxide-conformance: run label must use [A-Za-z0-9._-], not . or .." >&2
        exit 2
        ;;
esac
# A caller-provided label identifies a result family; it must not identify a
# live VM. Reserve a distinct build namespace before any artifacts exist so a
# stale watchdog can never resolve a later invocation's QEMU pidfile.
mkdir -p target/builds
BUILD_DIR="$(mktemp -d "target/builds/${RUN_LABEL}.XXXXXX")"
ID="${BUILD_DIR##*/}"
PORT="${OXIDE_QEMU_SSH_PORT:-$((20000 + ($$ % 20000)))}"
# Default to the retained executable-scoped SSH trace. Unlike xtask's
# implicit debug-boot default, it keeps the bounded conformance boot free of
# global serial logging while preserving a diagnostic route if SSH regresses.
QEMU_FEATURES="${OXIDE_QEMU_FEATURES-debug-sshd}"
MANIFEST="tools/network-conformance-manifest.tsv"
FRAME_DIR="target/network-conformance/$ID"
mkdir -p "$FRAME_DIR"
LOG="$(mktemp /tmp/oxide-conformance-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-conformance-XXXXXX.pid)"
QEMU_PIDFILE="target/builds/$ID/qemu-$QEMU_ARCH.pid"
KNOWN="$(mktemp /tmp/oxide-conformance-known-XXXXXX)"
CLIENT_KEY="$(mktemp /tmp/oxide-conformance-client-key-XXXXXX)"
rm -f "$CLIENT_KEY"
ZRAM_SERVICE=""
ZRAM_TARGET=""
QEMU_WATCHDOG=""
READINESS_POLL_SECONDS=1
LOG_TAIL_LINES=80
PHASE="init"
QEMU_STARTED=false
TERMINAL_RECORDED=false
HARNESS_CAUSE=null
HARNESS_DEBUG="$FRAME_DIR/harness-debug.log"
debug() {
    [ -z "${OXIDE_CONFORMANCE_DEBUG:-}" ] || {
        printf 'oxide-conformance: debug: %s\n' "$*" | tee -a "$HARNESS_DEBUG" >&2
    }
}
write_harness() {
    local terminal="$1" status="$2" signal="$3" tmp
    tmp="$(mktemp "$FRAME_DIR/.harness.XXXXXX")"
    printf '{"schema":1,"kind":"harness","phase":"%s","terminal":%s,"exit":%s,"signal":%s,"cause":%s,"qemu_started":%s}\n' \
        "$PHASE" "$terminal" "$status" "$signal" "$HARNESS_CAUSE" "$QEMU_STARTED" > "$tmp"
    mv -f "$tmp" "$FRAME_DIR/harness.json"
}
begin_preqemu_phase() {
    PHASE="$1"
    write_harness false 0 null
    debug "phase=$PHASE qemu_started=$QEMU_STARTED"
}
record_terminal() {
    local status="$1" signal="$2"
    [ "$TERMINAL_RECORDED" = true ] && return
    TERMINAL_RECORDED=true
    write_harness true "$status" "$signal"
    debug "terminal phase=$PHASE exit=$status signal=$signal qemu_started=$QEMU_STARTED"
}
on_err() {
    local status="$1"
    record_terminal "$status" null
    exit "$status"
}
on_signal() {
    local signal="$1" status
    case "$signal" in TERM) status=143 ;; INT) status=130 ;; *) status=1 ;; esac
    record_terminal "$status" "\"$signal\""
    exit "$status"
}
stop_qemu() {
    local qpid
    qpid="$(cat "$QEMU_PIDFILE" 2>/dev/null || true)"
    case "$qpid" in *[!0-9]*|'') return ;; esac
    qemu_owned "$qpid" || return
    kill -TERM "$qpid" 2>/dev/null || true
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
launcher_owned() {
    local pid="$1" start="$2" now
    [[ "$pid" =~ ^[0-9]+$ && "$start" =~ ^[0-9]+$ ]] || return 1
    [ -r "/proc/$pid/stat" ] || return 1
    now="$(awk '{print $22}' "/proc/$pid/stat")"
    [ "$now" = "$start" ]
}
launcher_stop() {
    local pid start
    read -r pid start < "$PIDFILE" 2>/dev/null || return
    launcher_owned "$pid" "$start" || return
    kill -TERM "$pid" 2>/dev/null || true
}
launcher_alive() {
    local pid start
    read -r pid start < "$PIDFILE" 2>/dev/null || return 1
    launcher_owned "$pid" "$start"
}
qemu_alive() {
    local qpid
    qpid="$(cat "$QEMU_PIDFILE" 2>/dev/null || true)"
    case "$qpid" in *[!0-9]*|'') return 1 ;; esac
    qemu_owned "$qpid"
}
require_runner_liveness() {
    local gate="$1"
    if launcher_alive; then return 0; fi
    if qemu_alive; then return 0; fi
    HARNESS_CAUSE="\"$gate readiness: launcher and QEMU exited\""
    echo "oxide-conformance: $gate readiness failed: launcher and QEMU exited" >&2
    tail -n "$LOG_TAIL_LINES" "$LOG" >&2
    return 1
}
cleanup() {
    cleanup_status=$?
    record_terminal "$cleanup_status" null
    debug "cleanup status=$cleanup_status"
    stop_qemu
    launcher_stop
    [ -z "$QEMU_WATCHDOG" ] || kill -TERM "$QEMU_WATCHDOG" 2>/dev/null || true
    if [ -n "${OXIDE_CONFORMANCE_DEBUG:-}" ]; then
        debug "retained serial log=$LOG"
    else
        rm -f "$LOG"
    fi
rm -f "$PIDFILE" "$KNOWN" "$CLIENT_KEY" "${CLIENT_KEY}.pub"
rm -rf "${KEYDIR:-}"
rm -f "${SSHD_DROPIN:-}" "${SSHD_CONFIG:-}" "${PASSWD_TMP:-}" "$ZRAM_SERVICE" "$ZRAM_TARGET"
}
trap 'on_err $?' ERR
trap 'on_signal TERM' TERM
trap 'on_signal INT' INT
trap cleanup EXIT

test -f "$MANIFEST" || { echo "oxide-conformance: missing $MANIFEST" >&2; exit 2; }

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
    [ "$encoded" = "-" ] && return 0
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

frame_b64() {
    base64 -w 0 "$1"
}

echo "oxide-conformance: prepare arch=$ARCH tests=$TESTS id=$ID"
begin_preqemu_phase rootfs
cargo run -q -p xtask -- rootfs --arch "$QEMU_ARCH" --id "$ID"
# The disposable conformance image validates a userspace component, not the
# graphical session. Keep systemd, zram-generator, swap activation, sshd and
# the normal multi-user dependency graph, while avoiding unrelated GNOME
# services that consume the bounded QEMU test budget.
begin_preqemu_phase target-select
debugfs -w -R 'rm /etc/systemd/system/default.target' \
    "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null
debugfs -w -R 'symlink /etc/systemd/system/default.target /usr/lib/systemd/system/multi-user.target' \
    "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null
# The target frame is meaningful only when the selected host oracle completed.
# Do not inject or boot an artifact after a host check failure: doing so would
# retain a guest result without the Linux control required by N22.
begin_preqemu_phase host-oracle
cargo run -q -p xtask -- glibc-test --arch "$ARCH" --tests "$TESTS" --inject "$TESTS" --id "$ID"

# The lifecycle corpus needs root and its exact target-only contract is more
# directly validated as a systemd oneshot than through an SSH transport. Boot
# an isolated target in the disposable image: the normal multi-user graph can
# wait indefinitely on unrelated host-facing services, while the kernel has
# already mounted /dev, /proc and /sys before PID 1 starts this target.
if [ "$TESTS" = t_zram_lifecycle ]; then
    begin_preqemu_phase zram-target
    ZRAM_SERVICE="$(mktemp /tmp/oxide-conformance-zram-service-XXXXXX)"
    ZRAM_TARGET="$(mktemp /tmp/oxide-conformance-zram-target-XXXXXX)"
    printf '%s\n' \
        '[Unit]' \
        'Description=Oxide ZRAM lifecycle conformance' \
        'DefaultDependencies=no' \
        'Before=shutdown.target' \
        'Conflicts=shutdown.target' \
        '[Service]' \
        'Type=oneshot' \
        'ExecStart=/usr/local/bin/oxide-conformance-t_zram_lifecycle --live' \
        > "$ZRAM_SERVICE"
    printf '%s\n' \
        '[Unit]' \
        'Description=Oxide ZRAM lifecycle conformance target' \
        'DefaultDependencies=no' \
        'Wants=oxide-conformance-zram.service' \
        'After=oxide-conformance-zram.service' \
        > "$ZRAM_TARGET"
    debugfs -w -R 'rm /etc/systemd/system/oxide-conformance-zram.service' \
        "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null 2>&1 || true
    debugfs -w -R "write $ZRAM_SERVICE /etc/systemd/system/oxide-conformance-zram.service" \
        "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null
    debugfs -w -R 'rm /etc/systemd/system/oxide-conformance-zram.target' \
        "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null 2>&1 || true
    debugfs -w -R "write $ZRAM_TARGET /etc/systemd/system/oxide-conformance-zram.target" \
        "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null
    debugfs -w -R 'rm /etc/systemd/system/default.target' \
        "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null
    debugfs -w -R 'symlink /etc/systemd/system/default.target oxide-conformance-zram.target' \
        "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null
fi

# The ZRAM lifecycle probe requires root and has exact target-only output.
# The copied image is disposable; provide host keys up front so sshd does not
# depend on the guest key-generation units, which are outside this test's ABI.
begin_preqemu_phase ssh-credentials
KEYDIR="$(mktemp -d /tmp/oxide-conformance-keys-XXXXXX)"
SSHD_DROPIN="$(mktemp /tmp/oxide-conformance-sshd-XXXXXX.conf)"
SSHD_CONFIG="$(mktemp /tmp/oxide-conformance-sshd-config-XXXXXX.conf)"
PASSWD_TMP="$(mktemp /tmp/oxide-conformance-passwd-XXXXXX)"
AUTH_KEY_PATH=/etc/ssh/oxide-conformance-authorized_keys
printf '%s\n' '[Service]' 'ExecStartPre=/usr/bin/mkdir -p /run/sshd' > "$SSHD_DROPIN"
printf '%s\n' "AuthorizedKeysFile $AUTH_KEY_PATH" 'PermitRootLogin yes' > "$SSHD_CONFIG"
debugfs -w -R 'mkdir /etc/systemd/system/sshd.service.d' \
    "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null
debugfs -w -R 'rm /etc/systemd/system/sshd.service.d/conformance.conf' \
    "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null 2>&1 || true
debugfs -w -R "write $SSHD_DROPIN /etc/systemd/system/sshd.service.d/conformance.conf" \
    "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null
debugfs -w -R 'mkdir /etc/ssh/sshd_config.d' \
    "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null 2>&1 || true
debugfs -w -R 'rm /etc/ssh/sshd_config.d/conformance.conf' \
    "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null 2>&1 || true
debugfs -w -R "write $SSHD_CONFIG /etc/ssh/sshd_config.d/conformance.conf" \
    "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null
for spec in "rsa 2048" "ecdsa 256" "ed25519"; do
    set -- $spec
    if [ "$1" = ed25519 ]; then
        ssh-keygen -q -t ed25519 -N '' -f "$KEYDIR/ssh_host_ed25519_key"
    else
        ssh-keygen -q -t "$1" -b "$2" -N '' -f "$KEYDIR/ssh_host_${1}_key"
    fi
    debugfs -w -R "rm /etc/ssh/ssh_host_${1}_key" \
        "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null 2>&1 || true
    debugfs -w -R "rm /etc/ssh/ssh_host_${1}_key.pub" \
        "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null 2>&1 || true
    debugfs -w -R "write $KEYDIR/ssh_host_${1}_key /etc/ssh/ssh_host_${1}_key" \
        "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null
    debugfs -w -R "write $KEYDIR/ssh_host_${1}_key.pub /etc/ssh/ssh_host_${1}_key.pub" \
        "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null
    debugfs -w -R "sif /etc/ssh/ssh_host_${1}_key mode 0100600" \
        "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null
done
ssh-keygen -q -t ed25519 -N '' -f "$CLIENT_KEY"
install_client_key() {
    local image="$1" image_home="$2"
    debugfs -w -R "mkdir $image_home" "$image" >/dev/null 2>&1 || true
    debugfs -w -R "sif $image_home uid 1000" "$image" >/dev/null
    debugfs -w -R "sif $image_home gid 1000" "$image" >/dev/null
    debugfs -w -R "sif $image_home mode 040755" "$image" >/dev/null
    debugfs -w -R "mkdir $image_home/.ssh" "$image" >/dev/null 2>&1 || true
    debugfs -w -R "write ${CLIENT_KEY}.pub $image_home/.ssh/authorized_keys" "$image" >/dev/null
    debugfs -w -R "sif $image_home/.ssh uid 1000" "$image" >/dev/null
    debugfs -w -R "sif $image_home/.ssh gid 1000" "$image" >/dev/null
    debugfs -w -R "sif $image_home/.ssh mode 040700" "$image" >/dev/null
    debugfs -w -R "sif $image_home/.ssh/authorized_keys uid 1000" "$image" >/dev/null
    debugfs -w -R "sif $image_home/.ssh/authorized_keys gid 1000" "$image" >/dev/null
    debugfs -w -R "sif $image_home/.ssh/authorized_keys mode 0100600" "$image" >/dev/null
}
install_client_key "target/builds/$ID/root-$QEMU_ARCH.img" "$GUEST_HOME"
# The home disk is mounted on /home, so its on-disk /oxide is /home/oxide.
install_client_key "target/builds/$ID/home-$QEMU_ARCH.img" "/$GUEST_USER"
debugfs -w -R "write ${CLIENT_KEY}.pub $AUTH_KEY_PATH" \
    "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null
debugfs -w -R "sif $AUTH_KEY_PATH mode 0100644" \
    "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null
debugfs -R 'dump /etc/passwd /tmp/oxide-conformance-passwd-dump' \
    "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null
awk -F: -v OFS=: -v user="$GUEST_USER" '$1 == user { $6 = "/" } 1' \
    /tmp/oxide-conformance-passwd-dump > "$PASSWD_TMP"
debugfs -w -R 'rm /etc/passwd' \
    "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null
debugfs -w -R "write $PASSWD_TMP /etc/passwd" \
    "target/builds/$ID/root-$QEMU_ARCH.img" >/dev/null
rm -f /tmp/oxide-conformance-passwd-dump

# Build the kernel and namespaced ISO before the bounded QEMU interval. The
# subsequent `--run-existing` launch consumes only the caller's guest budget.
begin_preqemu_phase image
image_args=(run -q -p xtask -- image --arch "$QEMU_ARCH" --id "$ID")
if [ -n "$QEMU_FEATURES" ]; then image_args+=(--features "$QEMU_FEATURES"); fi
OXIDE_SKIP_ROOTFS=1 cargo "${image_args[@]}"

OXIDE_SKIP_ROOTFS=1 OXIDE_QEMU_HEADLESS=1 OXIDE_QEMU_SSH_FWD=1 OXIDE_QEMU_SSH_PORT="$PORT" \
    setsid bash -c "exec cargo run -q -p xtask -- grub --arch $QEMU_ARCH --id $ID --run-existing > '$LOG' 2>&1 < /dev/null" &
QEMU_STARTED=true
PHASE=qemu
write_harness false 0 null
launcher_pid=$!
launcher_start="$(awk '{print $22}' "/proc/$launcher_pid/stat" 2>/dev/null || true)"
printf '%s %s\n' "$launcher_pid" "$launcher_start" > "$PIDFILE"
debug "qemu launch pid=$(cat "$PIDFILE") port=$PORT log=$LOG"
deadline=$(( $(date +%s) + TIMEOUT ))
# The shell-level readiness loops are allowed to fail independently, but the
# VM itself must never outlive the caller's explicit QEMU budget. xtask can
# detach QEMU from cargo's process group, so the watchdog also resolves the
# VM by this run's unique build directory.
(
    sleep "$TIMEOUT"
    stop_qemu
    launcher_stop
) &
QEMU_WATCHDOG=$!
if [ "$TESTS" = t_zram_lifecycle ]; then
    while [ "$(date +%s)" -lt "$deadline" ]; do
        grep -q 'oxide-conformance-zram.service: Deactivated successfully' "$LOG" 2>/dev/null && break
        require_runner_liveness ZRAM || exit 1
        sleep "$READINESS_POLL_SECONDS"
    done
    if ! grep -q 'oxide-conformance-zram.service: Deactivated successfully' "$LOG" 2>/dev/null; then
        echo "oxide-conformance: ZRAM lifecycle timeout" >&2; tail -n "$LOG_TAIL_LINES" "$LOG" >&2; exit 1
    fi
    stop_qemu
    sleep 1
    # The isolated target has no journald socket, so systemd's normal stdout
    # transport is intentionally unavailable. `Deactivated successfully` is
    # systemd's exact report that ExecStart exited zero. The program reaches
    # that exit only after every lifecycle assertion and its checked puts(3)
    # of the manifest's exact PASS string; record the actual transport rather
    # than fabricating captured stdout.
    printf '{"schema":1,"arch":"%s","probe":"t_zram_lifecycle","output_policy":"target-pass-exact","guest":{"exit":0,"stdout_b64":null,"result_transport":"systemd-oneshot-exit"},"match":true}\n' \
        "$ARCH" > "$FRAME_DIR/t_zram_lifecycle.json"
    echo "oxide-conformance: PASS t_zram_lifecycle frame=$FRAME_DIR/t_zram_lifecycle.json"
    exit 0
fi
ssh_ready() {
    ssh-keyscan -T 1 -p "$PORT" 127.0.0.1 >/dev/null 2>/dev/null
}
while [ "$(date +%s)" -lt "$deadline" ]; do
    ssh_ready && break
    require_runner_liveness SSH || exit 1
    sleep "$READINESS_POLL_SECONDS"
done
if ! ssh_ready; then
    echo "oxide-conformance: SSH timeout" >&2; tail -n "$LOG_TAIL_LINES" "$LOG" >&2; exit 1
fi
debug "ssh ready port=$PORT"

ssh_opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile="$KNOWN" -o GlobalKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 -p "$PORT")
for name in ${TESTS//,/ }; do
    meta="$(probe_meta "$name")" || { echo "oxide-conformance: probe $name absent from $MANIFEST" >&2; exit 2; }
    rows="$(printf '%s\n' "$meta" | awk -F '\t' '{ if (NR > 1) printf ","; printf $1 }')"
    syscalls="$(printf '%s\n' "$meta" | awk -F '\t' '{ if (NR > 1) printf ","; printf $2 }')"
    families="$(printf '%s\n' "$meta" | awk -F '\t' '{ if (NR > 1) printf ";"; printf $3 }')"
    states="$(printf '%s\n' "$meta" | awk -F '\t' '{ if (NR > 1) printf ","; printf $4 }')"
    contract="$(printf '%s\n' "$meta" | probe_contract)" || {
        echo "oxide-conformance: probe $name has no uniform execution contract" >&2
        exit 2
    }
    IFS=$'\t' read -r argv_spec probe_uid output_policy expected_stdout <<< "$contract"
    parse_probe_argv "$argv_spec" || { echo "oxide-conformance: invalid argv contract for $name" >&2; exit 2; }
    remote_command="$(guest_command "$probe_uid" "/usr/local/bin/oxide-conformance-$name")" || {
        echo "oxide-conformance: invalid uid contract for $name" >&2
        exit 2
    }
    case "$output_policy" in
        differential|target-pass-exact) ;;
        *) echo "oxide-conformance: invalid output policy for $name" >&2; exit 2 ;;
    esac
    if [ "$output_policy" = differential ] && [ "$expected_stdout" != - ]; then
        echo "oxide-conformance: differential probe $name must not declare target stdout" >&2
        exit 2
    fi
    if [ "$output_policy" = target-pass-exact ] && [ "$expected_stdout" = - ]; then
        echo "oxide-conformance: target-pass probe $name needs expected stdout" >&2
        exit 2
    fi
    debug "probe=$name argv=$argv_spec uid=$probe_uid policy=$output_policy"
    host="target/glibc-conf/${name}.host"
    expected_out="$(mktemp /tmp/oxide-conformance-host-out-XXXXXX)"
    expected_err="$(mktemp /tmp/oxide-conformance-host-err-XXXXXX)"
    guest_out="$(mktemp /tmp/oxide-conformance-guest-out-XXXXXX)"
    guest_err="$(mktemp /tmp/oxide-conformance-guest-err-XXXXXX)"
    set +e
    if [ "$output_policy" = differential ]; then
        env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC HOME=/ "$host" "${PROBE_ARGV[@]}" >"$expected_out" 2>"$expected_err"
        expected_status=$?
    else
        printf '%s\n' "$expected_stdout" >"$expected_out"
        : > "$expected_err"
        expected_status=0
    fi
    remaining=$(( deadline - $(date +%s) ))
    if [ "$remaining" -le 0 ]; then
        echo "oxide-conformance: guest execution budget exhausted" >&2
        exit 1
    fi
    timeout "$remaining" ssh -i "$CLIENT_KEY" "${ssh_opts[@]}" root@127.0.0.1 \
        "$remote_command" >"$guest_out" 2>"$guest_err"
    guest_status=$?
    debug "probe=$name guest_status=$guest_status"
    set -e
    host_out_b64="$(frame_b64 "$expected_out")"
    host_err_b64="$(frame_b64 "$expected_err")"
    guest_out_b64="$(frame_b64 "$guest_out")"
    guest_err_b64="$(frame_b64 "$guest_err")"
    if cmp -s "$expected_out" "$guest_out" && cmp -s "$expected_err" "$guest_err" && [ "$expected_status" -eq "$guest_status" ]; then match=true; else match=false; fi
    if [ "$output_policy" = differential ]; then
        printf '{"schema":1,"arch":"%s","probe":"%s","rows":"%s","syscalls":"%s","families":"%s","states":"%s","host":{"exit":%s,"stdout_b64":"%s","stderr_b64":"%s"},"guest":{"exit":%s,"stdout_b64":"%s","stderr_b64":"%s"},"match":%s}\n' \
            "$ARCH" "$name" "$rows" "$syscalls" "$families" "$states" "$expected_status" "$host_out_b64" "$host_err_b64" "$guest_status" "$guest_out_b64" "$guest_err_b64" "$match" \
            > "$FRAME_DIR/${name}.json"
    else
        printf '{"schema":1,"arch":"%s","probe":"%s","rows":"%s","syscalls":"%s","families":"%s","states":"%s","output_policy":"%s","host":null,"guest":{"exit":%s,"stdout_b64":"%s","stderr_b64":"%s"},"match":%s}\n' \
            "$ARCH" "$name" "$rows" "$syscalls" "$families" "$states" "$output_policy" "$guest_status" "$guest_out_b64" "$guest_err_b64" "$match" \
            > "$FRAME_DIR/${name}.json"
    fi
    if [ "$guest_status" -eq 124 ]; then
        echo "oxide-conformance: FAIL $name (guest execution)" >&2
        echo "oxide-conformance: guest stderr:" >&2
        cat "$guest_err" >&2
        tail -n "$LOG_TAIL_LINES" "$LOG" >&2
        exit 1
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
    rm -f "$expected_out" "$expected_err" "$guest_out" "$guest_err"
    echo "oxide-conformance: PASS $name frame=$FRAME_DIR/$name.json"
done
echo "oxide-conformance: PASS arch=$ARCH tests=$TESTS frames=$FRAME_DIR"
