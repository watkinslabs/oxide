#!/usr/bin/env bash
# Post-login filesystem sweep. Reuses the B18 console-login path,
# then drives the bash shell through a curated ls/cat/readlink
# sweep of /proc, /dev, /sys in lockstep: one command at a time,
# each followed by `echo ===DONE_<tag>===`. The harness waits for
# that exact marker before sending the next command, so any hang
# pinpoints the offending path.
#
# The raw qemu serial log is left at /tmp/oxide-fs-smoke-<arch>-*.log
# for post-run inspection.
#
# Usage:
#   tools/boot-smoke-fs.sh x86 [timeout_seconds]   # default 600
#   tools/boot-smoke-fs.sh arm [timeout_seconds]
set -uo pipefail

usage() {
    cat >&2 <<EOF
usage: $0 <x86|arm> [timeout_seconds]
EOF
    exit 2
}

ARCH="${1:-}"
case "$ARCH" in
    x86) MAKE_TARGET=qemu-x86 ;;
    arm) MAKE_TARGET=qemu-arm ;;
    *)   usage ;;
esac
TIMEOUT="${2:-${SMOKE_TIMEOUT:-600}}"

LOG="$(mktemp /tmp/oxide-fs-smoke-${ARCH}-XXXXXX.log)"
PIDFILE="$(mktemp /tmp/oxide-fs-smoke-${ARCH}-XXXXXX.pid)"
QIN="$(mktemp -u /tmp/oxide-fs-smoke-${ARCH}-qin-XXXXXX)"
mkfifo "$QIN"
cleanup() {
    if [ -s "$PIDFILE" ]; then
        local pid
        pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "-$pid" 2>/dev/null || true
            sleep 1
            kill -KILL "-$pid" 2>/dev/null || true
        fi
    fi
    rm -f "$PIDFILE" "$QIN"
    # $LOG is preserved for inspection
}
trap cleanup EXIT

echo "boot-smoke-fs: arch=$ARCH timeout=${TIMEOUT}s log=$LOG"

exec 9<>"$QIN"

OXIDE_QEMU_HEADLESS=1 setsid bash -c "exec make '$MAKE_TARGET' > '$LOG' 2>&1 < '$QIN'" &
echo $! > "$PIDFILE"

deadline=$(( $(date +%s) + TIMEOUT ))

wait_for() {
    local pat="$1" label="$2"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local pid
        pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "boot-smoke-fs: FAIL — qemu exited before $label" >&2
            tail -n 80 "$LOG" >&2
            exit 1
        fi
        if grep -aq "$pat" "$LOG" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    echo "boot-smoke-fs: FAIL — timeout waiting for $label" >&2
    tail -n 120 "$LOG" >&2
    exit 1
}

# Each step is one shell command + own DONE marker. PASS = every
# marker observed in order. FAIL = a step's marker never arrives →
# that path wedges.
TAGS=()
step() {
    local tag="$1" cmd="$2"
    TAGS+=("$tag")
    printf '%s; echo ===DONE_%s===\n' "$cmd" "$tag" >&9
    wait_for "===DONE_${tag}===" "$tag"
}

wait_for "oxide login:" "login prompt"
sleep 1
printf 'alice\n'     >&9
sleep 2
printf 'swordfish\n' >&9
wait_for 'oxide:~\$' "shell prompt"
sleep 1

# /proc — system-wide files
step proc_cmdline     'cat /proc/cmdline'
step proc_version     'cat /proc/version'
step proc_uptime      'cat /proc/uptime'
step proc_meminfo     'cat /proc/meminfo | head -10'
step proc_cpuinfo     'cat /proc/cpuinfo | head -20'
step proc_stat        'cat /proc/stat | head -10'
step proc_mounts      'cat /proc/mounts'
step proc_filesystems 'cat /proc/filesystems'

# /proc/self
step proc_self_status 'cat /proc/self/status | head -20'
step proc_self_maps   'cat /proc/self/maps | head -20'
step proc_self_comm   'cat /proc/self/comm'
step proc_self_cgroup 'cat /proc/self/cgroup'
step proc_self_fd_ls  'ls -la /proc/self/fd/'
step proc_self_fd_ls2 'ls -la /proc/self/fd'
step proc_self_fd_st  'stat /proc/self/fd'
step proc_self_ls     'ls -la /proc/self'
step proc_self_exe    'readlink /proc/self/exe'
step proc_self_cwd    'readlink /proc/self/cwd'
step proc_self_root   'readlink /proc/self/root'
step proc_self_fd0    'readlink /proc/self/fd/0'
step proc_self_fd1    'readlink /proc/self/fd/1'
step proc_self_fd2    'readlink /proc/self/fd/2'
step proc_self_fdinfo_ls 'ls /proc/self/fdinfo'
step proc_self_fdinfo_0  'cat /proc/self/fdinfo/0'

# /proc/1 (init)
step proc_1_comm      'cat /proc/1/comm'

# /dev
step dev_ls           'ls -la /dev'
step dev_stdin        'readlink /dev/stdin'
step dev_stdout       'readlink /dev/stdout'
step dev_stderr       'readlink /dev/stderr'
step dev_fd           'readlink /dev/fd'
step dev_stdout_write 'echo hello-from-dev-stdout > /dev/stdout'
step dev_shm_ls       'ls -la /dev/shm 2>&1'
step dev_shm_write    'echo shm-roundtrip > /dev/shm/probe'
step dev_shm_read     'cat /dev/shm/probe'
step dev_shm_stat     'stat -c %F:%s /dev/shm/probe'
step dev_shm_statfs   'stat -f -c %T /dev/shm'

# /sys
step sys_ls           'ls -la /sys 2>&1 | head -20'
step sys_class_ls     'ls /sys/class 2>&1 | head -20'
step sys_class_net    'ls /sys/class/net 2>&1'
step sys_lo_attrs     'ls /sys/class/net/lo 2>&1'
step sys_lo_addr      'cat /sys/class/net/lo/address'
step sys_lo_mtu       'cat /sys/class/net/lo/mtu'
step sys_lo_type      'cat /sys/class/net/lo/type'
step sys_lo_operstate 'cat /sys/class/net/lo/operstate'
step sys_lo_flags     'cat /sys/class/net/lo/flags'
step sys_cpu_ls       'ls /sys/devices/system/cpu 2>&1 | head -20'
step sys_cpu_online   'cat /sys/devices/system/cpu/online'
step sys_cpu_possible 'cat /sys/devices/system/cpu/possible'
step sys_cpu_present  'cat /sys/devices/system/cpu/present'
step sys_cpu_offline  'cat /sys/devices/system/cpu/offline'
step sys_lo_readlink  'readlink /sys/class/net/lo'
step sys_dev_lo_addr  'cat /sys/devices/virtual/net/lo/address'
step sys_lo_addr_thru 'cat /sys/class/net/lo/address  # via symlink follow'

# /proc/net
step proc_net_tcp     'cat /proc/net/tcp'
step proc_net_udp     'cat /proc/net/udp'
step proc_net_unix    'cat /proc/net/unix'
step proc_net_route   'cat /proc/net/route'

# Cross-checks
step df_all           'df'
step mount_all        'mount'
step stat_roots       'stat /proc /dev /sys /'

step sweep_done       'echo all-fs-paths-clean'

elapsed=$(( $(date +%s) - (deadline - TIMEOUT) ))
echo "boot-smoke-fs: PASS — $ARCH /proc /dev /sys sweep (${#TAGS[@]} steps) in ${elapsed}s"
exit 0
