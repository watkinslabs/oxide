#!/usr/bin/env python3
"""Exercise Firefox DNS failure handling on the graphical console.

The UART is only a control and diagnostic channel.  Browser progress is
observed from QEMU's graphical scanout through QMP screenshots; a quiet UART
is normal and is never treated as evidence that the graphical session hung.

Usage: tools/guest-firefox-check.py [boot_timeout_s]
"""
import hashlib
import json
import os
import re
import select
import signal
import socket
import subprocess
import sys
import time


BOOT_TIMEOUT = int(sys.argv[1]) if len(sys.argv) > 1 else 600
COMMAND_TIMEOUT = 35
RUN_ID = f"{os.getpid()}"
UART_SOCK = f"/tmp/oxide-firefox-uart-{RUN_ID}.sock"
QMP_SOCK = f"/tmp/oxide-firefox-qmp-{RUN_ID}.sock"
UART_LOG = f"/tmp/oxide-firefox-uart-{RUN_ID}.log"
QEMU_LOG = f"/tmp/oxide-firefox-qemu-{RUN_ID}.log"
SCREEN_PREFIX = f"/tmp/oxide-firefox-{RUN_ID}"
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
KERNEL_FAULT = re.compile(
    r"\[BUG\] scheduling while atomic|IRQ stack guard page|\[BADSTACK\]|#DF|Kernel panic"
)
KERNEL_STALL = re.compile(r"\[WATCHDOG\] (?:soft lockup|no-progress)|\[CPU-STALL\]")
STORAGE_ERROR = re.compile(
    r"\[EXT4-ERROR\]|\[NAMEI\] (?:openat-create|mkdir(?:at)?) .*err=5"
)
FIREFOX_ENV = (
    "HOME=/home/oxide XDG_RUNTIME_DIR=/run/user/1000 "
    "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus "
    "WAYLAND_DISPLAY=wayland-0 MOZ_ENABLE_WAYLAND=1"
)
PROFILE = os.environ.get("OXIDE_FIREFOX_PROFILE") == "1"
PROFILE_LOG = f"/tmp/oxide-firefox-profile-{RUN_ID}.txt"


env = dict(
    os.environ,
    OXIDE_QEMU_UART_SOCK=UART_SOCK,
    OXIDE_QEMU_QMP_SOCK=QMP_SOCK,
    OXIDE_QEMU_HEADLESS="1",
)
uart_log = open(UART_LOG, "wb", buffering=0)
qemu_log = open(QEMU_LOG, "wb")
print(
    f"guest-firefox-check: uart={UART_SOCK} qmp={QMP_SOCK} "
    f"uart_log={UART_LOG} qemu_log={QEMU_LOG}",
    flush=True,
)
qemu = subprocess.Popen(
    ["make", "qemu-x86"], env=env, stdout=qemu_log, stderr=subprocess.STDOUT,
    stdin=subprocess.DEVNULL, start_new_session=True,
)


def pump(conn, buf, seconds):
    deadline = time.time() + seconds
    while time.time() < deadline:
        ready, _, _ = select.select([conn], [], [], min(0.5, deadline - time.time()))
        if not ready:
            continue
        chunk = conn.recv(65536)
        if not chunk:
            return False
        buf.extend(chunk)
        uart_log.write(chunk)
    return True


def run(conn, buf, command, settle=COMMAND_TIMEOUT):
    """Run a debug-shell command and return bytes following its submission."""
    start = len(buf)
    conn.sendall(("\n" + command + "; printf 'OXIDE-RC-%d\\n' $?\n").encode())
    deadline = time.time() + settle
    while time.time() < deadline:
        output = ANSI.sub("", buf[start:].decode("utf-8", "replace"))
        if re.search(r"OXIDE-RC-[0-9]+\r?\n", output):
            return output
        if not pump(conn, buf, min(1, deadline - time.time())):
            break
    return ANSI.sub("", buf[start:].decode("utf-8", "replace"))


def rc(output, expected=0):
    return re.search(rf"OXIDE-RC-{expected}\r?\n", output) is not None


def connect_socket(path, deadline, name):
    while time.time() < deadline:
        if os.path.exists(path):
            candidate = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                candidate.connect(path)
                return candidate
            except OSError:
                candidate.close()
        if qemu.poll() is not None:
            raise RuntimeError(f"build/boot exited before the {name} appeared")
        time.sleep(1)
    raise RuntimeError(f"{name} never appeared")


def qmp_read(qmp, timeout=10):
    qmp.settimeout(timeout)
    pending = bytearray()
    while True:
        chunk = qmp.recv(8192)
        if not chunk:
            raise RuntimeError("QMP connection closed")
        pending.extend(chunk)
        while b"\n" in pending:
            pos = pending.index(b"\n")
            line = bytes(pending[:pos])
            del pending[:pos + 1]
            if not line.strip():
                continue
            obj = json.loads(line)
            if "event" not in obj:
                return obj


def qmp_command(qmp, execute, arguments=None):
    request = {"execute": execute}
    if arguments is not None:
        request["arguments"] = arguments
    qmp.sendall((json.dumps(request) + "\n").encode())
    response = qmp_read(qmp)
    if "error" in response:
        raise RuntimeError(f"QMP {execute} failed: {response['error']}")
    return response


def qmp_human(qmp, command):
    """Run one read-only HMP diagnostic through QMP."""
    return qmp_command(
        qmp,
        "human-monitor-command",
        {"command-line": command},
    ).get("return", "")


def screenshot(qmp, label):
    path = f"{SCREEN_PREFIX}-{label}.ppm"
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    qmp_command(qmp, "screendump", {"filename": path})
    deadline = time.time() + 5
    while time.time() < deadline:
        if os.path.exists(path) and os.path.getsize(path) > 16:
            with open(path, "rb") as image:
                digest = hashlib.sha256(image.read()).hexdigest()
            print(f"guest-firefox-check: {label} screen {path} sha256={digest[:16]}", flush=True)
            return digest
        time.sleep(0.05)
    raise RuntimeError(f"QMP did not produce {label} screenshot")


def screen_text(label):
    """OCR the graphical result so unrelated repainting cannot satisfy a URL check."""
    path = f"{SCREEN_PREFIX}-{label}.ppm"
    try:
        proc = subprocess.run(
            ["tesseract", path, "stdout"], stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout


def wait_for_screen(qmp, label, timeout, ready):
    """Return first OCR-confirmed graphical completion latency."""
    started = time.monotonic()
    text = ""
    while time.monotonic() - started < timeout:
        screenshot(qmp, label)
        text = screen_text(label)
        elapsed = time.monotonic() - started
        if ready(text.lower()):
            print(f"guest-firefox-check: {label} ready_s={elapsed:.3f}", flush=True)
            return elapsed, text
        time.sleep(1)
    print(f"guest-firefox-check: {label} ready_s=>{timeout}", flush=True)
    return None, text


def sample_rips(qmp, label, duration, samples):
    """Snapshot the running vCPU RIP through QMP without a GDB stop."""
    result = []
    interval = duration / samples
    for _ in range(samples):
        started = time.monotonic()
        response = qmp_command(
            qmp,
            "human-monitor-command",
            {"command-line": "info registers"},
        )
        registers = response.get("return", "")
        match = re.search(r"\bRIP=([0-9a-fA-F]+)", registers)
        if match:
            result.append((label, int(match.group(1), 16)))
        remaining = interval - (time.monotonic() - started)
        if remaining > 0:
            time.sleep(remaining)
    return result


def write_profile(samples):
    """Symbolize sampled kernel RIPs and retain per-phase distributions."""
    elf = "target/x86_64-unknown-oxide-kernel/release/oxide-x86_64"
    kernel_addresses = sorted({rip for _, rip in samples if rip >= 0xFFFF_8000_0000_0000})
    symbols = {}
    if kernel_addresses:
        proc = subprocess.run(
            ["addr2line", "-f", "-C", "-e", elf]
            + [f"0x{address:x}" for address in kernel_addresses],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )
        lines = proc.stdout.splitlines()
        for index, address in enumerate(kernel_addresses):
            symbols[address] = lines[index * 2] if index * 2 < len(lines) else "KERNEL_UNKNOWN"

    phases = sorted({label for label, _ in samples})
    with open(PROFILE_LOG, "w") as output:
        for phase in ["all"] + phases:
            selected = samples if phase == "all" else [sample for sample in samples if sample[0] == phase]
            counts = {}
            for _, rip in selected:
                name = symbols.get(rip, "USER" if rip < 0xFFFF_8000_0000_0000 else "KERNEL_UNKNOWN")
                key = (name, rip)
                counts[key] = counts.get(key, 0) + 1
            output.write(f"[{phase}] samples={len(selected)}\n")
            for (name, rip), count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:40]:
                output.write(
                    f"{count:6d} {count * 100.0 / max(len(selected), 1):6.2f}% "
                    f"0x{rip:016x} {name}\n"
                )
    print(f"guest-firefox-check: QMP RIP profile retained at {PROFILE_LOG}", flush=True)


def diagnostics(conn, buf):
    # The debug shell can itself be the blocked workload (for example, waiting
    # for the foreground runuser used to launch Firefox). Kernel SysRq is a UART
    # prefilter, so it remains available without a shell prompt: NUL arms it,
    # then t/c/w dump tasks, per-CPU scheduler state, and the current task.
    start = len(buf)
    for key in b"btcw":
        conn.sendall(b"\x00" + bytes([key]))
        pump(conn, buf, 2)
    sysrq = ANSI.sub("", buf[start:].decode("utf-8", "replace"))
    print("--- guest SysRq diagnostics ---\n" + sysrq[-24000:], flush=True)
    commands = (
        "timeout 10s ps -eo pid,ppid,stat,wchan:24,comm,args --sort=pid",
        "timeout 10s ss -tinap",
        "cat /proc/net/snmp; cat /proc/net/netstat; cat /proc/net/tcp; cat /proc/net/tcp6",
        "p=$(pgrep -u oxide -o firefox); test -n \"$p\" && for t in /proc/$p/task/*; do "
        "printf 'TASK %s ' \"${t##*/}\"; cat $t/comm $t/wchan $t/syscall; done",
        "timeout 10s systemctl --no-pager --full status systemd-resolved dbus-broker.service",
        "p=$(pidof systemd-resolved); test -n \"$p\" && { cat /proc/$p/status; cat /proc/$p/wchan; }",
        "timeout 10s journalctl -b --no-pager -n 160",
    )
    print("--- guest diagnostics ---", flush=True)
    for command in commands:
        output = run(conn, buf, command, settle=15)
        print(output[-12000:], flush=True)


uart = None
qmp = None
profile_samples = []
buf = bytearray()
ok = True
control_alive = True
try:
    deadline = time.time() + BOOT_TIMEOUT
    uart = connect_socket(UART_SOCK, deadline, "UART socket")
    qmp = connect_socket(QMP_SOCK, deadline, "QMP socket")
    qmp_read(qmp)
    qmp_command(qmp, "qmp_capabilities")

    shell_deadline = time.time() + BOOT_TIMEOUT
    while time.time() < shell_deadline:
        if rc(run(uart, buf, "true", settle=2)):
            break
    else:
        raise RuntimeError("serial debug shell did not answer")

    session = ""
    session_deadline = time.time() + BOOT_TIMEOUT
    while time.time() < session_deadline:
        session = run(
            uart,
            buf,
            "systemctl is-active graphical.target; pidof gnome-shell; "
            "test -S /run/user/1000/wayland-0",
            settle=5,
        )
        stall = KERNEL_STALL.search(buf.decode("utf-8", "replace"))
        if stall:
            raise RuntimeError(f"kernel stalled before GNOME readiness: {stall.group(0)}")
        if "active" in session and re.search(r"\r?\n[0-9]+\r?\n", session) and rc(session):
            break
        time.sleep(2)
    else:
        raise RuntimeError("GNOME Wayland session did not become ready")
    print("guest-firefox-check: graphical GNOME session ready", flush=True)

    # graphical.target precedes the end of GNOME's background startup. Let the
    # run queue settle before measuring steady-state syscall throughput. Keep
    # this snapshot O(1): enumerating every thread through procfs is itself a
    # large syscall workload and can overrun the command window on the exact
    # slow builds this harness is meant to diagnose, contaminating every later
    # command queued on the same debug shell.
    time.sleep(30)
    stall = KERNEL_STALL.search(buf.decode("utf-8", "replace"))
    if stall:
        raise RuntimeError(f"kernel stalled while GNOME settled: {stall.group(0)}")
    runtime = run(
        uart,
        buf,
        "cat /proc/loadavg; nproc",
        settle=15,
    )
    if not rc(runtime):
        control_alive = False
        raise RuntimeError("UART control channel stopped during GNOME settle")
    print("guest-firefox-check: settled runtime snapshot:\n" + runtime[-8000:], flush=True)

    journal = run(
        uart,
        buf,
        "d=/var/log/journal/$(cat /etc/machine-id); "
        "test -d \"$d\" && "
        "find \"$d\" -maxdepth 1 -type f -name 'system*.journal' -size +0c -print -quit | grep -q . && "
        "find \"$d\" -maxdepth 1 -type f -name 'user-1000*.journal' -size +0c -print -quit | grep -q . && "
        "timeout 20s journalctl --verify --quiet",
        settle=30,
    )
    if not rc(journal):
        ok = False
        print("guest-firefox-check: FAIL — persistent journals missing or invalid", flush=True)
        print(journal[-4000:], flush=True)
    else:
        print("guest-firefox-check: persistent system/user journals verified", flush=True)

    if PROFILE:
        print("guest-firefox-check: production QMP RIP sampling active", flush=True)

    # Two hundred thousand one-byte reads plus writes: the same 400k-call
    # release probe used to quantify the old syscall-wide runtime tax.  Keep
    # its current number beside the browser result so a stale pre-fix number
    # cannot be mistaken for the performance of this build.
    bench = run(
        uart,
        buf,
        "TIMEFORMAT='OXIDE-BENCH real=%R user=%U sys=%S'; "
        "for n in 1 2 3; do time dd if=/dev/zero of=/dev/null "
        "bs=1 count=200000 status=none; done",
        settle=60,
    )
    if not rc(bench):
        ok = False
        print("guest-firefox-check: FAIL — syscall benchmark did not complete", flush=True)
    print("guest-firefox-check: syscall benchmark:\n" + bench[-1600:], flush=True)

    # Separate transport latency from browser startup/rendering.  This is a
    # small HTTPS response on the same origin Firefox opens below, forced to
    # HTTP/1.1 so the measurement exercises DNS + TCP + TLS without depending
    # on the browser's HTTP/2 implementation.  Keep absence of curl diagnostic,
    # not fatal, because the graphical Firefox check remains the acceptance
    # criterion.
    transfer = run(
        uart,
        buf,
        "if command -v curl >/dev/null; then "
        "TIMEFORMAT='OXIDE-CURL-SHELL real=%R user=%U sys=%S'; "
        "time timeout 30s curl -kL --http1.1 -o /dev/null "
        "-w 'OXIDE-CURL code=%{http_code} bytes=%{size_download} "
        "start=%{time_starttransfer} total=%{time_total}\\n' "
        "https://one.one.one.one/cdn-cgi/trace; "
        "else echo 'OXIDE-CURL unavailable'; fi",
        settle=45,
    )
    print("guest-firefox-check: HTTPS control:\n" + transfer[-2400:], flush=True)

    ping = run(
        uart,
        buf,
        "timeout 20s busctl --system call org.freedesktop.resolve1 "
        "/org/freedesktop/resolve1 org.freedesktop.DBus.Peer Ping",
    )
    if not rc(ping):
        ok = False
        print("guest-firefox-check: FAIL — baseline resolver D-Bus Ping", flush=True)

    control = run(uart, buf, "true", settle=10)
    if not rc(control):
        control_alive = False
        raise RuntimeError("UART control channel stopped after resolver probe")

    baseline = screenshot(qmp, "baseline")
    launch = run(
        uart,
        buf,
        "runuser -u oxide -- mkdir -p /tmp/oxide-firefox-test-profile; "
        f"runuser -u oxide -- env {FIREFOX_ENV} firefox --new-instance "
        "--profile /tmp/oxide-firefox-test-profile --new-window "
        "https://one.one.one.one >/tmp/oxide-firefox.log 2>&1 & true",
    )
    if not rc(launch):
        ok = False
        print("guest-firefox-check: FAIL — Firefox launch command", flush=True)
    if PROFILE:
        profile_samples.extend(sample_rips(qmp, "valid-load", 20, 200))
    else:
        wait_for_screen(
            qmp,
            "valid-probe",
            20,
            lambda text: "internet safer" in text or "dns families" in text,
        )

    valid_health = run(
        uart,
        buf,
        "timeout 20s getent ahostsv4 one.one.one.one; "
        "pgrep -u oxide -f '[f]irefox' >/dev/null",
    )
    valid = screenshot(qmp, "valid")
    valid_text = screen_text("valid")
    print("guest-firefox-check: valid screen OCR:\n" + valid_text[-2000:], flush=True)
    if not (rc(valid_health) and re.search(r"1\.1\.1\.1", valid_health)):
        ok = False
        print("guest-firefox-check: FAIL — valid page health", flush=True)
        print(valid_health[-3000:], flush=True)
    if valid == baseline:
        ok = False
        print("guest-firefox-check: FAIL — graphical screen did not change for Firefox", flush=True)

    valid_net = run(
        uart,
        buf,
        "timeout 10s ss -tinap; cat /proc/net/snmp; cat /proc/net/netstat; "
        "cat /proc/net/tcp; cat /proc/net/tcp6",
        settle=20,
    )
    print("guest-firefox-check: network state after valid-page window:\n" + valid_net[-12000:], flush=True)

    missing_launch = run(
        uart,
        buf,
        f"runuser -u oxide -- env {FIREFOX_ENV} firefox "
        "--profile /tmp/oxide-firefox-test-profile --new-tab "
        "http://oxide-no-such-host.invalid >/tmp/oxide-firefox-invalid.log 2>&1 & true",
    )
    if not rc(missing_launch):
        ok = False
        print("guest-firefox-check: FAIL — Firefox did not accept invalid-host tab", flush=True)
        print(missing_launch[-3000:], flush=True)
    if PROFILE:
        profile_samples.extend(sample_rips(qmp, "invalid-load", 15, 150))
    else:
        wait_for_screen(
            qmp,
            "invalid-probe",
            15,
            lambda text: "server not found" in text and "oxide-no-such-host.invalid" in text,
        )

    missing_health = run(
        uart,
        buf,
        "timeout 20s getent ahostsv4 oxide-no-such-host.invalid; r=$?; "
        "test $r -eq 2 && pgrep -u oxide -f '[f]irefox' >/dev/null && "
        "timeout 20s busctl --system call org.freedesktop.resolve1 "
        "/org/freedesktop/resolve1 org.freedesktop.DBus.Peer Ping",
    )
    missing = screenshot(qmp, "invalid")
    missing_text = screen_text("invalid")
    print("guest-firefox-check: invalid screen OCR:\n" + missing_text[-2000:], flush=True)
    if not rc(missing_health):
        ok = False
        print("guest-firefox-check: FAIL — invalid-host browser/resolver health", flush=True)
        print(missing_health[-4000:], flush=True)
    if missing == valid:
        ok = False
        print("guest-firefox-check: FAIL — monitor did not change for invalid-host page", flush=True)
    if "oxide-no-such-host.invalid" not in missing_text.lower():
        ok = False
        print("guest-firefox-check: FAIL — invalid-host URL absent from monitor OCR", flush=True)

    fault = KERNEL_FAULT.search(buf.decode("utf-8", "replace"))
    if fault:
        ok = False
        print(f"guest-firefox-check: FAIL — kernel fault: {fault.group(0)}", flush=True)
    storage_error = STORAGE_ERROR.search(buf.decode("utf-8", "replace"))
    if storage_error:
        ok = False
        print(f"guest-firefox-check: FAIL — storage error: {storage_error.group(0)}", flush=True)
except (OSError, RuntimeError, socket.timeout, json.JSONDecodeError) as exc:
    ok = False
    print(f"guest-firefox-check: FAIL — {exc}", flush=True)
finally:
    if not ok and PROFILE and qmp is not None and not profile_samples:
        try:
            print("guest-firefox-check: sampling pre-readiness failure", flush=True)
            profile_samples.extend(sample_rips(qmp, "readiness-failure", 10, 200))
        except (OSError, RuntimeError, socket.timeout, json.JSONDecodeError) as exc:
            print(f"guest-firefox-check: failure sampling unavailable: {exc}", flush=True)
    if not ok and uart is not None and control_alive:
        diagnostics(uart, buf)
    if not ok and qmp is not None:
        dynamic_commands = []
        try:
            registers = qmp_human(qmp, "info registers")
            print(f"--- QMP info registers ---\n{registers}", flush=True)
            # R14 is the compiled x86 scheduler's per-CPU runqueue base on a
            # failed rq-lock acquisition. Retaining it makes the lock byte,
            # current task and switch-handoff token inspectable after teardown.
            for register in ("RSP", "RBP", "R14", "R15"):
                match = re.search(rf"\b{register}=([0-9a-fA-F]+)", registers)
                if match:
                    dynamic_commands.append(f"x /64gx 0x{match.group(1)}")
        except (OSError, RuntimeError, socket.timeout, json.JSONDecodeError) as exc:
            print(f"guest-firefox-check: QMP register diagnostic failed: {exc}", flush=True)
        for command in dynamic_commands + ["info irq", "info pic", "i /8bx 0x3f8"]:
            try:
                print(f"--- QMP {command} ---\n{qmp_human(qmp, command)}", flush=True)
            except (OSError, RuntimeError, socket.timeout, json.JSONDecodeError) as exc:
                print(f"guest-firefox-check: QMP diagnostic failed: {exc}", flush=True)
    if uart is not None:
        uart.close()
    if qmp is not None:
        qmp.close()
    if PROFILE and profile_samples:
        write_profile(profile_samples)
    try:
        os.killpg(os.getpgid(qemu.pid), signal.SIGTERM)
        qemu.wait(timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        try:
            os.killpg(os.getpgid(qemu.pid), signal.SIGKILL)
        except OSError:
            pass
    uart_log.close()
    qemu_log.close()

if not ok:
    print("--- UART tail for failed Firefox probe ---", flush=True)
    print(buf.decode("utf-8", "replace")[-24000:], flush=True)
print(f"guest-firefox-check: {'PASS' if ok else 'FAIL'}", flush=True)
raise SystemExit(0 if ok else 1)
