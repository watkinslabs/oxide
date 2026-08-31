#!/usr/bin/env python3
"""UART-only regression probe for systemd-resolved startup and D-Bus health.

This intentionally never contacts the guest through SSH: its only control and
observation channel is the QEMU UART socket.  It catches the regression where
resolved had a configured DNS server but no active link scope at boot, and it
also repeats its D-Bus Ping enough times to distinguish a responsive event
loop from the old one-off serial observation.

Usage: tools/guest-resolved-check.py <x86|arm> [boot_timeout_s]
"""
import os
import re
import select
import shlex
import socket
import subprocess
import sys
import time


ARCH = sys.argv[1] if len(sys.argv) > 1 else "x86"
if ARCH not in ("x86", "arm"):
    raise SystemExit("usage: guest-resolved-check.py <x86|arm> [boot_timeout_s]")
BOOT_TIMEOUT = int(sys.argv[2]) if len(sys.argv) > 2 else 600
# A pass/fail rate run repeats this probe dozens of times, and the settle
# windows below are what a FAILING boot spends nearly all its wall clock in:
# five D-Bus pings that each wait out the full command timeout. Measuring a
# rate does not need the repetition that diagnosing one boot does, so the
# counts and windows are settable. Defaults are the diagnostic ones.
COMMAND_TIMEOUT = int(os.environ.get("OXIDE_PROBE_CMD_TIMEOUT", "35"))
RESOLVER_READY_TIMEOUT = int(os.environ.get("OXIDE_PROBE_RESOLVER_TIMEOUT", "60"))
PING_COUNT = int(os.environ.get("OXIDE_PROBE_PINGS", "5"))
# How to bring the guest up. A rate run builds the ISO once and then launches
# it with `--run-existing`, so the per-iteration cargo + xorriso work is not
# repeated for a kernel nobody changed.
LAUNCH = os.environ.get("OXIDE_PROBE_LAUNCH")
SOCK = f"/tmp/oxide-resolved-uart-{ARCH}-{os.getpid()}.sock"
LOG = f"/tmp/oxide-resolved-uart-{ARCH}-{os.getpid()}.log"
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
KERNEL_FAULT = re.compile(
    r"\[BUG\] scheduling while atomic|IRQ stack guard page|\[BADSTACK\]|#DF|Kernel panic"
)


# The probe drives the systemd debug shell over UART.  Without this boot-line
# selection, serial-getty owns ttyS0 and the commands below are interpreted as
# login names, producing a false resolver failure.
env = dict(os.environ, OXIDE_QEMU_UART_SOCK=SOCK, OXIDE_QEMU_HEADLESS="1",
           OXIDE_SERIAL_SHELL="1")
log = open(LOG, "wb")
print(f"guest-resolved-check: arch={ARCH} uart={SOCK} log={LOG}", flush=True)
qemu = subprocess.Popen(
    shlex.split(LAUNCH) if LAUNCH else ["make", f"qemu-{ARCH}"],
    env=env, stdout=log, stderr=subprocess.STDOUT,
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
    return True


def wait_for(conn, buf, pattern, seconds):
    rx = re.compile(pattern)
    deadline = time.time() + seconds
    while time.time() < deadline:
        if rx.search(buf.decode("utf-8", "replace")):
            return True
        if not pump(conn, buf, 1):
            return False
    return False


def run(conn, buf, command, settle=COMMAND_TIMEOUT):
    """Run one command and return only bytes produced after its submission.

    The marker contains `$?` in the transmitted source and a numeric result in
    its evaluated output, so command echo cannot counterfeit success.
    """
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


conn = None
buf = bytearray()
ok = True
try:
    deadline = time.time() + BOOT_TIMEOUT
    while time.time() < deadline:
        if os.path.exists(SOCK):
            try:
                conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                conn.connect(SOCK)
                break
            except OSError:
                conn = None
        if qemu.poll() is not None:
            raise RuntimeError("build/boot exited before the UART appeared")
        time.sleep(2)
    if conn is None:
        raise RuntimeError("UART socket never appeared")
    # The image need not route a target-completion line to the UART.  Ask the
    # debug shell directly until it proves it is alive; this is also what the
    # ordinary smoke harness does when its passive marker is absent.
    shell_deadline = time.time() + BOOT_TIMEOUT
    while time.time() < shell_deadline:
        out = run(conn, buf, "true", settle=2)
        if re.search(r"OXIDE-RC-0", out):
            break
    else:
        raise RuntimeError("serial debug shell did not answer")
    # The debug shell is intentionally available before the normal boot target.
    # Give NetworkManager and resolved time to finish link discovery before
    # asking for the scope; this is a readiness check, not a boot-speed check.
    run(conn, buf, "sleep 20", settle=30)

    ready_deadline = time.time() + RESOLVER_READY_TIMEOUT
    scope = ""
    while time.time() < ready_deadline:
        unit = run(conn, buf, "systemctl is-active systemd-resolved; pidof systemd-resolved")
        if re.search(r"^active\s*$", unit, re.MULTILINE) and re.search(r"[0-9]+", unit):
            scope = run(conn, buf, "resolvectl status")
            if re.search(r"Current Scopes:\s+DNS LLMNR/IPv4", scope) and re.search(r"OXIDE-RC-0", scope):
                break
        time.sleep(1)
    print("guest-resolved-check: resolved unit probe:\n" + unit[-1200:], flush=True)
    if re.search(r"Current Scopes:\s+DNS LLMNR/IPv4", scope) and re.search(r"OXIDE-RC-0", scope):
        print("guest-resolved-check: IPv4 DNS scope ready", flush=True)
    else:
        # `resolvectl status` is a diagnostic D-Bus round trip, and can miss
        # the command marker when the boot is busy even though resolved is
        # serving the stub.  The end-to-end D-Bus and DNS probes below are the
        # authoritative readiness checks; keep this as a warning so the
        # harness cannot call a working resolver broken on text-format timing.
        print("guest-resolved-check: WARNING — status scope text unavailable; continuing with end-to-end probes", flush=True)
        print(scope[-3000:], flush=True)

    for n in range(1, PING_COUNT + 1):
        out = run(conn, buf,
            "busctl --system call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.DBus.Peer Ping")
        if re.search(r"OXIDE-RC-0", out):
            print(f"guest-resolved-check: D-Bus Ping {n}/{PING_COUNT} OK", flush=True)
        else:
            ok = False
            print(f"guest-resolved-check: FAIL — D-Bus Ping {n}/{PING_COUNT}", flush=True)
            print(out[-3000:], flush=True)
            if n == 1:
                # The resolver can be active while its D-Bus peer or the
                # broker is parked forever.  Capture the kernel-visible wait
                # owner at the first failure; this is the useful distinction
                # between a network configuration problem and a scheduler/
                # IPC wait regression.
                diag = run(conn, buf,
                    "ps -eo pid,comm,state,wchan; for p in $(pidof dbus-broker systemd-resolved); do echo PID=$p; cat /proc/$p/wchan; done")
                print("guest-resolved-check: wait diagnostics:\n" + diag[-5000:], flush=True)

    query = run(conn, buf, "getent ahostsv4 one.one.one.one")
    if re.search(r"1\.1\.1\.1", query) and re.search(r"OXIDE-RC-0", query):
        print("guest-resolved-check: stub DNS query OK", flush=True)
    else:
        ok = False
        print("guest-resolved-check: FAIL — stub DNS query", flush=True)
        print(query[-3000:], flush=True)

    missing = run(conn, buf, "getent ahostsv4 oxide-no-such-host.invalid")
    if re.search(r"OXIDE-RC-2", missing) and not re.search(r"^[0-9].*STREAM", missing, re.MULTILINE):
        print("guest-resolved-check: negative DNS query OK", flush=True)
    else:
        ok = False
        print("guest-resolved-check: FAIL — negative DNS query", flush=True)
        print(missing[-3000:], flush=True)

    fault = KERNEL_FAULT.search(buf.decode("utf-8", "replace"))
    if fault:
        ok = False
        print(f"guest-resolved-check: FAIL — kernel fault: {fault.group(0)}", flush=True)
except RuntimeError as exc:
    ok = False
    print(f"guest-resolved-check: FAIL — {exc}", flush=True)
finally:
    if conn is not None:
        conn.close()
    try:
        os.killpg(os.getpgid(qemu.pid), 9)
    except OSError:
        pass
    # QEMU's UART is routed through the Unix socket, so it is not present in
    # the build log opened above.  Preserve the captured guest transcript in
    # the advertised log before closing it; otherwise a failed resolver probe
    # prints evidence that disappears with the process.
    try:
        with open(LOG, "ab") as uart_log:
            uart_log.write(buf)
    except OSError:
        pass
    log.close()

if not ok:
    print("--- UART tail for failed resolved probe ---", flush=True)
    print(buf.decode("utf-8", "replace")[-24000:], flush=True)
print(f"guest-resolved-check: {'PASS' if ok else 'FAIL'} ({ARCH})", flush=True)
raise SystemExit(0 if ok else 1)
