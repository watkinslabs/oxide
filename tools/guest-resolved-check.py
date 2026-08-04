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
import socket
import subprocess
import sys
import time


ARCH = sys.argv[1] if len(sys.argv) > 1 else "x86"
if ARCH not in ("x86", "arm"):
    raise SystemExit("usage: guest-resolved-check.py <x86|arm> [boot_timeout_s]")
BOOT_TIMEOUT = int(sys.argv[2]) if len(sys.argv) > 2 else 600
SETTLE = 8 if ARCH == "x86" else 20
SOCK = f"/tmp/oxide-resolved-uart-{ARCH}-{os.getpid()}.sock"
LOG = f"/tmp/oxide-resolved-uart-{ARCH}-{os.getpid()}.log"
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


env = dict(os.environ, OXIDE_QEMU_UART_SOCK=SOCK, OXIDE_QEMU_HEADLESS="1")
log = open(LOG, "wb")
print(f"guest-resolved-check: arch={ARCH} uart={SOCK} log={LOG}", flush=True)
qemu = subprocess.Popen(
    ["make", f"qemu-{ARCH}"], env=env, stdout=log, stderr=subprocess.STDOUT,
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


def run(conn, buf, command, settle=SETTLE):
    """Run one command and return only bytes produced after its submission.

    The marker contains `$?` in the transmitted source and a numeric result in
    its evaluated output, so command echo cannot counterfeit success.
    """
    start = len(buf)
    conn.sendall(("\n" + command + "; printf 'OXIDE-RC-%d\\n' $?\n").encode())
    pump(conn, buf, settle)
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

    unit = run(conn, buf, "systemctl is-active systemd-resolved; pidof systemd-resolved")
    print("guest-resolved-check: resolved unit probe:\n" + unit[-1200:], flush=True)
    scope = run(conn, buf, "resolvectl status")
    if re.search(r"Current Scopes:\s+DNS LLMNR/IPv4", scope) and re.search(r"OXIDE-RC-0", scope):
        print("guest-resolved-check: startup scope OK", flush=True)
    else:
        ok = False
        print("guest-resolved-check: FAIL — no IPv4 DNS scope at boot", flush=True)
        print(scope[-3000:], flush=True)

    for n in range(1, 6):
        out = run(conn, buf,
            "busctl --system call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.DBus.Peer Ping")
        if re.search(r"OXIDE-RC-0", out):
            print(f"guest-resolved-check: D-Bus Ping {n}/5 OK", flush=True)
        else:
            ok = False
            print(f"guest-resolved-check: FAIL — D-Bus Ping {n}/5", flush=True)
            print(out[-3000:], flush=True)

    query = run(conn, buf, "getent ahostsv4 one.one.one.one")
    if re.search(r"1\.1\.1\.1", query) and re.search(r"OXIDE-RC-0", query):
        print("guest-resolved-check: stub DNS query OK", flush=True)
    else:
        ok = False
        print("guest-resolved-check: FAIL — stub DNS query", flush=True)
        print(query[-3000:], flush=True)
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
    log.close()

if not ok:
    print("--- UART tail for failed resolved probe ---", flush=True)
    print(buf.decode("utf-8", "replace")[-24000:], flush=True)
print(f"guest-resolved-check: {'PASS' if ok else 'FAIL'} ({ARCH})", flush=True)
raise SystemExit(0 if ok else 1)
