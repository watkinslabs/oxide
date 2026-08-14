#!/usr/bin/env python3
"""Prove a guest's physical-NIC path obtains an IPv4 lease and exchanges packets.

The Fedora root image owns DHCP through NetworkManager. The probe stages the
image first, then starts the guest deadline only after QEMU launches. A serial
shell runs an address-and-gateway check; its output marker cannot be satisfied
by UART command echo because the marker is split in the typed command.

Usage: tools/guest-network-check.py <x86> [runtime_timeout_s]
"""
import os
import re
import select
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

ARCH = sys.argv[1] if len(sys.argv) > 1 else "x86"
if ARCH != "x86":
    print("guest-network-check: only x86 native-Q35 currently has e1000e", file=sys.stderr)
    sys.exit(2)
TIMEOUT = int(sys.argv[2]) if len(sys.argv) > 2 else 600
ROOT = Path(__file__).resolve().parent.parent
STAMP = f"{ARCH}-network-{os.getpid()}"
SOCK = f"/tmp/oxide-{STAMP}.sock"
LOG = Path(os.environ.get("NETWORK_KEEP_LOG", ROOT / "target/boot-logs" / f"{STAMP}.log"))
MARKER = "OXIDE-NETWORK-OK"
READY = re.compile(r"sh-5\.2#")


def die(message, qemu=None):
    print(f"guest-network-check: FAIL — {message}", file=sys.stderr)
    if qemu is not None:
        stop(qemu)
    if LOG.exists():
        print(f"guest-network-check: retained serial log {LOG}", file=sys.stderr)
        print(LOG.read_text(errors="replace")[-6000:], file=sys.stderr)
    sys.exit(1)


def stop(proc):
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=3)
    except (OSError, subprocess.TimeoutExpired):
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except OSError:
            pass


def pump(conn, buf, serial, seconds):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        readable, _, _ = select.select([conn], [], [], 0.5)
        if not readable:
            continue
        chunk = conn.recv(65536)
        if not chunk:
            return False
        buf.extend(chunk)
        serial.write(chunk)
        serial.flush()
    return True


def main():
    LOG.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, OXIDE_QEMU_HEADLESS="1", OXIDE_QEMU_UART_SOCK=SOCK)
    print("guest-network-check: staging fresh x86 image", flush=True)
    if subprocess.run(["make", "qemu-x86-image"], cwd=ROOT, env=env).returncode:
        die("image preparation failed")
    host_log = LOG.with_suffix(LOG.suffix + ".host")
    log = host_log.open("wb")
    serial = LOG.open("wb")
    qemu = subprocess.Popen(["make", "qemu-x86-existing"], cwd=ROOT, env=env,
                            stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                            start_new_session=True)
    conn = None
    deadline = time.monotonic() + TIMEOUT
    try:
        while time.monotonic() < deadline:
            if qemu.poll() is not None:
                die("QEMU exited before UART was available", qemu)
            if os.path.exists(SOCK):
                try:
                    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    conn.connect(SOCK)
                    break
                except OSError:
                    conn = None
            time.sleep(1)
        if conn is None:
            die("UART socket never appeared", qemu)
        buf = bytearray()
        while time.monotonic() < deadline:
            if qemu.poll() is not None:
                die("QEMU exited before network proof", qemu)
            pump(conn, buf, serial, 1)
            text = buf.decode("utf-8", "replace")
            if not READY.search(text):
                continue
            start = len(buf)
            command = "ip -4 -o addr show dev eth0 scope global | grep -Eq 'inet [1-9][0-9]*\\.' && ping -c1 -W3 10.0.2.2 >/dev/null && printf '%s\\n' OXIDE-NET\"WORK\"-OK"
            conn.sendall(("\n" + command + "\n").encode())
            if not pump(conn, buf, serial, 5):
                die("UART closed during network proof", qemu)
            if MARKER in buf[start:].decode("utf-8", "replace"):
                print("guest-network-check: PASS — eth0 acquired IPv4 and pinged QEMU gateway", flush=True)
                return
        die(f"timeout after {TIMEOUT}s without DHCP/gateway proof", qemu)
    finally:
        if conn is not None:
            conn.close()
        stop(qemu)
        log.close()
        serial.close()
        if os.path.exists(SOCK):
            os.unlink(SOCK)


if __name__ == "__main__":
    main()
