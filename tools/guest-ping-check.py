#!/usr/bin/env python3
"""Drive the guest's serial debug shell and run the distribution's ping(8) as an
ordinary user. Boots via `make qemu-<arch>` with the UART on a unix socket, so
the check needs neither guest networking nor sshd.

Usage: tools/guest-ping-check.py <x86|arm> [boot_timeout_s]
"""
import os, re, select, socket, subprocess, sys, time

ARCH = sys.argv[1] if len(sys.argv) > 1 else "x86"
BOOT_TIMEOUT = int(sys.argv[2]) if len(sys.argv) > 2 else 600
SOCK = f"/tmp/oxide-ping-uart-{ARCH}-{os.getpid()}.sock"
LOG = f"/tmp/oxide-ping-uart-{ARCH}-{os.getpid()}.log"

# Every command runs as the unprivileged desktop user, which holds no
# capabilities: the echo-probe tool therefore has only the ICMP datagram
# endpoint class to fall back on.
CHECKS = [
    ("group window", "cat /proc/sys/net/ipv4/ping_group_range", r"0\s+2147483647"),
    ("no capabilities", "getcap /usr/bin/ping; echo CAPS_DONE", r"CAPS_DONE"),
    ("loopback probe", "runuser -u oxide -- ping -c2 -W3 127.0.0.1", r"2 received"),
    ("endpoint export", "cat /proc/net/icmp", r"local_address"),
    ("ipv6 loopback probe", "runuser -u oxide -- ping -6 -c1 -W3 ::1", r"1 received"),
]

env = dict(os.environ, OXIDE_QEMU_UART_SOCK=SOCK, OXIDE_QEMU_HEADLESS="1")
log = open(LOG, "wb")
print(f"guest-ping-check: arch={ARCH} sock={SOCK} log={LOG}", flush=True)
qemu = subprocess.Popen(["make", f"qemu-{ARCH}"], env=env, stdout=log, stderr=subprocess.STDOUT,
                        stdin=subprocess.DEVNULL, start_new_session=True)

conn = None
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
        print("guest-ping-check: FAIL — build/boot exited before the UART appeared", flush=True)
        sys.exit(1)
    time.sleep(2)
if conn is None:
    print("guest-ping-check: FAIL — UART socket never appeared", flush=True)
    qemu.kill(); sys.exit(1)

buf = bytearray()

def pump(seconds):
    end = time.time() + seconds
    while time.time() < end:
        r, _, _ = select.select([conn], [], [], 0.5)
        if not r:
            continue
        chunk = conn.recv(65536)
        if not chunk:
            return
        buf.extend(chunk)

def wait_for(pattern, seconds):
    end = time.time() + seconds
    rx = re.compile(pattern)
    while time.time() < end:
        if rx.search(buf.decode("utf-8", "replace")):
            return True
        pump(1)
    return False

def run(cmd, seconds=90):
    tag = f"OXMARK{int(time.time()*1000)%100000}"
    start = len(buf)
    conn.sendall(f"\n{cmd}; echo {tag}-rc=$?\n".encode())
    end = time.time() + seconds
    while time.time() < end:
        pump(1)
        text = buf[start:].decode("utf-8", "replace")
        if f"{tag}-rc=" in text and not f"echo {tag}" in text.split(f"{tag}-rc=")[-1]:
            return text
    return buf[start:].decode("utf-8", "replace")

ok = True
try:
    if not wait_for(r"Reached target (basic|multi-user|graphical)", BOOT_TIMEOUT):
        print("guest-ping-check: FAIL — userspace never reached a boot target", flush=True)
        sys.exit(1)
    # The debug shell is enabled on this line by the boot command line; nudge it
    # into printing a prompt before issuing anything that matters.
    conn.sendall(b"\n")
    pump(5)
    probe = run("echo SHELL_ALIVE", 60)
    if "SHELL_ALIVE" not in probe:
        print("guest-ping-check: FAIL — no serial shell responded", flush=True)
        print(probe[-2000:], flush=True)
        sys.exit(1)
    for label, cmd, want in CHECKS:
        out = run(cmd)
        if re.search(want, out):
            print(f"guest-ping-check: {label} OK", flush=True)
        else:
            ok = False
            print(f"guest-ping-check: FAIL — {label} (wanted /{want}/)", flush=True)
            print(out[-3000:], flush=True)
finally:
    try:
        conn.close()
    except OSError:
        pass
    try:
        os.killpg(os.getpgid(qemu.pid), 9)
    except OSError:
        pass

print(f"guest-ping-check: {'PASS' if ok else 'FAIL'} ({ARCH})", flush=True)
sys.exit(0 if ok else 1)
