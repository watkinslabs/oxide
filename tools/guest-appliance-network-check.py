#!/usr/bin/env python3
"""Prove an appliance image obtains a lease and resolves names, over UART only.

The appliance profiles (`micro`, `nano`) carry no NetworkManager: the network
manager is systemd-networkd, selected by an `enable` line in a preset file the
compose applies, with systemd-resolved publishing the lease's DNS servers. That
is four separate things that can each silently be absent, and an image with any
of them missing looks exactly like a broken kernel from userspace. This asks the
guest about all of them.

`tools/guest-network-check.py` is the sibling probe for the NetworkManager path
on native-Q35 hardware; this one is the appliance/virtio path.

Usage: tools/guest-appliance-network-check.py [profile] [boot_timeout_s]
"""
import os, re, select, socket, subprocess, sys, time

ARCH = "x86"
PROFILE = sys.argv[1] if len(sys.argv) > 1 else "micro"
BOOT_TIMEOUT = int(sys.argv[2]) if len(sys.argv) > 2 else 900
SOCK = f"/tmp/oxide-appliance-net-{PROFILE}-{os.getpid()}.sock"
LOG = f"/tmp/oxide-appliance-net-host-{PROFILE}-{os.getpid()}.log"
UART = f"/tmp/oxide-appliance-net-uart-{PROFILE}-{os.getpid()}.txt"
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
env = dict(os.environ, OXIDE_QEMU_UART_SOCK=SOCK, OXIDE_QEMU_HEADLESS="1",
           OXIDE_SERIAL_SHELL="1", OXIDE_QUICKBOOT_PROFILE=PROFILE)
log = open(LOG, "wb")
# Stage the image BEFORE the boot deadline starts. `make qemu-x86` builds and
# then boots, so a probe that starts its clock there is timing a kernel build,
# and a cold tree makes it look like a boot that never reached the UART.
print(f"appliance-network: staging {PROFILE} image", flush=True)
if subprocess.run(["make", f"qemu-{ARCH}-image"], env=env, stdout=log,
                  stderr=subprocess.STDOUT).returncode:
    print("appliance-network: FAIL — image preparation failed", flush=True)
    raise SystemExit(1)
qemu = subprocess.Popen(["make", f"qemu-{ARCH}-existing"], env=env, stdout=log,
                        stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                        start_new_session=True)

def pump(conn, buf, seconds):
    deadline = time.time() + seconds
    while time.time() < deadline:
        r, _, _ = select.select([conn], [], [], min(0.5, max(0.01, deadline - time.time())))
        if not r:
            continue
        chunk = conn.recv(65536)
        if not chunk:
            return False
        buf.extend(chunk)
    return True

def clean(raw):
    """Decode one UART slice. The line terminator is CR LF, so a `^` anchor in
    a caller's pattern would otherwise be looking at the CR and never match a
    correct answer."""
    return ANSI.sub("", raw.decode("utf-8", "replace")).replace("\r", "")


def run(conn, buf, command, settle=35):
    start = len(buf)
    conn.sendall(("\n" + command + "; printf 'OXIDE-RC-%d\\n' $?\n").encode())
    deadline = time.time() + settle
    while time.time() < deadline:
        out = clean(buf[start:])
        if re.search(r"OXIDE-RC-[0-9]+\n", out):
            return out
        if not pump(conn, buf, 1):
            break
    return clean(buf[start:])

conn, buf, ok, results = None, bytearray(), True, []
try:
    deadline = time.time() + BOOT_TIMEOUT
    while time.time() < deadline:
        if os.path.exists(SOCK):
            try:
                conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); conn.connect(SOCK); break
            except OSError:
                conn = None
        if qemu.poll() is not None:
            raise RuntimeError("build/boot exited before the UART appeared")
        time.sleep(2)
    if conn is None:
        raise RuntimeError("UART socket never appeared")
    while time.time() < deadline:
        if re.search(r"OXIDE-RC-0", run(conn, buf, "true", settle=2)):
            break
    else:
        raise RuntimeError("serial debug shell did not answer")
    run(conn, buf, "sleep 20", settle=30)

    checks = [
        ("networkd enabled", "systemctl is-enabled systemd-networkd.service", r"^enabled"),
        ("networkd active", "systemctl is-active systemd-networkd.service", r"^active"),
        ("resolved enabled", "systemctl is-enabled systemd-resolved.service", r"^enabled"),
        ("wired profile shipped", "ls /usr/lib/systemd/network/20-wired.network", r"20-wired\.network"),
        ("resolv.conf symlink", "readlink /etc/resolv.conf", r"stub-resolv\.conf"),
        ("nameserver published", "grep -c ^nameserver /etc/resolv.conf", r"^[1-9]"),
        ("ipv4 lease", "ip -4 -o addr show scope global", r"inet [1-9][0-9]*\."),
        ("default route", "ip -4 route show default", r"^default via"),
        ("forward query", "getent ahostsv4 one.one.one.one", r"1\.1\.1\.1"),
    ]
    for label, cmd, want in checks:
        out = run(conn, buf, cmd)
        good = re.search(want, out, re.MULTILINE) is not None
        ok = ok and good
        results.append((good, label, out))
except RuntimeError as exc:
    ok = False
    print(f"appliance-network: FAIL — {exc}", flush=True)
finally:
    if conn is not None:
        conn.close()
    try:
        os.killpg(os.getpgid(qemu.pid), 9)
    except OSError:
        pass
    log.close()
    # Retain the transcript: a truncated console capture cost a whole boot once.
    with open(UART, "w") as f:
        f.write(clean(buf))
for good, label, out in results:
    print(f"appliance-network: {'OK  ' if good else 'FAIL'} {label}", flush=True)
    if not good:
        print("        " + out.replace("\n", "\n        ")[-1200:], flush=True)
print(f"appliance-network: transcript {UART}", flush=True)
print(f"appliance-network: {'PASS' if ok else 'FAIL'}", flush=True)
raise SystemExit(0 if ok else 1)
