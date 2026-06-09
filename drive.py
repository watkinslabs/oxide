#!/usr/bin/env python3
import socket, time, sys, select

SOCK = "/tmp/v.sock"
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(SOCK)
s.setblocking(False)

logf = open("/tmp/serial.log", "ab", buffering=0)

def drain(timeout):
    """Read all available bytes for up to `timeout` seconds, return accumulated str."""
    buf = b""
    end = time.time() + timeout
    while time.time() < end:
        r,_,_ = select.select([s], [], [], 0.3)
        if r:
            try:
                d = s.recv(65536)
            except BlockingIOError:
                continue
            if not d:
                break
            buf += d
            logf.write(d)
            sys.stdout.write(d.decode("utf-8","replace"))
            sys.stdout.flush()
    return buf.decode("utf-8","replace")

def wait_for(needle, timeout):
    end = time.time() + timeout
    acc = ""
    while time.time() < end:
        acc += drain(1.0)
        if needle in acc:
            return True, acc
    return False, acc

def send(line):
    s.sendall((line + "\n").encode())
    time.sleep(0.2)

# Wait for login prompt. Boot is quiet+KVM-fast, so the prompt was likely
# already printed before we connected — nudge with a newline to reprint it.
print("=== WAITING FOR LOGIN ===", flush=True)
s.sendall(b"\n")
time.sleep(0.5)
ok, acc = wait_for("login:", 120)
print(f"\n=== login prompt seen: {ok} ===", flush=True)
if not ok:
    print("NO LOGIN PROMPT — dumping last buffer above", flush=True)
    sys.exit(2)

send("alice")
time.sleep(0.5)
ok, _ = wait_for("assword", 15)
send("swordfish")
time.sleep(1.0)
# drain whatever follows login (motd + prompt)
drain(4)

cmds = [
    ("SANITY", "echo OK-$((3+4))", 8),
    ("STARSHIP", "starship --version | head -1; echo SS=$?", 20),
    ("SIGURG", "timeout 10 sigurg_async_smoke; echo SMOKE=$?", 20),
    ("DUF", "timeout 10 duf --version 2>&1 | tail -2; echo DUF=$?", 25),
    ("GLOW", "timeout 10 glow --version; echo GLOW=$?", 25),
    ("MICRO", "timeout 10 micro -version; echo MICRO=$?", 25),
    ("YQ", "timeout 10 yq --version; echo YQ=$?", 25),
]

for name, cmd, to in cmds:
    print(f"\n\n========== {name} :: {cmd} ==========", flush=True)
    send(cmd)
    drain(to)

print("\n\n=== ALL COMMANDS SENT ===", flush=True)
drain(3)
s.close()
