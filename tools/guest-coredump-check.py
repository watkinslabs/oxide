#!/usr/bin/env python3
"""Crash a real program in the guest and prove the core it leaves is one a
debugger can read: `PT_LOAD` segments whose contents are the faulting text.

Boots via `make qemu-<arch>` with the UART on a unix socket, drives the serial
debug shell, then pulls the core's ELF header, program-header table and note
segment out over that same serial line and parses them here. The instruction
bytes at the crashing thread's program counter are compared against the same
bytes read from the on-disk object `NT_FILE` names, so a pass means the dump
carries the program's own instructions at the address it executed them from.

Usage: tools/guest-coredump-check.py <x86|arm> [boot_timeout_s]
"""
import base64, os, re, select, socket, struct, subprocess, sys, time

ARCH = sys.argv[1] if len(sys.argv) > 1 else "x86"
BOOT_TIMEOUT = int(sys.argv[2]) if len(sys.argv) > 2 else 900
SETTLE = 20 if ARCH == "x86" else 50
# How long the system is given to finish starting after its shell answers.
SETTLE_BOOT = 120 if ARCH == "x86" else 240
SOCK = f"/tmp/oxide-core-uart-{ARCH}-{os.getpid()}.sock"
LOG = f"/tmp/oxide-core-uart-{ARCH}-{os.getpid()}.log"
# Everything the guest said, kept whatever the outcome: a run that fails
# before the first check has nothing to explain itself with otherwise.
SERIAL = f"/tmp/oxide-core-serial-{ARCH}-{os.getpid()}.log"

DIR = "/tmp/coredump-check"
CORE = f"{DIR}/core"

PT_LOAD, PT_NOTE = 1, 4
PF_X = 1
NT_PRSTATUS, NT_FILE = 1, 0x46494c45
PAGE = 4096
# `pr_reg` starts here in every LP64 `elf_prstatus`; the program counter's slot
# inside the block is per-arch.
PR_REG_OFF = 112
PC_SLOT = {"x86": 16, "arm": 32}[ARCH]
PROBE_BYTES = 64

env = dict(os.environ, OXIDE_QEMU_UART_SOCK=SOCK, OXIDE_QEMU_HEADLESS="1")
log = open(LOG, "wb")
print(f"guest-coredump-check: arch={ARCH} sock={SOCK} log={LOG}", flush=True)
# Without `debug-boot` the console stays quiet enough to read a command's
# output back: that feature's per-call traces otherwise interleave with every
# line the shell prints.
FEATURE_VAR = {"x86": "QEMU_FEATURES_X86", "arm": "QEMU_FEATURES_ARM"}[ARCH]
# `COREDUMP_CHECK_DEBUG=1` keeps `debug-boot` on for the `[COREDUMP]` trace,
# at the cost of a console too noisy for the byte-level checks below.
FEATURES = "debug-boot" if os.environ.get("COREDUMP_CHECK_DEBUG") else ""
qemu = subprocess.Popen(["make", f"qemu-{ARCH}", f"{FEATURE_VAR}={FEATURES}"], env=env, stdout=log, stderr=subprocess.STDOUT,
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
        print("guest-coredump-check: FAIL — build/boot exited before the UART appeared", flush=True)
        sys.exit(1)
    time.sleep(2)
if conn is None:
    print("guest-coredump-check: FAIL — UART socket never appeared", flush=True)
    qemu.kill(); sys.exit(1)

buf = bytearray()

def pump(seconds):
    end = time.time() + seconds
    while time.time() < end:
        r, _, _ = select.select([conn], [], [], 0.5)
        if not r:
            continue
        chunk = conn.recv(1 << 20)
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

def run(cmd, settle=None):
    start = len(buf)
    conn.sendall(f"\n{cmd}\n".encode())
    pump(settle if settle is not None else SETTLE)
    return buf[start:].decode("utf-8", "replace")

def fetch(path, off, count):
    """Read `count` bytes at `off` from a guest file, over the serial line."""
    tag = "B64"
    out = run(f"echo {tag}$(dd if={path} bs=1 skip={off} count={count} 2>/dev/null | base64 -w0){tag}",
              settle=max(SETTLE, 6 + count // 1500))
    m = re.search(tag + r"([A-Za-z0-9+/=]*)" + tag, out)
    if not m:
        return None
    return base64.b64decode(m.group(1))

failures = []

def check(name, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{(' — ' + detail) if detail else ''}", flush=True)
    if not ok:
        failures.append(name)

try:
    # The serial debug shell answers long before the system has finished
    # starting. Crashing into a half-mounted `/tmp` writes the dump under a
    # directory a later mount then covers, so wait for the prompt, then let the
    # boot finish before touching anything.
    if not wait_for(r"sh-[\d.]+[#$]|[#$] $|oxide login:", BOOT_TIMEOUT):
        print("guest-coredump-check: FAIL — no shell on the serial line", flush=True)
        sys.exit(1)
    wait_for(r"Reached target|Startup finished", SETTLE_BOOT)
    pump(SETTLE_BOOT)

    run(f"mkdir -p {DIR}; rm -f {CORE}; echo {CORE} > /proc/sys/kernel/core_pattern;"
        f" cat /proc/sys/kernel/core_pattern")
    # Ask for the whole of every private file mapping, so the program's text is
    # carried rather than reduced to its identifying header page.
    crash = (f"bash -c 'ulimit -c unlimited; echo 0x3f > /proc/self/coredump_filter;"
             f" cat /proc/self/coredump_filter; kill -SEGV $$'")
    print(run(crash), flush=True)
    listing = run(f"ls -la {DIR}; echo SZ$(stat -c %s {CORE} 2>/dev/null || echo 0)SZ")
    print(listing, flush=True)
    m = re.search(r"SZ(\d+)SZ", listing)
    size = int(m.group(1)) if m else 0
    check("a crash leaves a core file", size > 0, f"{size} bytes")
    if size == 0:
        raise SystemExit(1)

    head = fetch(CORE, 0, 4096)
    check("the core starts with an ELF header", bool(head) and head[:4] == b"\x7fELF")
    if not head or head[:4] != b"\x7fELF":
        raise SystemExit(1)
    e_type, e_machine = struct.unpack_from("<HH", head, 16)
    e_phoff, = struct.unpack_from("<Q", head, 32)
    e_phentsize, e_phnum = struct.unpack_from("<HH", head, 54)
    check("it is an ET_CORE object", e_type == 4, f"e_type={e_type} e_machine={e_machine}")

    phdrs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        ty, flags, off, vaddr, paddr, filesz, memsz, align = struct.unpack_from("<IIQQQQQQ", head, o)
        phdrs.append(dict(ty=ty, flags=flags, off=off, vaddr=vaddr, filesz=filesz, memsz=memsz))
    loads = [p for p in phdrs if p["ty"] == PT_LOAD]
    print(f"  program headers: {e_phnum} total, {len(loads)} PT_LOAD", flush=True)
    for p in loads[:12]:
        print(f"    PT_LOAD vaddr={p['vaddr']:#014x} memsz={p['memsz']:#x} "
              f"filesz={p['filesz']:#x} flags={p['flags']}", flush=True)
    check("the core carries PT_LOAD segments", len(loads) > 0, f"{len(loads)}")
    check("some PT_LOAD carries contents", any(p["filesz"] > 0 for p in loads),
          f"{sum(p['filesz'] for p in loads)} bytes of memory")

    note = next((p for p in phdrs if p["ty"] == PT_NOTE), None)
    check("the core carries a PT_NOTE segment", note is not None)
    if note is None:
        raise SystemExit(1)
    nb = fetch(CORE, note["off"], note["filesz"])
    check("the note segment reads back", bool(nb) and len(nb) == note["filesz"],
          f"{len(nb) if nb else 0}/{note['filesz']}")
    if not nb or len(nb) != note["filesz"]:
        raise SystemExit(1)

    notes, o = [], 0
    while o + 12 <= len(nb):
        namesz, descsz, ty = struct.unpack_from("<III", nb, o)
        name_off = o + 12
        desc_off = name_off + (namesz + 3) // 4 * 4
        notes.append((ty, nb[desc_off:desc_off + descsz]))
        o = desc_off + (descsz + 3) // 4 * 4
    types = [t for t, _ in notes]
    print(f"  notes: {[hex(t) for t in types]}", flush=True)

    prstatus = next((d for t, d in notes if t == NT_PRSTATUS), None)
    check("a crashing thread's registers are present", prstatus is not None)
    if prstatus is None:
        raise SystemExit(1)
    pc, = struct.unpack_from("<Q", prstatus, PR_REG_OFF + PC_SLOT * 8)
    check("the register block is not zeroed", any(prstatus[PR_REG_OFF:PR_REG_OFF + 200]),
          f"pc={pc:#x}")

    ftab = next((d for t, d in notes if t == NT_FILE), None)
    check("the mapping table names the objects that were mapped", ftab is not None)
    files = []
    if ftab:
        count, psize = struct.unpack_from("<QQ", ftab, 0)
        names = ftab[(2 + 3 * count) * 8:].split(b"\0")
        for i in range(count):
            s, e, pg = struct.unpack_from("<QQQ", ftab, (2 + 3 * i) * 8)
            files.append((s, e, pg, names[i].decode("utf-8", "replace") if i < len(names) else ""))
        for f in files[:12]:
            print(f"    {f[0]:#014x}-{f[1]:#014x} pgoff={f[2]} {f[3]}", flush=True)
        check("the mapping table has entries", count > 0, f"{count} mappings, page size {psize}")
        check("every entry names a path", all(f[3] for f in files))

    seg = next((p for p in loads if p["vaddr"] <= pc < p["vaddr"] + p["memsz"]), None)
    check("a PT_LOAD covers the crashing program counter", seg is not None)
    if seg is None:
        raise SystemExit(1)
    print(f"  crash segment: vaddr={seg['vaddr']:#x} filesz={seg['filesz']:#x} "
          f"memsz={seg['memsz']:#x} flags={seg['flags']}", flush=True)
    delta = pc - seg["vaddr"]
    check("that PT_LOAD carries the faulting instruction's bytes", delta + PROBE_BYTES <= seg["filesz"])
    if delta + PROBE_BYTES > seg["filesz"]:
        raise SystemExit(1)

    got = fetch(CORE, seg["off"] + delta, PROBE_BYTES)
    check("the bytes read back out of the core", bool(got) and len(got) == PROBE_BYTES)
    if not got or len(got) != PROBE_BYTES:
        raise SystemExit(1)
    print(f"  core[pc..pc+{PROBE_BYTES}] = {got.hex()}", flush=True)
    check("they are not a zero-filled hole", any(got))

    obj = next((f for f in files if f[0] <= pc < f[1]), None)
    check("the mapping table names the object the program counter is in", obj is not None,
          obj[3] if obj else "")
    if obj:
        file_off = obj[2] * PAGE + (pc - obj[0])
        want = fetch(obj[3], file_off, PROBE_BYTES)
        print(f"  {obj[3]}[{file_off:#x}] = {want.hex() if want else '<unread>'}", flush=True)
        check("the dumped text is the program's own instructions", got == want)
finally:
    open(SERIAL, "wb").write(bytes(buf))
    print(f"guest-coredump-check: serial transcript in {SERIAL} ({len(buf)} bytes)", flush=True)
    try:
        conn.close()
    except OSError:
        pass
    qemu.terminate()
    # `make` is not QEMU's parent process group, so terminating it leaves the
    # guest running and holding a write lock on the disk image every later run
    # needs. The launcher drops a pidfile for exactly this.
    pidfile = f"target/builds/default/qemu-{'x86_64' if ARCH == 'x86' else 'aarch64'}.pid"
    try:
        os.kill(int(open(pidfile).read().strip()), 9)
    except (OSError, ValueError):
        pass

if failures:
    print(f"guest-coredump-check: FAIL — {', '.join(failures)}", flush=True)
    sys.exit(1)
print("guest-coredump-check: PASS", flush=True)
