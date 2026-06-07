#!/usr/bin/env python3
# syscall-audit — coverage checker for the oxide syscall dispatch.
#
# Cross-references every `NR_*` constant in crates/kernel/syscall/src/nrs.rs
# against the live dispatch chain (the big match in
# crates/kernel/syscalls/src/lib.rs + the sub-dispatchers it chains to in its
# default arm: sched::cred/timers, perms, fs::xattr/keyring, and the legacy
# syscall::dispatch table). Reports, per number:
#   ROUTED   — has an `NR_X =>` arm somewhere in the chain (real handler)
#   ENOSYS   — routed to sys_enosys / enosys (deliberate; should match the
#              17 OBSOLETE numbers per docs/15)
#   UNROUTED — a known NR_ constant with no arm → falls through to ENOSYS
#
# Exit non-zero if any non-OBSOLETE number is UNROUTED or ENOSYS, so this can
# gate CI once coverage is complete. Drives the docs/15 "every syscall IMPL"
# sweep + the one-file-per-syscall split (docs/53 §0).
import re, sys, os, pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
NRS = REPO / "crates/kernel/syscall/src/nrs.rs"
# Files that carry `NR_X =>` dispatch arms (the live chain).
DISPATCH_FILES = [
    "crates/kernel/syscalls/src/lib.rs",
    "crates/kernel/syscalls/src/dispatch.rs",
    "crates/kernel/syscalls/src/proc.rs",
    "crates/kernel/syscalls/src/time.rs",
    "crates/kernel/syscalls/src/misc.rs",
    "crates/kernel/syscalls/src/perms.rs",
    "crates/kernel/syscalls/src/select.rs",
    "crates/kernel/syscalls/src/net_recv.rs",
    "crates/kernel/syscalls/src/clone.rs",
    "crates/kernel/syscalls/src/signal_dispatch.rs",
    "crates/kernel/syscalls/src/signal_trace.rs",
    "crates/kernel/syscalls/src/ptrace.rs",
    "crates/kernel/syscalls/src/io_uring.rs",
    "crates/kernel/syscalls/src/hostname.rs",
    "crates/kernel/syscalls/src/uname.rs",
    "crates/kernel/sched/src/cred.rs",
    "crates/kernel/sched/src/timers.rs",
    "crates/kernel/sched/src/compat.rs",
    "crates/kernel/fs/src/xattr.rs",
    "crates/kernel/fs/src/keyring.rs",
    "crates/kernel/syscall/src/dispatch.rs",
]
# 17 OBSOLETE x86_64 numbers (modern Linux ENOSYS's them) per docs/15 legend.
OBSOLETE = {
    134,  # afs_syscall
    174,  # create_module
    176,  # delete_module (note: 176 is delete_module; keep per docs/15)
    178,  # query_module
    167,  # _sysctl? — refined below by name, see docs/15
    183,  # getpmsg/putpmsg group
    184,  # tuxcall
    188,  # security
    205,  # set_thread_area? (kept IMPL on x86) — name-gated below
    214,  # epoll_ctl_old
    215,  # epoll_wait_old
    220,  # ? — placeholder; the precise 17 are name-matched below
}
# Name-based OBSOLETE set is authoritative (numbers vary by arch):
OBSOLETE_NAMES = {
    "afs_syscall","create_module","get_kernel_syms","query_module",
    "getpmsg","putpmsg","tuxcall","security","vserver","nfsservctl",
    "_sysctl","uselib","epoll_ctl_old","epoll_wait_old","sysfs",
    "_newselect","tux",
}

def read(p):
    f = REPO / p
    return f.read_text() if f.is_file() else ""

# 1. all NR_ constants: pub const NR_FOO: usize = 42;
nrs = {}
for m in re.finditer(r"pub const NR_([A-Z0-9_]+)\s*:\s*\w+\s*=\s*(\d+)", read(NRS)):
    nrs[m.group(1)] = int(m.group(2))

# 2. routed: any NR_X *referenced* in a dispatch file routes it. This catches
#    `NR_A | NR_B => h`, `nr if matches!(nr, NR_A|NR_B)` guards, and sub-handler
#    `match nr { NR_X => .. }` forms that a `=>`-anchored regex would miss.
#    Dispatch files only mention NR_ to route it (definitions live in nrs.rs).
routed = set()
enosys_ctx = set()   # NR_ appearing on a line that targets sys_enosys/enosys
for p in DISPATCH_FILES:
    for line in read(p).splitlines():
        names = re.findall(r"\bNR_([A-Z0-9_]+)\b", line)
        if not names:
            continue
        # skip pure comments
        stripped = line.lstrip()
        if stripped.startswith("//") or stripped.startswith("///"):
            continue
        for n in names:
            routed.add(n)
            if "enosys" in line.lower():
                enosys_ctx.add(n)

routed_real, enosys, unrouted = [], [], []
for name, num in sorted(nrs.items(), key=lambda kv: kv[1]):
    if name in routed:
        if name in enosys_ctx:
            enosys.append((num, name))
        else:
            routed_real.append((num, name))
    else:
        unrouted.append((num, name))

def lc(s): return s.lower()
bad = [(n,nm) for (n,nm) in (enosys+unrouted) if lc(nm) not in OBSOLETE_NAMES]

print(f"=== oxide syscall coverage ===")
print(f"NR_ constants:      {len(nrs)}")
print(f"ROUTED (real):      {len(routed_real)}")
print(f"ENOSYS (explicit):  {len(enosys)}")
print(f"UNROUTED (→enosys): {len(unrouted)}")
print(f"OBSOLETE (allowed): {len(OBSOLETE_NAMES)} by name")
print()
if unrouted:
    print("--- UNROUTED (registered NR_ with no dispatch arm) ---")
    for n,nm in unrouted: print(f"  {n:>4}  NR_{nm}")
    print()
if enosys:
    print("--- explicit ENOSYS arms ---")
    for n,nm in enosys: print(f"  {n:>4}  NR_{nm}  -> {routed.get(nm,'')[:40]}")
    print()
print(f"=== {len(bad)} non-OBSOLETE numbers still ENOSYS/UNROUTED (must reach IMPL) ===")
for n,nm in bad[:80]: print(f"  {n:>4}  NR_{nm}")
sys.exit(1 if bad else 0)
