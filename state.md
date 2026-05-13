# state — hand-off

Branch: B21-ext4-lazy-bytes (PR #1017)
Status: merged work landed; ARM boot still wedges in user space.

## What just landed (PR #1017)
- `Ext4FileInode` is lazy: `wrap_file()` no longer reads all bytes; only `read()` pulls. Fixes 1.2 MiB-per-stat blowup on ARM busybox PATH probes.
- Real `sys_newfstatat` (kernel/src/syscalls/newfstatat.rs) — per-arch struct stat (x86=144, arm=128). `NR_NEWFSTATAT` dispatch was previously sys_statx, which mis-reads args and corrupted userspace.

## Open: ARM init faults pre-login
`make qemu-arm FEATURES=debug-irq` boots through every device, prints
`init-arm: spawned`, then immediately:

```
[FAULT] esr=0000000092000044 ec=0x24 (data-abort-lower-el)
        far=5a555a55deadbeef elr=0000000010070334
        dfsc=translation-l0 W
```

FAR = `SIG_FRAME_MAGIC` exactly (crates/kernel/fs/src/sig_dispatch.rs:36).
elr is inside busybox text (offset 0x70334 — a `strb w27, [x19], #1`
in some buffer-write loop). x19 has the signal magic value.

Theories ranked:
1. Signal delivery firing on init before it can register handlers — but
   `take_lowest_pending` only fires post-syscall, and init shouldn't have a
   handler. (Sanity: instrument deliver_arm with kinfo regardless of feature.)
2. build_user_stack writing the magic into argv/auxv unintentionally —
   grep says no, but worth double-checking the random16 / platform auxv slots.
3. SvcFrame leakage between smoke task → init task (same syscall stack reused).

## First task next session
1. Add an unconditional klog probe at the top of `deliver_arm` (not under
   debug-sched). Re-run with `FEATURES=debug-irq`. If the probe fires
   pre-fault, that's theory 1.
2. If not, dump init's user stack around saved_sp at first syscall (a klog
   in syscall entry printing sp_el0 + first 64 bytes).
