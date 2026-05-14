# state — hand-off

Branch: B21-ext4-lazy-bytes (PR #1017)
Status: merge conflict with main resolved; B21 code still present; ARM boot still wedges in user space.

## What just landed on this branch
- `Ext4FileInode` is lazy: `wrap_file()` no longer reads all bytes; only `read()` pulls. Fixes 1.2 MiB-per-stat blowup on ARM busybox PATH probes.
- Real `sys_newfstatat` (`kernel/src/syscalls/newfstatat.rs`) — per-arch `struct stat` (x86=144, arm=128). `NR_NEWFSTATAT` previously dispatched to `sys_statx`, which mis-read args and corrupted userspace.
- Merged `origin/main`; the only conflict was this hand-off file.

## Open: ARM init faults pre-login
`make qemu-arm FEATURES=debug-irq` boots through every device, prints
`init-arm: spawned`, then immediately:

```
[FAULT] esr=0000000092000044 ec=0x24 (data-abort-lower-el)
        far=5a555a55deadbeef elr=0000000010070334
        dfsc=translation-l0 W
```

FAR = `SIG_FRAME_MAGIC` exactly (`crates/kernel/fs/src/sig_dispatch.rs:36`).
elr is inside busybox text (offset `0x70334`, `strb w27, [x19], #1`). x19 has the signal magic value.

## Theories ranked
1. Signal delivery fires on init before handler registration; sanity-check by logging unconditionally at `deliver_arm` entry.
2. `build_user_stack` leaks the magic into argv/auxv; re-check random16 and platform auxv slots.
3. `SvcFrame` state leaks from smoke task to init task.

## First task next session
1. Add an unconditional klog probe at the top of `deliver_arm` (not under `debug-sched`). Re-run with `FEATURES=debug-irq`.
2. If that probe does not fire, dump init's user stack around `saved_sp` at first syscall entry.
