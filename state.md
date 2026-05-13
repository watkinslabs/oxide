# state — hand-off

Branch: B22-sig-deliver-mask-and-arm-offset (open, push next)
Previous: B21-ext4-lazy-bytes → PR #1017 merged

## What just landed

### B21 (PR #1017)
- `Ext4FileInode` is lazy: `wrap_file()` no longer reads all bytes;
  reads load on first `read()` only. Killed the 1.2 MiB-per-stat
  blowup on ARM busybox PATH probes.
- Real `sys_newfstatat` (`kernel/src/syscalls/newfstatat.rs`) —
  per-arch struct stat (x86=144 B, arm=128 B). `NR_NEWFSTATAT`
  dispatch was previously routed to `sys_statx`, which mis-reads
  args (a2=flags vs a2=statbuf) and corrupted userspace memory.

### B22 (current, not yet PR)
Three coupled signal-dispatch bugs that wedged ARM init in a
recursive SIGCHLD storm:
1. **No mask on handler entry** — POSIX requires the delivered signal
   be blocked during its own handler. We weren't doing it, so SIGCHLD
   re-fired nested inside busybox-init's handler and each nested
   frame stomped on the outer handler's saved x19/x20. x19 eventually
   loaded `SIG_FRAME_MAGIC` and faulted at the next `strb [x19]`.
2. **rt_sigreturn_arm offset bug** — was `cur_sp - 40`, should be
   `cur_sp - 32`. ARM `ret` doesn't pop the stack like x86 `ret`;
   copied offset was wrong from the start.
3. **SIG_FRAME_BYTES 40 → 48** — keeps handler-entry SP 16-byte
   aligned per AAPCS64 and makes room for the new saved-sigmask slot.

## Status

Both arches boot to `oxide login:`. ARM lockstep with x86 restored
end-to-end on the init path.

## First task next session

1. Push B22, open PR.
2. ARM login interaction smoke: `root`, then run `uname -a`,
   `ls /`, `ps`, etc. — verify the originally-reported "Permission
   denied" on bare-name PATH exec is gone end-to-end.
3. Stray SIGSEGV from a child task during ARM boot (tid=4112,
   far=00007ffffffbf000) — boot continues but the fault deserves
   investigation when it surfaces in real workloads.
