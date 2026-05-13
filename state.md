# state — hand-off

Branch: B22-sig-deliver-mask-and-arm-offset (PR #1018, awaiting merge)
Previous: B21-ext4-lazy-bytes → PR #1017 merged

## ARM end-to-end verified

`make qemu-arm` boots to `oxide login:`. Logging in as `root` and
running the originally-broken bare-name PATH commands now works:

```
oxide:~# uname -a
Linux oxide 5.15.0-oxide #1 SMP PREEMPT oxide v0.1.0 aarch64 GNU/Linux
oxide:~# ls /
bin dev etc hello.txt home init lib lib64 lost+found proc
root run sbin sys tmp usr var
oxide:~# ps
PID   USER     TIME  COMMAND
    1 root      0:00 init
```

The "Permission denied" report that motivated the B21+B22 chain is closed.

## Closed in this stretch

### B21 (PR #1017, merged)
- `Ext4FileInode` lazy: `wrap_file()` no longer reads all bytes;
  reads load on first `read()`. Killed 1.2 MiB-per-stat blowup on
  ARM busybox PATH probes.
- Real `sys_newfstatat` (`kernel/src/syscalls/newfstatat.rs`) —
  per-arch struct stat (x86=144 B, arm=128 B). `NR_NEWFSTATAT`
  previously routed to `sys_statx` which mis-reads args (a2=flags
  vs a2=statbuf) and corrupted userspace memory.

### B22 (PR #1018, open)
Three coupled signal-dispatch bugs that wedged ARM init in a
recursive SIGCHLD storm:
1. **No mask on handler entry** — POSIX requires the delivered
   signal be blocked during its own handler. Without this, SIGCHLD
   re-fired nested inside busybox-init's handler; each nested frame
   stomped on the outer handler's saved x19/x20. x19 eventually
   loaded `SIG_FRAME_MAGIC` and faulted at the next `strb [x19]`.
2. **rt_sigreturn_arm offset bug** — was `cur_sp - 40`, should be
   `cur_sp - 32`. ARM `ret` is a register-indirect branch and does
   NOT pop the stack like x86 `ret`; offset was copied verbatim from
   x86 and never matched ARM reality.
3. **SIG_FRAME_BYTES 40 → 48** — keeps handler-entry SP 16-byte
   aligned per AAPCS64 and makes room for the new saved-sigmask slot.

## First task next session

1. Confirm PR #1018 merged.
2. Open items worth investigation when they surface in real workloads:
   - Stray SIGSEGV from a child task during ARM boot (tid≈4112, far≈0x7ffffffbf000) — boot continues, init survives.
