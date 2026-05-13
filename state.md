# State 2026-05-12 (end of long session)

## Branch / PRs

Main is up-to-date through PR #1015 (statx ABI map fix). Seven PRs landed today:

- #1010 — interactive shell on x86 (login + readdir + linker BSS fix + fork+exec).
- #1011 — `ps` shows real Linux PIDs.
- #1012 — ARM EL0 IRQ delivery (VBAR_EL1 slot 0x480, SPSR DAIF mask, GIC level vs edge).
- #1013 — ARM ABI map: faccessat dispatch + sys_access fallback + ext4 perm bits.
- #1014 — sys_statx mask = STATX_BASIC_STATS.
- #1015 — ARM statx ABI map fix (was statx → openat).

## ARM status — what's working, what's not

**Working:**
- Boot to `oxide login:` then root shell.
- Builtins: `echo`, `pwd`, `cd`, `id`.
- Absolute-path fork+exec — `/bin/uname -a` prints `Linux oxide 5.15.0-oxide #1 SMP PREEMPT oxide v0.1.0 aarch64 GNU/Linux`.

**Broken: bare-name PATH search.** `uname`, `ls`, etc. print "Permission denied" without forking.

## Root cause (narrowed)

1. ARM busybox-ash calls **newfstatat** (ARM nr 79 → x86 nr 262), not statx.
2. `NR_NEWFSTATAT` currently dispatches to `sys_statx`, which reads `args.a2` as flags (newfstatat's `a2` is statbuf), and writes the statx struct to `args.a4` (uninitialised for newfstatat callers).
3. Caller's actual statbuf at `args.a2` stays all-zero. busybox reads `st_mode = 0`, `S_ISREG` fails, marks the file inaccessible, eventually prints `"Permission denied"`.
4. Absolute paths work because busybox has a different code path that calls `tryexec`/`execve` directly without the failed stat check.

## What I tried that didn't work

- **Proper `sys_newfstatat` handler** with per-arch `struct stat` layout (x86=144 B, aarch64=128 B). Function is structurally correct (verified via klog probe — it runs and returns valid data for many paths during busybox-init: /sbin/mount, /sbin/hostname, etc.). **But dispatching `NR_NEWFSTATAT` to it makes ARM boot hang silently at "keymap loaded" without reaching `oxide login:`.** Some downstream caller depends on the broken-ABI behavior in a way that isn't visible from klog. Boot hang persists with both `FEATURE_SH_STANDALONE=n` and `FEATURE_PREFER_APPLETS=n` in busybox-aarch64 rebuild — not an applet-dispatch issue.

- **Rebuilt busybox-aarch64** with `FEATURE_PREFER_APPLETS=n` + `FEATURE_SH_STANDALONE=n`. Shell still says "Permission denied" — confirms the dispatch ABI is the bug, not applet routing.

## Concrete next-session recipe

1. Re-add `sys_newfstatat` handler (the one from B17/B18, deleted from main but findable in the conversation log).
2. Hook NR_NEWFSTATAT to dispatch it.
3. Add klog at the END of each rcS line in `vendor/busybox/busybox-1.37.0/examples/init.d/rcS` (we need to identify WHICH rcS step doesn't return).
4. Or attach qemu-mcp + qemu_break at busybox-init's main entry, single-step to find where it diverges from the broken-stat path.
5. Once identified, fix the kernel side (likely a missing syscall, signal handling gap, or AT_EMPTY_PATH special-case for `fstatat(fd, "", AT_EMPTY_PATH)`).

## Followups (not blocking)

- Re-enable fbcon klog aux sink after debugging `fbcon_flush_pixels` virtio-gpu submit wedge.
- `B12-rcS-wedge` parked branch needs review now that core boot works.

## Commits on main (last 7)

```
gh pr list --state merged --limit 7
```
