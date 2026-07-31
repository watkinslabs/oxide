# state.md — session hand-off

Main `60ddaa565`, clean: 0 open PRs, both arches boot, **GNOME reaches a
registered session**. 28 PRs merged this session.

## Headline: GNOME boots

Two kernel bugs were blocking the desktop. Both fixed and merged.

| Bug | PR | Effect |
|---|---|---|
| `/proc/self` bound to tid 0 | #4267 | The inode existed so `open` succeeded, but every read/write returned ENOENT. systemd writes `/proc/self/oom_score_adj` at its OOM_ADJUST exec step on *every* spawn, so udevd, journald, dbus-broker, rtkit, accounts-daemon and upower all died there. `/proc/self` and `/proc/thread-self` are now magic symlinks resolved at readlink time. |
| x86_64 `clone(2)` used arm64's argument order | #4269 | arm64 selects `CONFIG_CLONE_BACKWARDS`; x86_64 does **not** (the `select` at `arch/x86/Kconfig:16` is inside `config X86_32`). `CLONE_SETTLS` therefore took FS_BASE from the `child_tid` register — glibc passes `&pd->tid` — displacing every thread's static TLS by `0x2d0`, so `__ctype_init` dereferenced a NULL locale pointer. Every threaded glibc daemon SEGV'd. Regression introduced the same day by #4246. |

Boot now: 0 core dumps, `graphical.target` reached, gdm-autologin opens the
oxide session, gnome-keyring starts, session registers with GDM at ~30s.

## Open: `user@1000.service` (lane `B1608-user-manager-fails` in flight)

`systemd --user` exits **status=1 in 176ms**, no core dump — a deliberate exit
after an early check fails. Consequence: no per-user systemd instance and no
user D-Bus, so `gnome-session-binary` reports `NameHasNoOwner:
org.freedesktop.systemd1` and falls back to the non-systemd startup procedure.
The desktop is therefore degraded, not properly managed. A `camera` unit also
still fails (lower priority).

Suspects worth checking before guessing: cgroup v2 delegation for the user
slice, `/run/user/1000` semantics, `/proc/self`-derived paths systemd uses
(`/proc/self/fd`, readlink results), and errnos from its early sandbox probes.

## Syscall compliance matrix (`scratch/syscall-compliance-matrix.md`)

PARTIAL 194 → **110**; IMPL 250/385. Rows are annotated per merge with what was
actually wrong, not just "done".

Defect pattern that dominated: **correct code nothing calls.** `kill_fasync`
had no production caller so `O_ASYNC` was inert kernel-wide; `rq->nr_running`
excluded the running task so every CPU advertised load 0 and nothing ever
migrated; user-namespace id translation had zero callers; readahead was
computed faithfully and discarded at all three call sites; `RLIMIT_NPROC` and
`RLIMIT_MEMLOCK` were enforced nowhere.

## Next up

1. Finish `user@1000` (B1608).
2. Then the remaining 110 PARTIAL rows — largest clusters are the socket
   family (54/55 still owe ~8 `ENOPROTOOPT` options), ptrace 101, mount 165/166.
3. Named subsystem gaps, each needing its own lane: SCHED_DEADLINE has no
   scheduling class; RSS accounting does not exist (blocks `ru_maxrss` and
   `VmRSS`); atime policy has zero call sites; synthetic filesystems use ordinal
   readdir cursors; FUSE has no fsync slot.

## Traps that cost real time today

- **`make smoke-*` must run with the sandbox disabled.** Otherwise boot-smoke
  cannot reap its own QEMU; the leak locks `root-<arch>.img` and the next
  attempt fails with *zero kernel output*, which reads exactly like a boot
  failure. Three attempts died to this. Now in CLAUDE.md (#4260).
- **Kernel-gated files are invisible to `cargo test`.** #4265 merged with a
  green 4934-test run while `xtask kernel` failed on six `SigInfo` initializers
  in `#[cfg(target_os)]` files. Fixed forward in #4266. Always build both
  kernel targets before trusting a merge.
- **Check the enclosing `config` block before believing a Kconfig grep.** A
  bare `grep 'select CLONE_BACKWARDS' arch/x86/Kconfig` hits a line owned by
  `config X86_32`. That mis-verification killed a branch that had the clone
  fix right, and cost a whole extra lane.
