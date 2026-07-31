# state.md — session hand-off

Main `10c213ec8`, clean: 0 open PRs, both arches boot, **GNOME boots with
working mouse and keyboard**, 0 failed units, 0 core dumps. 40 PRs merged.

## Headline: the desktop works

Four kernel bugs stood between the tree and a usable GNOME session. All fixed.

| Bug | PR | Effect |
|---|---|---|
| `/proc/self` bound to tid 0 | #4267 | The inode existed so `open` succeeded, but every read/write returned ENOENT. systemd writes `/proc/self/oom_score_adj` at its OOM_ADJUST exec step on *every* spawn, so udevd, journald, dbus-broker, rtkit, accounts-daemon and upower all died there and gdm never ran. Now a magic symlink resolved at readlink time, with `/proc/thread-self`. |
| x86_64 `clone(2)` used arm64's argument order | #4269 | arm64 selects `CONFIG_CLONE_BACKWARDS`; x86_64 does **not** — the `select` at `arch/x86/Kconfig:16` is inside `config X86_32`. `CLONE_SETTLS` took FS_BASE from the `child_tid` register (glibc passes `&pd->tid`), displacing every thread's static TLS by `0x2d0`, so `__ctype_init` dereferenced a NULL locale pointer. Every threaded glibc daemon SEGV'd. |
| procfs had no `dentry_operations` | #4271 | `/proc/<pid>` inodes cached ownership from first lookup. systemd's child walked its own `/proc/<pid>/fd` as root, then `setresuid(1000)` and got EACCES from `opendir` — `user@1000.service` exited 1, leaving gnome-session in degraded fallback with no user D-Bus. Now `pid_revalidate`/`pid_delete_dentry` via a new `InodeOps::child_d_op`. |
| epoll/evdev inode-number collision | #4272 | Both used base `0x7400_0000`, so `/dev/input/event0` decoded as an epoll instance and the epoll ioctl handler claimed every evdev ioctl, answering EINVAL. libinput asks `EVIOCGBIT(0)` first, concluded the devices were unusable, and never read them: live compositor, dead input. |

## Defect classes worth checking at review

These each bit more than once, and naming them made the next one faster to find.

1. **Correct code nothing calls.** `kill_fasync` had no production caller so
   `O_ASYNC` was inert kernel-wide; user-namespace id translation had zero
   callers; readahead was computed and discarded at all three call sites;
   `RLIMIT_NPROC`/`RLIMIT_MEMLOCK` were enforced nowhere; atime policy still
   has zero call sites.
2. **Identity inferred instead of owned.** #4273 swept the class: `/dev/console`
   and `/dev/tty1` shared one `st_ino`; every signalfd shared one; socket ids
   came from reused heap addresses; `fbdev` masked only the low half of the ino
   so ~1 socket in 65536 reached the framebuffer ioctl handler. Identity now
   comes from `i_private`, and `vfs::pseudo_ino` owns the number space with a
   compile-time disjointness assertion.
3. **Large values on a 16 KiB stack.** Four instances: `VirtioInputDev` 3440 B
   by value (#4275), 21 driftsort scratch frames at 4160 B each (#4276), a TCP
   child built by value on the delivery frame (#4279), and **two** copies of the
   3528-byte child `Task` on the parent's stack (#4280). Linux heap-allocates
   each of these and passes a pointer. `make stack-gate` now catches it at build
   time.

## Gates that now exist (and one that never ran)

- `make smoke-mouse` — injects virtio input over QMP and asserts real event
  counts. Both arches PASS. Input regressions are now caught.
- `make smoke-virtio-input-rebind` — PASS both arches as of #4281.
- `stack-gates` CI job — runs `stack-depth-gate.py` and `frame-size-gate.py`.
  The latter **was not in CI at all** and both its baselines were empty.

## Open: the gate under-reports blocking paths (lane B1621 in flight)

`schedule()` costs x86_64 3016 B / aarch64 **4608 B**, and the walker cuts that
cycle so it is added to no reported depth. aarch64 `sys_sendmmsg` reports
12880 but would be 17488 against a 16384 B stack if it blocks at max static
depth — the gate says PASS on a path that can overflow. B1621 is making the
accounting honest first, then fixing what it exposes.

## Syscall compliance matrix (`scratch/syscall-compliance-matrix.md`)

PARTIAL 194 → **110**; IMPL 250/385. Rows annotated per merge with what was
actually wrong.

## Next up

1. Finish B1621 (blocking-path stack accounting + the aarch64 net arm).
2. The remaining 110 PARTIAL rows — largest clusters: socket 54/55 (~8 options
   still `ENOPROTOOPT`), ptrace 101, mount 165/166.
3. Named subsystem gaps, each its own lane: SCHED_DEADLINE has no scheduling
   class; **RSS accounting does not exist** (blocks `ru_maxrss`, `VmRSS`); atime
   policy has zero call sites; synthetic filesystems use ordinal readdir
   cursors; FUSE has no fsync slot.
4. Flagged, unowned: `packet::deliver` holds `Weak::upgrade` temporaries so the
   last drop runs socket teardown from the packet path (Linux's protocol hook
   holds a strong ref released with `synchronize_net()`); journal socket lines
   report a nonsense SCM_CREDENTIALS pid; `parse_proc_path` has no production
   callers.

## Traps that cost real time

- **`make smoke-*` must run with the sandbox disabled.** Otherwise boot-smoke
  cannot reap its QEMU; the leak locks `root-<arch>.img` and the next attempt
  fails with *zero kernel output*, which reads exactly like a boot failure.
  Also: boot-smoke DELETES its log on completion, and the log path it prints is
  the one to copy while the boot is live.
- **Kernel-gated files are invisible to `cargo test`.** #4265 merged with 4934
  hosted tests green while `xtask kernel` failed on six `SigInfo` initializers
  in `#[cfg(target_os)]` files. Always build both kernel targets before trusting
  a merge.
- **Check the enclosing `config` block before believing a Kconfig grep.**
  `grep 'select CLONE_BACKWARDS' arch/x86/Kconfig` hits a line owned by
  `config X86_32`. That mis-verification cost a lane and a wrongly-dropped branch.
- **A leaf symbol is not a cause.** The #4275 overflow reported `vt_console_sink`
  on x86 and `ArmMmu::map` on aarch64 — two different leaves on one failure means
  the stack was already gone. Chasing the leaf wasted a lane.
