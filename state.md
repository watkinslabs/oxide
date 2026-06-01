# Session hand-off

## Headline
**systemd 259 PID1 EXECUTES on oxide, BOTH arches** (F349 #1466: `/lib/systemd/systemd
--version` → "systemd 259 (259) +SECCOMP +OPENSSL +ACL +BLKID +IDN2 +KMOD +PCRE2 +SYSVINIT"
rv=0, x86 + arm). L2 tree complete (17 deps) + arm catchable-SIGILL kernel fix (F347).
Branch: `main` clean @ #1466. Now: **F350 — run systemd AS INIT.**

## D6 systemd progress (merged)
- #1461 scaffold, #1462 acl/util-linux .pc, #1463 x86 libs, #1464 F348 libs both arches +
  systemd_probe rv=0, #1465 PID1+systemctl+libsystemd-core build both arches, #1466 F349
  stage + run PID1 (--version rv=0 both arches).
- Build: `vendor/systemd/build.sh` (meson cross, both arches). `gen-pc.sh` writes L2 .pc.
  All musl gaps fixed (research/systemd-build.md): nss.h shim; statx backport into arm cross
  musl sys/stat.h + statx() syscall wrapper (arm c_link_args); global L2 includes in c_args;
  arm -rpath-link for transitive libcrypto; util-linux .pc subdirs; acl EXPORT-strip;
  compression+gcrypt+gshadow disabled. Staged via l2_deps::SYSTEMD_STAGE + mkdir /lib/systemd.

## Open work
1. **F350: systemd as init.** Stage minimal units (default.target→basic.target→sysinit.target;
   a serial-getty@ttyS0.service or debug shell). Add a boot path to exec /lib/systemd/systemd
   as PID1 (kernel cmdline init= OR an rcS `exec` test first). Surfaces KERNEL gaps (mount
   cgroup2/proc/sysfs/devtmpfs, sd-event epoll, signalfd, timerfd, /dev/kmsg, /proc/1,
   SCM_CREDENTIALS, mount propagation — most built in Track K). Fix each gap IN-PR. Incremental:
   first get systemd PID1 to start + reach a basic target / spawn a getty.
2. **Fix the pre-push hook gate gap (quick B-fix).** `.githooks/pre-push` skips smoke for
   tools/xtask changes ("no kernel/userspace/arch changes"), but tools/xtask/src/* (l2_deps,
   main.rs, oxide-smokes.sh) ALTER the rootfs → must gate. F349 pushed un-gated (verified arm
   manually). Add `tools/xtask/` + `vendor/` to the hook's boot-relevant path set.
3. Low-pri: x86 #UD→catchable-SIGILL parity mirror (hal-x86_64/fault.rs); no-handler SIGILL
   wstatus 11→4.

## First command (next session)
F350: build/stage minimal systemd units + attempt `/lib/systemd/systemd` as init; OR first
the quick pre-push hook gate-gap fix.

## CRITICAL harness rules
- Both-arch gate via backgrounded PLAIN `git push` (run_in_background+dangerouslyDisableSandbox;
  `git push 2>FILE; echo PUSH_DONE rc=$?>>FILE`). rc=0=pass. rc=141/"closed" but gate PASSED →
  re-push `SKIP_SMOKE=1`. **NOTE: hook skips smoke for tools/xtask-only changes** → verify both
  arches MANUALLY (controlled boots) for rootfs-affecting tools/xtask changes until fix #2 lands.
- "host forwarding tcp::2222" → stale qemu squats port → clear (ss 2222/1234 + pgrep
  `system-aarch64`/`system-x86_64` pid; NEVER `pkill -f qemu`=self-kill). ALWAYS kill local
  verify-boot qemu by port+pid after each boot.
- Watch rootfs free (`dumpe2fs`); arm now ~68/128 MiB. spec-lint clean before commit/PR.
  `main.rs` AT the 1000-line cap (refactor before edit). Branch per change (BRANCH FIRST, not
  main); revert dirtied `kernel/blobs/rootfs-*.img` before commit; explicit `git add <paths>`.
