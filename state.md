# state.md — session handoff

## Headline
Driving **G19 glibc-on-kernel integration** (docs/59§6) + the Linux-correct
console/serial fix that unblocked it. Branch series `P17-NN` (tty+login phase,
index-tracked). glibc-ABI libc (`crates/user/glibc`) + rtld (`crates/user/ldso`)
now LOAD AND RUN on the oxide kernel, both arches.

## Landed this session (merged to main)
- **P17-12 (#2013)** `/dev/console` follows the `console=` cmdline (Linux 5:1):
  console crate's serial-vs-VT split routed /dev/console to the video VT, so
  `oxide login:` never reached serial → boot-smoke hung at getty on BOTH arches
  (masked by SKIP_SMOKE doc pushes). Fixed: `cmdline::preferred_console()` (last
  `console=` wins), `console::system_console_inode()` for /dev/console + init
  fd0/1/2, default cmdline `console=tty0 console=ttyS0`. Also fixed the aarch64
  vdso build path (broke after the vdso→crate move).
- **P17-13 (#2014)** G19b: glibc smoke runs on x86 kernel. Two staging bugs:
  `debugfs write` exits 0 on failure (unit dropped because /usr/lib/systemd/
  system didn't exist yet → mkdir parents first); unit wired via the wrong
  wants dir → `Wants=g19smoke.service` on the Oxide Default Target.
- **P17-14 (#2015)** G19c: glibc smoke runs on aarch64. Fixed ucontext/aarch64
  ldp/stp offset >504 build error (+ the stp-packs-8-not-16 vreg bug) via x1
  base + individual str/ldr. Generalized the g19 build/stage to both arches.
- **P17-15 (#2016)** glibc stdio/malloc/string kernel test (both arches):
  snprintf, malloc/realloc, string, full FILE path (fopen/fprintf/fclose).
- **B129 (#2012)** netfilter parallel-test flake (was the real CI-red) + glibc
  math clippy correctness.

- **P17-16 (#2017)** pthread-on-kernel test: clone/TLS/futex-mutex/join.
- **P17-17 (#2018, MERGING)** `fix(clone)`: aarch64 ctid/tls arg order
  (CLONE_BACKWARDS). clone arg order is per-arch — x86 `(…,ctid=a3,tls=a4)`,
  arm `(…,tls=a3,ctid=a4)`. Dispatcher used x86 order everywhere → arm
  `clear_child_tid` got the TLS value → thread-exit CHILD_CLEARTID FUTEX_WAKE
  hit the wrong addr → `pthread_join` hung forever on arm. Fixed in
  dispatch.rs (arch-select ctid/tls). **Verified both arches**: full glibc
  pthread (4-thread futex-mutex contention + join) passes on arm now.
  Diagnosed via `g19_glibc_jointest` (join-isolation, now a regression test).

## SMP status (task #6 — effectively done)
- x86 SMP=2 flaky-login race: **NOT reproducible** (5/5 clean tcg boots) —
  already fixed by prior work.
- The real concurrency bug was the arm clone/pthread hang above (fixed).

## Verify gates / how to boot
- **x86**: `OXIDE_QEMU_KVM=1 timeout 240 cargo run -q -p xtask -- grub --arch
  x86_64 --smp 1 > /tmp/b.log 2>&1` (foreground, single line, KVM ~20s to login).
  grep the log for markers. rc=124 = booted+timed-out = good.
- **arm boot infra gotcha (THIS dev box)**: the standard `-bios ovmf-aarch64.fd`
  OVMF (retrage nightly) STALLS in DXE under TCG here — never reaches GRUB. The
  repo's qemu path is UNCHANGED (works on the user's infra). For LOCAL arm
  verification only, boot the built ISO via the Fedora EDK2 **pflash** firmware
  (known-good): `-drive if=pflash,unit=0,file=/usr/share/edk2/aarch64/
  QEMU_EFI-silent-pflash.raw,readonly=on -drive if=pflash,unit=1,file=<copy of
  vars-template-pflash.raw>` + the ISO + root/home virtio-blk disks. ~5-7 min
  TCG to login. Do NOT change the repo firmware/image_qemu.rs (user directive).
- **NEVER `pkill -f qemu-system`** in a multi-step shell command — `-f` matches
  the pkill command's OWN cmdline, `-9` kills the parent shell before the next
  step runs (cost hours of "no log" confusion). Use `pkill -x qemu-system-<arch>`
  (exact process name) or just don't pkill (single-line foreground boots are clean).
- rootfs staging changes need a cache MISS: `rm -f target/rootfs-cache/*<arch>*`.
- glibc host conformance: `cargo run -q -p xtask -- glibc-test` (114/114).

## Next (first task)
1. Finish P17-16: confirm arm pthread markers (g19p-*), commit + PR + merge.
2. **SMP** (user-requested, task #6): the x86 SMP=2 flaky-login race (qemu MCP
   docs: repros under `accel=tcg smp=2`, never kvm) + AP bring-up timing. Repro
   with `--smp 2` tcg, fix root cause the Linux way (no hacks), both arches
   boot SMP=2 to login.
3. G19d (task #4): migrate init/userspace probes musl→glibc; G19final retire musl.

## Notes
- glibc 2.34+ folds pthread/dl/rt into libc.so.6 (our libc exports
  pthread_create etc.); folded stubs (libpthread.so.0…) → libc.so.6.
- The g19 oneshot (`g19smoke.service`, Before=console-getty) runs all three
  glibc-on-kernel bins before login so markers land on serial.
- Tasks tracked in the TaskList (1-3,5 done/in-progress; 4,6 pending).
