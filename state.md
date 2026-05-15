# state — hand-off

Branch: main (clean). K1..K8 closed (substrate). K9..K15 open.

## Closed in this stretch (PRs landed)

- #1022 (F25) K1 console termios echo flags — ECHOE/ECHOK/
  ECHONL/ECHOCTL added; DEFAULT_LFLAG matches `stty sane`.
- #1023 (F26) K6 file-backed mmap substrate — `FileBacking`
  trait + per-inode `PageCache` + demand-page File arm.
- #1024 (D05) audit refresh post K1/K2/K6.
- #1025 (F27) K3a O_NONBLOCK plumb — `Inode::read_nonblock`/
  `write_nonblock`; pipe blocks via WaitList; CLOSE_HOOK
  multi-slot registry.
- #1026 (F28) K3b POSIX + OFD record locks — `fs::posix_lock`
  per-inode range list, F_SETLK/SETLKW/GETLK + F_OFD_*.
- #1027 (F29) K4 procfs symlinks — `/proc/self/{exe,cwd,root}`
  + `/proc/self/fd/<n>` real Symlink inodes via
  `procfs::proc_links`; `Inode::readlink` default-impl.
- #1028 (F30) K5 default-action coredump — fatal SIG_DFL signals
  route through `fs::coredump`.
- #1029 (F31) K7 acceptance harness — `tools/accept.py` drives
  QEMU + serial against `scenario.sh` files.
- D06 (next merge) audit refresh post K3/K4/K5/K7/K8.

## K9..K15 open

- K9 ptrace: register slab + scheduler stop-state integration
  (peek/poke is real, control is stubs).
- K10 bpf+seccomp+landlock: cBPF/eBPF verifier+JIT; full
  seccomp_unotify; landlock ruleset chains.
- K11 io_uring: SQE/CQE rings; IORING_OP_* set.
- K12 SysV IPC + POSIX MQ: largely done; audit for gaps.
- K13 DRM/KMS + input subsystem.
- K14 vDSO per-arch ELF mapped into every user AS.
- K15 glibc compatibility surface.

## RT signal queue (K5 open)

Per-task `sigpending: AtomicU64` collapses RT-signal multiplicity.
Convert to a bitmap + per-RT-signal queue<(siginfo_t, sigval_t)>;
update every site that does `sigpending.fetch_or(1 << bit)`.

## First task next session

K9 ptrace control: add per-task `ptrace_stop_state` to Task;
park on PTRACE_ATTACH / SYSCALL stop; wake on PTRACE_CONT.
Per-arch `struct user_regs_struct` materialization from the
saved syscall/IRQ frame for PTRACE_GETREGS/SETREGS.
