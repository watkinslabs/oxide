# state — hand-off

Branch: main (clean). K1..K8 closed; K9 mostly already done
(audit text was stale); K12 already done. K5 RT-signal queue +
K10 landlock enforcement + K11 io_uring polish + K13 DRM/KMS +
K14 vDSO + K15 glibc compat all open.

## Closed in this stretch (PRs landed)

- #1022 (F25) K1 ECHOE/ECHOK/ECHONL/ECHOCTL.
- #1023 (F26) K6 file-backed mmap via FileBacking + per-inode
  PageCache.
- #1024 (D05) audit refresh post K1/K2/K6.
- #1025 (F27) K3a O_NONBLOCK plumbing + blocking pipe.
- #1026 (F28) K3b POSIX + OFD record locks.
- #1027 (F29) K4 procfs symlinks.
- #1028 (F30) K5 default-action coredump.
- #1029 (F31) K7 tools/accept.py scenario harness.
- #1030 (D06) audit refresh post K3/K4/K5/K7/K8.
- #1031 (F33) sys_getrandom via RDRAND/RNDR HW RNG.
- #1032 (D07) sweep 'rides v2' / 'out of scope for v1' comments.
- #1033 (F34) PTRACE_SETOPTIONS + GETEVENTMSG real storage.
- D08 (pending) doc sweep: stale ptrace doc-comment fixes.

## Open work per batch

### K5 RT signal queue (32..64)

Per-task `sigpending: AtomicU64` collapses multiplicity. Convert
to standard bitmap (1..31) + per-RT-signal queue<(siginfo_t,
sigval_t)> for 32..64. Update every `sigpending.fetch_or` site
(~25 across the tree) so RT signals are queued, not merged.

### K9 ptrace control (partial gap)

GETSIGINFO/SETSIGINFO/INTERRUPT/LISTEN/GETFPREGS/SETFPREGS still
silent-0. SETSIGINFO needs a per-task last-siginfo slot wired
into the signal-delivery path; GETSIGINFO reads it. FPREGS needs
per-arch FP frame access (FXSAVE / NEON V regs).

### K10 landlock enforcement

`landlock_add_rule` / `landlock_restrict_self` return EOPNOTSUPP.
Real impl needs a per-task ruleset chain checked on every path-
based syscall (openat, unlinkat, renameat, …).

### K10 eBPF verifier + JIT

`fs::bpf` admits cBPF program loads; eBPF verifier (range/type
analysis) + per-arch JIT are open.

### K13 DRM/KMS + input

virtio-gpu scanout works; full DRM ioctl set (DRM_IOCTL_MODE_*),
KMS atomic modesetting, evdev `/dev/input/event*` from
virtio-input are open.

### K14 vDSO

Per-arch tiny ELF (clock_gettime / getcpu fast paths) mapped
into every user AS at execve.

### K15 glibc compatibility surface

Beyond musl: anything glibc-specific not yet covered by the
~200 wired syscalls. Discovered ad-hoc as glibc-linked
binaries fail.

## First task next session

K5 RT signal queue: design `Task.sigpending: SignalState` enum
with `Standard(AtomicU64)` and `Rt(Spinlock<[VecDeque<SigInfo>;
32]>)`. Update every fetch_or site to branch on signal number.
