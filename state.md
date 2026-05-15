# state — hand-off

Branch: main (clean). K1..K9 closed (substrate + extensions);
K11/K12 already done; K15 partial. K10 landlock-enforce + eBPF
JIT, K13 DRM/KMS user bring-up, K14 vDSO ELF, K15 TLS / versioned
symbols remain.

## Closed this session (18 PRs)

| PR | Branch | Summary |
|----|--------|---------|
| #1022 | F25 | K1: ECHOE/ECHOK/ECHONL/ECHOCTL on /dev/console |
| #1023 | F26 | K6: file-backed mmap via FileBacking trait + per-inode PageCache |
| #1024 | D05 | audit refresh post K1/K2/K6 |
| #1025 | F27 | K3a: O_NONBLOCK plumb (Inode::read_nonblock/write_nonblock) + blocking pipe via WaitList |
| #1026 | F28 | K3b: POSIX + OFD record locks (fs::posix_lock) |
| #1027 | F29 | K4: /proc/self/{exe,cwd,root,fd/N} Symlink inodes + Inode::readlink |
| #1028 | F30 | K5: SIG_DFL fatal signals dump core (10-signal expansion) |
| #1029 | F31 | K7: tools/accept.py scenario harness |
| #1030 | D06 | audit refresh post K3/K4/K5/K7/K8 |
| #1031 | F33 | sys_getrandom via RDRAND/RNDR (LCG fallback) |
| #1032 | D07 | sweep "rides v2" / "out of scope for v1" out of code (18 files) |
| #1033 | F34 | PTRACE_SETOPTIONS + GETEVENTMSG real storage |
| #1034 | D08 | sweep stale ptrace doc-comments + state.md |
| #1035 | F35 | K5: RT signal queue (33..64 siginfo_t multiplicity) |
| #1036 | F36 | K9: PTRACE_GETSIGINFO + SETSIGINFO real (siginfo Spinlock slot) |
| #1037 | F37 | K15: IFUNC R_*_IRELATIVE in user dl |
| #1038 | D09 | dl module header sweep post-IFUNC |
| #1039 | D10 (this) | audit refresh post K5/K9/K15 partials |

## Truly-open work

### K10 landlock enforcement

`landlock_add_rule` + `landlock_restrict_self` return EOPNOTSUPP
(intentional honest signal — silent-0 would lie about sandbox
enforcement). Real impl needs: per-task `landlock_chain:
Vec<Arc<Ruleset>>` + check hooks in openat/unlinkat/renameat/
linkat/symlinkat/mknodat/mkdirat (every path-based syscall).

### K10 eBPF verifier + JIT

`fs::bpf` admits cBPF program loads + maps. Real eBPF needs
type/range verifier (the hardest piece) + x86_64/aarch64 JITs.

### K13 DRM/KMS + evdev

virtio-gpu scanout works; full DRM_IOCTL_MODE_* + atomic
modesetting + evdev `/dev/input/event*` from virtio-input
backings.

### K14 vDSO

Per-arch tiny ELF (clock_gettime / getcpu / time) mapped into
every user AS at execve.

### K15 TLS + versioned symbols

PT_TLS init-image + DTPMOD64/DTPOFF64/TPOFF64 relocs; DT_VERNEED/
VERSYM resolution; lazy-PLT via GOT trampoline (currently force
BIND_NOW).

### K9 ptrace tail

PTRACE_GETFPREGS / SETFPREGS need per-arch FP frame access
(FXSAVE area on x86, NEON V regs on arm). PTRACE_INTERRUPT /
LISTEN need real stop-state machinery.

## First task next session

K10 landlock substrate: define `Ruleset { rules: Vec<Rule> }`
where `Rule = (path_glob, allowed_ops_mask)`. `landlock_create_
ruleset` returns memfd-shaped fd carrying it. `restrict_self`
appends to `Task.landlock_chain`. Check hook in `vfs::namei`
walks the chain and denies on first mismatch. Then unhook
EOPNOTSUPP in mod.rs.
