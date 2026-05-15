# state — hand-off

Branch: main (clean). spec-lint clean, 1044 tests pass, both arches build.

## Most recent landed (continuation)

| PR | Branch | Summary |
|----|--------|---------|
| #1093 | F75 | dup3 honour O_CLOEXEC |
| #1094 | F76 | epoll_create1 honour EPOLL_CLOEXEC |
| #1095 | F77 | userfaultfd + pidfd_open honour create-time flags |
| #1096 | F78 | clone3 honour CLONE_PIDFD (write pidfd to user struct) |
| #1097 | B26 | hotfix #1096 missing SAFETY comment |
| #1098 | F79 | mq_open honour O_CLOEXEC + O_NONBLOCK on fd |

Earlier this run: F59..F74, B25, D11..D21 (see prior state for full list).

## Open next

- mknodat/symlinkat: needs ext4 mknod + symlink helpers (S_IFLNK
  recognized in inode.rs but no readlink path)
- #NM-driven lazy FPU save/restore
- TLS endgame: FS_BASE/TPIDR_EL0 at execve + per-task TLS block
- futex_waitv real multi-futex wait substrate
- ext4: dir>4KiB, extent depth>2, symlink read, O_TMPFILE
- K10 eBPF verifier + JIT (multi-PR)
- K13 DRM/KMS atomic + per-evdev registry
- virtio-net live driver
- netlink + nftables = network management substrate

## Discipline notes (added this run)

[[feedback_lint_gate_command]] saved to memory after #1073 and #1096
both needed hotfix branches. The required gate before every commit
chain is:

```
cargo run -p xtask -- spec-lint 2>&1 | tail -1 | grep -q "^spec-lint: clean$"
```

If that returns non-zero, do NOT create the branch.

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | tail -5
```
