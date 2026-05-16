# state — hand-off

Branch: main (clean). spec-lint clean, 1049 tests pass, both arches build.
Shell still works end-to-end per prior session.

## This session

1. **F82 (#1114) — mknodat + symlinkat write-side.** New ext4 helpers
   `Mount::create_symlink` (fast-inline ≤60B; slow path via
   `append_block` + `set_inode_size`) and `Mount::create_mknod`
   (S_IF{CHR,BLK,FIFO,SOCK}; rdev in `i_block[0..4]` for char/block).
   rootfs `symlink_at` / `mknod_at`; namei syscalls
   `sys_symlink` / `sys_symlinkat` / `sys_mknod` / `sys_mknodat`
   replace the EROFS stub. POSIX mknod-with-S_IFREG routes through
   `create_at`. aarch64 ABI: nr 33 fixed (was→133 mknod with shifted
   args; now→259 mknodat); nr 36→266 symlinkat added. +5 hosted tests.

2. **F83 (#1115) — real sys_futex_waitv (slot 449).** Replaces the
   compat ENOSYS arm. New `WAITV_GROUPS` alongside `WAITERS`; each
   group holds N keys + Arc<Task> + AtomicI32 woken_idx. `wake_key()`
   walks both lists; groups fire one-shot via CAS. `dispatch_waitv()`
   does per-key `*uaddr == val` pre-flight, parks, returns index.
   Split into `kernel/src/syscalls/futex_waitv.rs` (proc.rs hit cap).

## All PRs this session

| PR | Branch | Summary |
|----|--------|---------|
| #1114 | F82 | ext4 mknod/symlink write-side + arm ABI fix |
| #1115 | F83 | sys_futex_waitv real impl (multi-key wait groups) |

## Open next (priority order, unchanged from prior session minus F83)

1. **mknodat/symlinkat write-side** ✅ done (F82)
2. **ext4 extent depth > 2** — current write supports depth ≤ 1
   (ExtentTreeFull at 169 GB cap); read supports depth ≤ 2.
3. **O_TMPFILE** — needs orphan-inode list + AT_EMPTY_PATH linkat.
   Non-trivial (multi-day) for full Linux correctness.
4. **futex_waitv** ✅ done (F83)
5. **TLS endgame** — FS_BASE / TPIDR_EL0 setup at execve, per-task
   TLS block allocation (currently relies on arch_prctl post-exec).
6. **#NM-driven lazy FPU save/restore** on context switch (perf).
7. **K10 eBPF verifier + JIT** (multi-PR, large).
8. **K13 DRM/KMS atomic + per-evdev registry** (large).
9. **virtio-net live driver** (types in, not driving an iface yet).
10. **netlink + nftables** = network management substrate.
11. **DHCP / DNS / TLS** = userspace work.

## Investigation backlog

- **qemu-mcp boot hangs at `dl: hello / hello-from-dyn`** before
  reaching `oxide login:`. Pre-existing per [[project_login_hang_cat_smoke]]
  — kernel-spawned smoke ELF `hello_dyn` doesn't return cleanly,
  stalls the smoke loop, init never spawns getty. `make qemu-x86`
  may or may not differ (uses same `--features debug-boot`). Worth a
  bisect after the next clean PR.

## Discipline notes

- spec-lint gate BEFORE `git checkout -b` per
  [[feedback_lint_gate_command]].
- Branch per change; never delete merged branches; no
  Co-Authored-By trailers; PR-time CI is the only soak gate.

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | tail -5
```

Pick from "Open next". Strong candidates: TLS endgame (#5) or #NM
lazy FPU (#6) — both well-scoped, single-PR achievable.
