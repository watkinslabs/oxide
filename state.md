# Handoff — sysinit pivot_root deadlock BROKEN; boot advances 90s→573s

Main = `66c1c7e7` (+ C107 ext42.md→scratch merged). Goal: console login → live-gnome.
This session: 4 PRs merged (#2895 #2896 #2897 #2898).

## ★★ BREAKTHROUGH: the multi-session sysinit pivot_root deadlock is FIXED (B685/#2895)
Every service using mount-namespacing (`ProtectSystem=` etc.) deadlocked sysinit at
`pivot_root -EINVAL`. THREE Linux-correctness bugs, all fixed + boot-verified:
1. **Bind inherited SOURCE peer group** (`165_mount.rs`): binding the shared open_tree
   clone of `/` made the service rootfs SHARED → pivot EINVAL. Linux `do_loopback`
   clones flag 0 (never a peer of source). Removed `join_peer_group(target, src_pg)`.
2. **Overmount on ns root invisible** (`vfs mount/model.rs`): `mount_exact_at`/
   `mount_at_path_exact` short-circuited `is_ns_root_dentry` → underlay root, ignoring a
   stacked mount. After `pivot_root(.,.)` the old root is stacked on `/`; `umount2(.,
   MNT_DETACH)` returned 0 → EINVAL. Now check for overmount first (Linux `lookup_mnt`).
3. **`umount2(".")` used STALE cwd string** (`166_umount2.rs`): after pivot relocates the
   mount the cwd string is stale. Resolve relative targets via live `cwd_vfs` dentry
   (same fix chroot(2) already had).
Boot proof: PIVOT-EINVAL gone, `umount2(.) rv=0`, journald/udev/sysctl/tmpfiles now
START; boot reaches 573s (was hard-deadlock ~90s).

## Comprehensive FS/mount harness built (B686/#2896, B687/#2897) — the "does the FS work" test
- `vfs/tests/mount_propagation_pivot.rs`: full systemd idiom end-to-end (make-rshared →
  unshare → make-rslave → bind → pivot → umount2 MNT_DETACH) + submount-carry assertions.
- `ext4/tests/fs_ops_stress_image.rs`: mkdir chains, dir-block growth, symlinks, files,
  persist (mini-j.img, CI).
- `ext4/tests/real_rootfs_mkdir_repro.rs` (#[ignore], env-gated `OXIDE_ROOTFS_IMG`):
  opens the REAL boot rootfs and drives per-op + batched + 15.6k-op churn + the
  VFS/framecache path (`mkdir_at`/`write_file`). Run:
  `OXIDE_ROOTFS_IMG=/home/nd/oxide/images/output/live-gnome-x86_64-root.img cargo test
   -p ext4 --test real_rootfs_mkdir_repro -- --ignored --nocapture`
- B686 also fixed the swallowed-EIO: ext4 create ops now map real MountError
  (DirFull/NoSpace→ENOSPC, Depth→ENOTSUP, genuine IO→EIO) via `vfs_error_from_mount`.

## Remaining boot issue #1: `mkdir /var/log/journal/<id> err=5` + `/run/udev err=5`
NARROWED to CONCURRENCY. EVERY single-threaded hosted layer SUCCEEDS on the real image
(raw Mount, batched, 15.6k-op churn, VFS/framecache path). With the B686 errno fix the
boot STILL shows err=5 (EIO) — so it's NOT htree DirFull (→ENOSPC now), NoSpace, dir-
growth, submount-carry, or image state. It's a genuine Dir/BlockIo/Inode error → a
multi-task race in `create_dir`'s bitmap/GDT/inode allocation (services create in
different parent dirs concurrently; parent i_rwsem serializes same-dir but the GLOBAL
allocator is shared). NEXT: (a) klog the MountError variant in-boot (needs ext4
`debug-mount` feature wired into the kernel build), or (b) a hosted multi-thread
concurrency stress test on `Arc<Mount>`. Likely non-fatal (journald falls back to
volatile /run) — boot progressed past it.

## Full ext4 roadmap: `scratch/ext42.md` (thorough audit, this session)
P0 durability: **`SuperOps::sync_fs` calls the no-op `flush_pending_tx()` not
`commit_batch()`** (`rootfs/ops/mountfs.rs:37`) → batched metadata on non-root ext4
(`/home`) can be lost on syncfs. Small clear fix + remount test. Also: Drop commits
clean-bit into the same undrained shadow (2.2). P1: htree leaf-split + htree-create
absent (populated indexed dirs) ; jbd2 revoke/checksum absent (crash-only). See §7 fix
order + §9 files.

## First command next session
`cd /home/nd/oxide/kernel && git log --oneline -3`  # main @ 66c1c7e7
Then EITHER: fix the P0 batch-drain (`sync_fs`→`commit_batch`, ext42 §2.1) — small, clear;
OR pin the boot mkdir-EIO variant: wire ext4 `debug-mount` into the kernel build, klog the
MountError in `special.rs` mkdir, one boot; OR verify how far the (now-unblocked) boot
reaches — boot `features=debug-mnt`, watch for graphical.target / login past 573s.

## Notes
- Boot-verify centrally on main; `make smoke` can't reach login yet → mount/ext4-only
  pushes use `SKIP_SMOKE=1`.
- aarch64: all fixes arch-neutral; compile; arm boot untestable here (no packed image).
- C107 branch used a below-`next` counter (107<108) — harmless, merged; index still @108.
