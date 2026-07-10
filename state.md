# Handoff — sysinit deadlock + mkdir-EIO both FIXED; boot grinds, next = slowness

Main = `eeb9d7c3`. Goal: console login → live-gnome. ~11 PRs merged this session.
Boot now: NO pivot deadlock, NO mkdir err=5; reaches 345s+ still progressing
through per-service namespace setup (journald started). Not yet at login/graphical.

## ★★ Two multi-session blockers FIXED this session
1. **sysinit pivot_root deadlock (B685/#2895)** — 3 Linux-correctness mount bugs:
   bind inherited source peer-group (`165_mount.rs`), overmount-on-ns-root invisible
   to `mount_exact_at`/`mount_at_path_exact` (`vfs model.rs`), `umount2(".")` used the
   stale cwd string (`166_umount2.rs`). pivot_root + `umount2(., MNT_DETACH)` now work.
2. **boot `mkdir /var/log/journal/<id> err=5` + `/run/udev err=5` (B691/#2902)** — the
   ext4 allocator RACE. `try_alloc_{inode,}_in_group` did the bitmap read→find→set with
   NO lock, and the shared `MountState.shadow` lifecycle was unserialized → concurrent
   creates double-allocated one inode → corruption → EIO. Fixed with a mount-wide
   `op_lock` (Linux `ext4_lock_group`, class Ext4Alloc=59) held across the whole create
   in create_dir/file/symlink/mknod. Boot-verified: err=5 GONE (was every boot).

## ext4 100% Linux-compat plan: `scratch/ext4-compat-plan.md` (14 lanes)
DONE: Lane 1 batch-drain durability (sync_fs→commit_batch, B688/#2899), Lane 1b
batch read-your-writes (shadow-aware dir lookup, B689/#2900), Lane 2 batch clean-drop
(Drop commits, B690/#2901), Lane 3 concurrent-create race (B691/#2902).
Hosted harnesses added: batch_syncfs_persists, batch_read_your_writes,
batch_drop_persists, concurrent_alloc_image (8thr×40 creates, 0 double-alloc),
fs_ops_stress_image, real_rootfs_mkdir_repro (env-gated real image), plus
vfs mount_propagation_pivot (full switch-root idiom).
TODO (ext42.md order): 4 jbd2 revoke+seq replay, 5 jbd2 checksums, 6 htree leaf split,
7 htree creation, 8 htree dx csum, **9 block allocator run-length/goal (perf!)**,
10 lazy unwritten extents (perf!), 11 backup SB/GDT, 12 POSIX ACL, 13 fallocate range
ops, 14 huge_file i_blocks.

## Remaining boot issue: SLOWNESS (next frontier)
Boot progresses (no deadlock/EIO) but grinds ~345s+ without reaching login. Strong
suspect = ext4 perf (Lanes 9/10): one-block-at-a-time allocator + eager
fallocate/zero-extension → high latency + journal volume under the boot's file-heavy
workload. Also the `/run/credentials/* umount2 rv=-22` are likely benign. NEXT:
profile which service/op dominates the 17s→89s→345s grind (boot `features=debug-mnt`,
sample `[KERNIP]`; or hosted: time a create-heavy workload), then Lane 9/10.

## First command next session
`cd /home/nd/oxide/kernel && git log --oneline -3`  # main @ eeb9d7c3
Then EITHER continue the ext4 plan (Lane 9 allocator run-length = biggest perf win;
or Lane 4 jbd2 revoke for crash-safety); OR profile the boot slowness to confirm the
allocator is the bottleneck before investing.

## Notes / gotchas
- **STOP using `git add -A`** — it swept ext42.md, then rustc-ice-*.txt dumps into
  commits twice. `rustc-ice-*.txt` now gitignored (C108). Stage explicit paths.
- Transient rustc ICE "unstable fingerprints ... EvaluatedToOk" during incremental
  builds is a compiler cache bug, not our code — retry/clean rebuild.
- Boot-verify centrally on main; mount/ext4-only pushes use `SKIP_SMOKE=1`.
- aarch64: all fixes arch-neutral; compile; arm boot untestable here (no packed image).
- Batch-mode concurrent serialization now via op_lock on creators; delete/rename
  mutators are NOT yet op_lock-covered (create-vs-delete race is a small follow-up).
