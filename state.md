# Handoff — 2 boot blockers fixed + 7 ext4 lanes; new blocker = tmpfiles-dev 210s hang

Main = `15a07db3`. Goal: console login → live-gnome. ~13 PRs merged this session.
Boot now: NO pivot deadlock, NO mkdir err=5; ext4 perf fixes HALVED the hwdb gap
(72s→37s). New dominant blocker is NON-ext4 (below). Boot still not at login.

## ★★ Fixed + boot-verified this session
1. **sysinit pivot_root deadlock (B685/#2895)** — 3 mount bugs (bind source-peer-group
   inheritance; overmount-on-ns-root invisible to mount_exact_at; umount2(".") stale cwd).
2. **boot mkdir err=5 (B691/#2902)** — ext4 concurrent-create allocator RACE (bitmap RMW
   unserialized) → double-alloc → EIO. Fixed with mount-wide `op_lock` on create ops.
   Boot-verified: err=5 GONE.

## ext4 100% Linux-compat plan `scratch/ext4-compat-plan.md` — 7/14 lanes DONE
- L1 sync_fs→commit_batch durability (#2899) · L1b batch shadow-aware lookup (#2900)
- L2 Drop commits batch (#2901) · L3 concurrent-create op_lock (#2902)
- **L10 lazy unwritten-extent fallocate — no eager zeroing (#2905)**
- **sparse writes leave holes, not O(n²) zero-fill (#2906, B693)**
All e2fsck-clean (e2fsck present on box). Harnesses: batch_syncfs/read_your_writes/
drop_persists, concurrent_alloc (0 double-alloc), fs_ops_stress, real_rootfs_mkdir_repro,
fallocate_unwritten + sparse_write e2fsck tests, mount_propagation_pivot.
TODO lanes: 4 jbd2 revoke+seq-replay, 5 jbd2 checksums, 6 htree leaf split, 7 htree
create, 8 htree dx csum, 9 block-allocator run-length (would batch hwdb's ~3400
per-block allocs → shrink the 37s hwdb gap further), 11 backup SB/GDT, 12 POSIX ACL,
13 fallocate PUNCH/COLLAPSE/INSERT range, 14 huge_file i_blocks.

## ★ NEW dominant boot blocker: `systemd-tmpfiles-setup-dev-early.service` 210s hang
Boot gaps now (smp=1, debug-mnt): 15.6→53.2 (37s, hwdb.bin write — ext4, Lane 9 helps)
then **53.2→263.8 (210s) = systemd-tmpfiles-setup-dev-early** creating static /dev
device nodes. 210s ≈ DefaultTimeoutStartSec → the service HANGS and is killed, boot
proceeds at 263s (next service's mount-ns setup, vpid=48). This is NOT ext4 — it's
device-node creation (devtmpfs/tmpfs mknod) or a tmpfiles rule wait. NEXT: boot
`features=debug-mnt`, find vpid of tmpfiles-setup-dev-early, read /proc/<pid>/status
State + fd during 53-263s to see what it's stuck on (a mknod? a socket/varlink wait
like the old userdbd issue? a devtmpfs op?). Do NOT assume ext4.

## First command next session
`cd /home/nd/oxide/kernel && git log --oneline -3`  # main @ 15a07db3
Then EITHER: (a) trace the tmpfiles-setup-dev-early 210s hang (the live-gnome blocker,
non-ext4); OR (b) ext4 Lane 9 run-allocation (shrinks the 37s hwdb gap); OR (c) ext4
Lanes 4-8/11-14 for 100% compat completeness.

## Notes / gotchas
- **NEVER `git add -A`** — swept ext42.md + rustc-ice dumps into commits (now gitignored).
  Stage explicit paths. `git checkout -b <B##>` then `git add <files>`.
- Transient rustc ICE "unstable fingerprints...EvaluatedToOk" = compiler cache bug, retry.
- e2fsck is THE gate for format-critical ext4 changes (e2fsck_image.rs runs `e2fsck -fn`).
- Boot-verify centrally on main; mount/ext4-only pushes use `SKIP_SMOKE=1`.
- `/run/credentials/* umount2 rv=-22` are benign (credential tmpfs teardown).
- aarch64: all fixes arch-neutral; compile; arm boot untestable here (no packed image).
