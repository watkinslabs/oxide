# Handoff — ext4 12/14 lanes done (full htree write path!); 2 boot blockers fixed

Main = `67acb0f1`. ~17 PRs merged this session. Focus: complete ext4 (hosted +
e2fsck-gated, NO booting per user). console/live-gnome share the sysinit path.

## ★★ Fixed + boot-verified earlier this session
1. **sysinit pivot_root deadlock (#2895)** — 3 mount bugs.
2. **boot mkdir err=5 (#2902)** — ext4 concurrent-create allocator race → op_lock.
   ext4 perf fixes halved the hwdb boot gap (72s→37s).

## ext4 100% plan `scratch/ext4-compat-plan.md` — 12 of 14 lanes DONE
All e2fsck-clean (e2fsck present) or unit-verified:
- L1 sync_fs→commit_batch (#2899) · L1b batch shadow-aware lookup (#2900)
- L2 Drop commits batch (#2901) · L3 concurrent-create op_lock (#2902)
- L10 lazy unwritten fallocate (#2905) · sparse writes leave holes (#2906)
- L14 huge_file i_blocks (#2908) · L12 POSIX ACL enforcement (#2909)
- **L6+7+8 FULL htree write path (#2911)** — leaf split, linear→indexed create,
  root grow (1→2 level), node split, dx_tail checksums, + inode-bitmap padding
  fix. Verified: 6000 creates through our code build a clean 2-level index
  (mke2fs fresh image, `e2fsck -fn` clean); 360 creates split leaves on htree.img.

## Remaining 2-3 lanes — LARGE / need new machinery (honest scope)
- **4, 5 jbd2 revoke + commit/tag checksums** — crash-recovery ONLY (we WAL +
  apply to targets, so clean runs are correct). Verifying needs a CRASH-INJECTION
  harness (mount, stage a txn, DON'T apply targets, remount+replay, assert). That
  harness is the prerequisite — build it first.
- **13 fallocate PUNCH_HOLE/COLLAPSE/INSERT** — multi-crate plumbing (sys_fallocate
  in sched/falloc.rs → VFS `InodeOps::fallocate` trait → ext4/tmpfs impls) PLUS
  middle-range extent surgery (split a spanning extent → +1 extent → possible
  node overflow; model on truncate.rs's depth-0/depth>0 walk). Currently EOPNOTSUPP
  (tools degrade gracefully). Do depth-0 (inline) first + e2fsck-test, then depth>0.
- **9 allocator run-length** — now MARGINAL: `insert_extent_record` coalesces, and
  alloc_block returns consecutive blocks for fresh regions, so extents are already
  compact. Reservation-cache (amortize per-alloc RMW) is the only real gain.
- **11 backup SB/GDT** — NON-ISSUE (Linux keeps primary authoritative at runtime).

## First command next session
`cd /home/nd/oxide/kernel && git log --oneline -3`  # main @ 67acb0f1
For ext4 100%: (1) build a crash-injection harness → jbd2 revoke+csum (4,5);
(2) PUNCH_HOLE (13) — plumbing + depth-0 extent surgery, e2fsck-gated.
For live-gnome (separate, NON-ext4): the `systemd-tmpfiles-setup-dev-early` 210s
hang blocks the boot — trace what its vpid is stuck on (device-node/mknod/varlink),
NOT ext4.

## Gotchas
- NEVER `git add -A` (swept ext42.md + rustc-ice dumps; gitignored). Stage explicit.
- e2fsck (/usr/bin/e2fsck) is THE gate for format-critical ext4; e2fsck_image.rs
  can mke2fs a fresh fixture at runtime (see htree_create_split test) to exercise
  paths htree.img can't (limited free inodes).
- User forbids booting for ext4 work — iterate hosted. [[ext4-work-no-booting]]
- aarch64: fixes arch-neutral; compile; arm boot untestable here.
