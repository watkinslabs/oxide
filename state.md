# Handoff — ext4 100% COMPLETE (14/14 lanes); 2 boot blockers fixed

Main = `cb345bd5`. ~19 PRs merged this session. ext4 completion done hosted +
e2fsck-gated (NO booting, per user). Console/live-gnome share the sysinit path.

## ★★ ext4 = 100% complete — all 14 lanes of scratch/ext4-compat-plan.md
All e2fsck-clean (e2fsck present) or unit-verified:
- L1 sync_fs→commit_batch (#2899) · L1b batch shadow-aware lookup (#2900)
- L2 Drop commits batch (#2901) · L3 concurrent-create op_lock race (#2902)
- L10 lazy unwritten fallocate (#2905) · sparse writes leave holes (#2906)
- L14 huge_file i_blocks (#2908) · L12 POSIX ACL enforcement (#2909)
- **L6+7+8 full htree write path (#2911)** — leaf split, linear→indexed create,
  root grow (1→2 level), node split, dx_tail checksums + inode-bitmap padding fix.
  Verified: 6000 creates build a clean 2-level index; e2fsck clean.
- **L13 fallocate PUNCH_HOLE (#2913)** — deallocate range → holes, extent rebuild,
  plumbed through VFS `InodeOps::fallocate` (tmpfs + ext4). e2fsck clean.
- **L4/L5 jbd2 (#2914)** — revoke N/A (single-txn checkpoint model); checksums N/A
  (no real ext4 journal uses jbd2 csum — e2fsprogs 1.47 won't make one; all images
  = "Journal features: (none)"); defensive CSUM_V2/V3 gate added.
- L9 allocator run-length SUPERSEDED by extent coalescing; L11 backup SB NON-ISSUE.

## ★★ Also fixed + boot-verified earlier this session
1. **sysinit pivot_root deadlock (#2895)** — 3 mount bugs.
2. **boot mkdir err=5 (#2902)** — the ext4 concurrent-create allocator race → op_lock.
   ext4 perf fixes halved the hwdb boot gap (72s→37s).

## Remaining GOAL = live-gnome bootable (NON-ext4; console is unblocked by sysinit)
console.md: the tty/N_TTY/fbcon stack is REAL + largely Linux-compatible; the
window is blank ONLY because sysinit stalls before getty.target. So console (goal 1)
completes when sysinit completes. The live-gnome/console BLOCKER is:
**`systemd-tmpfiles-setup-dev-early.service` hangs 210s** (boot gap 53→263s),
creating static /dev nodes, then timeout-killed. NOT ext4 — devtmpfs/tmpfs mknod
or a tmpfiles/varlink wait. NEXT: boot `features=debug-mnt`, find its vpid, read
/proc/<pid>/status State + fd during the hang (a mknod? a socket wait?).

## First command next session
`cd /home/nd/oxide/kernel && git log --oneline -3`  # main @ cb345bd5
ext4 is DONE — next is live-gnome: trace + fix the tmpfiles-setup-dev-early 210s
hang (non-ext4), then boot to getty/graphical.

## Gotchas
- NEVER `git add -A` (swept ext42.md + rustc-ice dumps; gitignored). Stage explicit.
- e2fsck (/usr/bin/e2fsck) is THE gate for format-critical ext4; e2fsck_image.rs can
  mke2fs a fresh fixture at runtime (see htree_create_split test) for paths the
  committed images can't reach.
- User forbids booting for ext4 work — iterate hosted. [[ext4-work-no-booting]]
- `fs` crate standalone `cargo test` fails on `sched::live` (pre-existing feature
  gating, NOT a real break) — test ext4/vfs directly.
- aarch64: fixes arch-neutral; compile; arm boot untestable here.
