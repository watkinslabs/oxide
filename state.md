# Handoff — 9/14 ext4 lanes + 2 boot blockers fixed; live-gnome blocker = tmpfiles 210s

Main = `cd20fadb`. ~16 PRs merged this session. Console/ext4/live-gnome share the
sysinit critical path (console.md: tty stack is real; window blank only because
sysinit stalls before getty). All three goals advance by clearing sysinit stalls.

## ★★ Fixed + boot-verified
1. **sysinit pivot_root deadlock (#2895)** — 3 mount bugs (bind source-peer-group;
   overmount-on-ns-root invisible; umount2(".") stale cwd).
2. **boot mkdir err=5 (#2902)** — ext4 concurrent-create allocator RACE → op_lock.
Boot now: no pivot deadlock, no mkdir EIO; ext4 perf fixes HALVED the hwdb gap
(72s→37s). Reaches deep into sysinit.

## ext4 100% plan `scratch/ext4-compat-plan.md` — 9/14 lanes DONE (all e2fsck/unit-verified)
L1 sync_fs→commit_batch (#2899) · L1b batch shadow-aware lookup (#2900) · L2 Drop
commits batch (#2901) · L3 concurrent-create op_lock (#2902) · L10 lazy unwritten
fallocate (#2905) · sparse writes leave holes / O(n²) fix (#2906) · L14 huge_file
i_blocks (#2908) · L12 POSIX ACL enforcement (#2909).

## Remaining 5 ext4 lanes — LARGE / hard-to-verify (need dedicated focus, NOT a rush)
- **4,5 jbd2 revoke + commit/tag checksums** — crash-recovery ONLY (we WAL + apply
  to targets, so clean runs are correct; only a crash+replay exercises these).
  Needs a CRASH-INJECTION harness to verify — can't gate on e2fsck of a clean image.
- **6,7,8 htree leaf-split + creation + dx-csum** — coupled unit: split needs dx-block
  csum for metadata_csum images or e2fsck rejects. Real "large-dir create" gap.
- **9 allocator run-length** — traced: does NOT fix the hwdb 37s gap (that's 13.5MB
  of DATA writes, already metadata-batched; cost is write-path/virtio, not alloc).
- **13 fallocate PUNCH_HOLE/COLLAPSE/INSERT** — middle-range extent surgery (split a
  spanning extent → +1 extent → node overflow); no bulk extent-rebuild primitive yet.
- **11 backup SB/GDT** — NON-ISSUE: Linux keeps primary authoritative at runtime,
  doesn't mirror counters; backups valid from mkfs (we never resize).

## ★ live-gnome BLOCKER (non-ext4): `systemd-tmpfiles-setup-dev-early` 210s hang
Boot gaps: 15.6→53.2 (37s hwdb.bin write) then **53.2→263.8 (210s) = tmpfiles-setup-
dev-early** creating static /dev nodes, then timeout-killed at 210s → proceeds.
NOT ext4 — devtmpfs/tmpfs mknod or a tmpfiles/varlink wait. THIS is the live-gnome
blocker. NEXT: boot `features=debug-mnt`, find its vpid, read /proc/<pid>/status
State + fd during 53-263s to see what it's stuck on (a mknod? a socket wait?).

## First command next session
`cd /home/nd/oxide/kernel && git log --oneline -3`  # main @ cd20fadb
Recommended order for the GOAL (live-gnome): (1) trace + fix the tmpfiles-dev 210s
hang (the actual blocker); then boot to getty/graphical. For ext4 100% completeness:
the htree unit (6+7+8) is the biggest real gap; jbd2 (4+5) needs a crash-injection
harness first; PUNCH_HOLE (13) needs an extent-rebuild primitive.

## Gotchas
- NEVER `git add -A` (swept ext42.md + rustc-ice dumps; now gitignored). Stage explicit.
- e2fsck (/usr/bin/e2fsck present) is THE gate for format-critical ext4 (e2fsck_image.rs).
- Boot-verify on main; mount/ext4-only pushes use SKIP_SMOKE=1.
- rustc ICE "unstable fingerprints" = transient compiler cache bug, retry.
- aarch64: fixes arch-neutral; compile; arm boot untestable here (no packed image).
