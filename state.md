# state.md — session handoff

## Headline
**VFS Linux-compliance campaign at its no-new-infra ceiling: ~258/287 = 90% DONE, merged to `origin/main`.** Boots both arches to login; dcache 100%, syscalls 98%, file 97%. The 12 remaining rows are the documented FLOOR (see `/home/nd/oxide/fix-ledger.md` FINAL "REMAINING-WORK BACKLOG").

## What got done (all boot-verified, on main)
Drove the 287-item VFS audit from a stale-recorded 55 (real ~100) to 90%. Clusters solved: **D24 mount-identity** (the multi-session plateau — `is_global_root` structural-heuristic root cause; `is_ns_root_dentry` graft-fix → map-drop + walk-flip); **fs_context fallback-conversion** (ext4/PseudoFs/tmpfs/cgroup2 realize at CMD_CREATE); **device-model** (device_add facade unifies /dev+/sys, ext4-overlay removed, /etc in rootfs, eventfs predicate engine); **call_rcu** (real RCU + dentry deferred-free); **mount-internals** (root-collapse, MOUNT_WRITE serialization); **dirfd** (*at seeds from real (mnt,dentry)); **ext4 frame-backed mmap**; **mount-attr** (D51/D52); **fanotify** (D56). Plus all keystones + ~70 mop-up items.

## The floor (12 rows — each gated, see ledger backlog A–F)
- A infra-gated (4): namei D3 (SMP AP-sched), mount D28b (no lock-free reader consumer), mount D30 (vfs→sched cycle/per-cpu mnt-ns slot), inode D2-leaf (low value).
- B executor-pivot SB-identity (2): superblock D24-bind, mount D16.
- C no consumer (1): namei D4 (needs network/fuse fs).
- D cross-cutting boot-load-bearing (2): inode D9 (Inode::lookup signature, functionally-equivalent), syscalls D56 per-vfsmount scope.
- E display-only (1): namei D7 (d_path bind-ambiguity = Linux-equivalent).
- F wontfix-by-design (2): file D34, superblock D6.

## First task next session
`git fetch && git checkout main && git reset --hard origin/main`; read `fix-ledger.md` top. To push past 90% needs NEW kernel infra, not ledger mop-up: (a) SMP AP-scheduling (master-plan phase 4 tail) → unlocks namei D3 + mount D28b + real RCU benefit; (b) executor-pivot SB-identity rework (shared-SB clone_mnt without breaking 203/EXEC) → unlocks superblock D24 + mount D16. Otherwise 90% is the Linux-faithful no-new-infra ceiling. Method that worked: read-only Plan architect first (assess achievable-vs-floor), staged implement + N-boot verify; one item = one lane (CLAUDE.md anti-dup rule).
