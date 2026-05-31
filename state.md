# Session hand-off — 2026-05-31

## TL;DR
Autonomous run. B20 closed (#1376), K2 mount-tree foundation (#1377).
Now executing the "big lift": full Linux-faithful VFS dentry/mount
rebuild — Track K2V in TASKS.md, staged V1..V7, each a PR booting both
arches. V1 (ext4 dir-inode lookup) done on branch F280. Continue down
the V-stages autonomously. See TASKS.md "Track K2V" for the plan +
architecture decisions (per-dentry dcache, spinlock-not-RCU, string
table during transition).

## V-stage progress
- V1 ext4 `Inode::lookup(name)` (F280): `rootfs::lookup_child_ino` +
  `wrap_any_ino` (real on-disk mode) + `Ext4StatInode::lookup`;
  `lookup_inode_any` now builds via wrap_any_ino. Hosted tests
  `lookup_in_dir_resolves_child`/`_missing`. Additive — nothing calls
  the ext4 dir lookup yet (V2 walker will).
- V2 path_lookup walker (F281): `vfs::namei::path_lookup(start, root, path,
  LookupFlags)` — per-component via dentry children-cache + Inode::lookup,
  symlink follow (rel/abs) with ELOOP+depth≤40, `.`/`..` (root-clamped),
  O_NOFOLLOW/RESOLVE_NO_SYMLINKS/BENEATH, mount-cross via
  `set_mount_resolver` hook (abs-path keyed during string-table
  transition). Dentry gained children map (cached_child/cache_child/
  forget_child). VfsError += Eloop/Enametoolong. 9 hosted tests
  (tests/namei_walk.rs). Additive — NOT wired into any syscall yet.
- NEXT: V3 — wire path_lookup into syscalls in clusters. Start with
  sys_newfstatat (stat): install the mount resolver (bridge to
  vfs::mount), build/cache a global root dentry from ext4 root, resolve
  via path_lookup with fallback to the old vfs::mount::lookup for
  backends without per-component lookup (procfs/sysfs). Boot-verify each
  cluster. Then open → exec → namei mutations → real dirfd/*at.

## Last K2 work: mount-tree-ids (F279)
vfs::mount Mount gained persistent `mnt_id` + `Propagation` (AtomicU8).
/proc/mountinfo now emits real mnt_id and real parent_id (longest
proper path-prefix via `parent_id_of`) instead of synthesized index+1
with all-parents=root — so systemd/findmnt see the true tree (/dev/shm
parent = /dev). sys_mount records MS_SHARED/PRIVATE/SLAVE/UNBINDABLE via
`set_propagation` (was pure no-op); mountinfo shows `shared:<id>` /
`unbindable`. Tree is IMPLICIT in mount_point paths (no Arc cycles) so
MS_MOVE later = mount_point change + parent recompute. mount_smoke now
asserts unique ids + shared-root tag. Both arches: mount_smoke PASS +
login. NOTE: tmpfs still registers via devfs registry, not
vfs::mount::TABLE (fragmented) — unify in later K2/K3.

## Last work: B20 alarm/SIGALRM wake (PR #1376)
`read()` on empty pipe + alarm(1)+SIGALRM never returned. Three layered
bugs, fixed bottom-up:
1. alarm_ns only checked at syscall-return tail → serviced in
   `tick_wake_expired`.
2. `tick_wake_expired` was dead since F152 retired the rx kthread →
   rewired into the live timer tick `tick_poll_combined` (lib.rs),
   throttled ~100ms (LAST_SCAN_NS). This also revived SO_*TIMEO
   timeout-wakes, which were silently dead.
3. **WaitList finish_wait contract bug (systemic)**: signal/deadline
   wake bypasses the WaitList → stale Arc → later wake_all enqueues a
   dead task → corrupt context switch → silent wedge. Fixed at the
   primitive: wake_one/wake_all only enqueue Sleeping tasks; park dedups.
   Covers pipe+sem+msg+mq+net+epoll+evdev.
Also: post_pgrp missing wake_if_sleeping. Split sys_ptrace → ptrace.rs.
Regression guard: `/bin/alarm_probe`. Both arches reach login.

Diagnosis lesson: a chained `cmd; echo exit=$?; grep ...` Bash call
returns the LAST command's exit, NOT the smoke's — verify boot-smoke
PASS via its own EXITCODE or the "reached login" line, not the wrapper.

## Next: Track K (do K2 first — partial, hard gate)
K1 cgroup v2 done (#1355). K2 real mount is **partial** (#1358/#1359):
dynamic /proc/mounts + mountinfo, MS_BIND + propagation/MS_REMOUNT
accepted. REMAINING for K2: MS_REC recursive bind, MS_MOVE (ENOSYS now),
pivot_root, peer-propagation event semantics, mount-record tree.
Then K3 (CLONE_NEWNS mount namespaces), K4 (rtnetlink RTM_GETLINK),
K5 (SCM creds / NETLINK_KOBJECT_UEVENT / /proc/<pid>/ns / /dev/kmsg /
memfd seals), K6 (fsopen/fsconfig/fsmount/move_mount). K1b = cgroup
controller enforcement depth.

First task next session:
  grep -rn "MS_MOVE\|MS_REC\|pivot_root\|fn sys_mount" kernel/src/syscalls/mount.rs

## Gates (B20)
- spec-lint clean
- pre-push `make smoke` PASS both arches (arm login 26s, x86 fast)
- alarm_probe PASS both arches (manual seq runs, full init smokes)

## Working-tree leftovers (pre-existing, leave alone)
  tools/kill-defunct.sh
  vendor/pam/install-{aarch64,x86_64}/*

## Endgame reminder
GNOME/Wayland distro on real musl + dynamic systemd. Track K unblocks
systemd; Track L (shared-lib userspace) + D6 (systemd) are the horizon.
