# Session hand-off — 2026-05-31

## TL;DR
Autonomous run. Merged this session: B20 (#1376), K2 mount-tree
foundation (#1377), V1 ext4 dir lookup (#1378), V2 path_lookup walker
(#1379). Executing the "big lift" — full Linux-faithful VFS dentry/mount
rebuild (Track K2V). **PLAN REORDERED 2026-05-31 per user**: the first
V3 (wire symlink-follow into stat/open) was a legacy-first+fallback
BOLT-ON on the fragmented mount table V5 replaces — reverted (F282 never
merged). New order = verify-left + foundation-first. Also updated
CLAUDE.md "How to act on big/cross-subsystem changes" with the lessons.

## V3 DONE (F283): verify-left harness
`crates/kernel/ext4/tests/walk_image.rs` + `tests/walk.img` drive
`vfs::path_lookup` over the REAL ext4 Inode impls in `cargo test`
(~0.6s, no QEMU) — 7 tests: descent, abs/rel/intermediate(merged-usr R6)
symlink follow, ELOOP, O_NOFOLLOW. Enabled by `rootfs::set_test_mount`
(publishes a fixture Mount into MOUNT_PTR) + un-gating the ext4 rootfs
Inode layer for host (boot bits ROOTFS/init/ImageDisk stay kernel-only).
THIS IS THE DEV LOOP for V4–V7 — extend walk.img + walk_image.rs to
verify each stage before any QEMU boot.

## V3+V4 done; NEXT V5 unified mount tree
- V3 verify-left harness merged (#1381): `crates/kernel/ext4/tests/
  walk_image.rs` + `walk.img`. THE dev loop — extend it per stage.
- V4 in progress (F284): `FileSystem::root()` (docs/16§2 Superblock::root)
  — the inode the walk switches to on mount-crossing; ext4 returns ino-2.
  Hosted test `fs_root_is_root_dir`. Additive, unused in kernel yet.
- NEXT V5: THE foundation — unified dentry-keyed mount tree spanning
  ext4/tmpfs/devfs/proc/sys. Install a kernel mount-resolver bridging
  `path_lookup`'s cross-hook to the real registries via `fs.root()`;
  add `root()` for tmpfs/devfs/procfs/sysfs; fill procfs/sysfs dir
  `lookup(name)`. Drops the string-table + devfs-registry split +
  BindFs rewrite. Verify crossing on the harness FIRST. Then V6 migrate
  ALL path syscalls (re-add symlink_probe), V7 bind/MS_MOVE/pivot_root/
  MS_REC/propagation/per-ns.

## Harness gotchas (don't rediscover)
- `boot-smoke` = login PROMPT only; `boot-smoke-login` = actual login
  (alice/swordfish→id). Login regressions slip the prompt gate — the
  pre-push hook only runs prompt-smoke. Consider gating on login-smoke.
- `make qemu-x86` defaults TCG; `OXIDE_QEMU_KVM=1` for KVM (fast). Boot
  qemu directly with `hostfwd=tcp::2299` + `vendor/firmware/ovmf-x64.fd`
  to avoid colliding with a user's :2222 session.
- `| tail`/`| grep` on long cmds swallow output + return nonzero under
  the shell; REDIRECT to a file and read the file. Kill stale qemu +
  confirm :2222 free before boots (26h orphans happen).
- qemu MCP hangs in OVMF under TCG (never reaches kernel) — not usable
  for full-boot repro here; use direct KVM qemu.

GOTCHAS learned (don't rediscover by booting):
- musl stat()/lstat() → `sys_stat` (slots 4/6), NOT statx/newfstatat.
- ext4 symlink *create* is NOT implemented (bake fixtures via debugfs).
- `make qemu-x86` is a cold debug-boot rebuild (~5min); warm-build once,
  kill stale qemu + confirm port 2222 free before each boot, and don't
  chain `cmd > file; echo >> file` under the shell's `set -e`.

## V1/V2 (merged) detail
- V1 ext4 `Inode::lookup(name)` (#1378): `rootfs::lookup_child_ino` +
  `wrap_any_ino` (real mode) + `Ext4StatInode::lookup`.
- V2 walker (#1379): `vfs::namei::path_lookup(start, root, path,
  LookupFlags)` — per-component dentry-cache + Inode::lookup, symlink
  (rel/abs) ELOOP+depth≤40, `.`/`..`, RESOLVE flags, mount-cross via
  `set_mount_resolver`. Dentry children cache. 9 hosted tests.

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
