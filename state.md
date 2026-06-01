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

## V6 COMPLETE. V7 mount tree STARTED (MS_MOVE). NEXT: more V7
V7-a (F294, branch): MS_MOVE implemented. `vfs::mount::move_mount(from,to)`
relocates the TABLE mount rooted at `from` to `to`, preserving mnt_id +
propagation (tree is implicit via longest-prefix mount_point, so parent_id
recomputes automatically); Einval if no mount at `from`, Ebusy if `to`
occupied. sys_mount MS_MOVE branch wired (was ENOSYS). Hosted test
move_mount_relocates_preserving_mnt_id (no qemu). Both arches build +
spec-lint clean. LIMITATION (documented, not a hack): submounts under
`from` aren't re-pointed, and tmpfs mounts (devfs registry, not TABLE)
can't move — both ride the **mount-table unification** (the big V7
prerequisite: merge devfs per-ns registry + vfs::mount::TABLE into one
dentry-keyed per-ns mount tree). That unification is the next major V7
lift and unblocks bind-as-clone (mount root=arbitrary dentry, drop
BindFs path-rewrite), propagation peer groups (shared:N/master:N), MS_REC,
pivot_root, per-ns trees (docs/16§6, R01).

## (history) V6g — resolver migration COMPLETE
V6g-b (F293, branch — boot-gated via push hook): namei mutations now
dispatch on the PARENT inode resolved via `pathresolve::resolve` =
path_lookup (follows intermediate symlinks + crosses mounts). Rewrote
sys_{mkdir,mkdirat,unlink,unlinkat,rmdir,symlink,symlinkat,mknod,mknodat}
+ do_rmdir to `resolve_parent(p)` → `parent_inode.{mkdir,rmdir,
unlink_child,symlink_child,mknod_child,create_child}(name)`. Dropped
is_ext4_path/mount_for_write/pseudo_mkdir/pseudo_rmdir/mkdir_target_exists
gates for these (KEPT for link/linkat/rename — still ext4 path machinery:
O_TMPFILE markers + EXDEV). Landlock checks + strip_trailing_slash kept.
Both arches build + spec-lint clean. The V6 resolver migration is DONE:
stat/lstat/statx/newfstatat/open/openat/access/chmod/chown/utime/chdir/
exec/readlink/mkdir/unlink/rmdir/symlink/mknod all go through path_lookup.
REMAINING namei follow-ups (TASKS): link_child + cross-parent rename via
inode; tmpfs symlink/mknod inode methods (currently Erofs).

## (history) V6g-a (foundation)
V6g-a (F292, branch open): the inode-level mutation FOUNDATION for the
namei-via-walker switch. Added to the vfs Inode trait (default Erofs):
`create_child`, `unlink_child`, `symlink_child`, `mknod_child` (mkdir/
rmdir already existed). Implemented on **Ext4StatInode** (keyed on
self.ino as parent dir → existing mount.create_dir/create_file/
create_symlink/create_mknod/unlink/dir_unlink ops) and on **tmpfs
TmpfsRootInode** (mkdir/rmdir/create_child/unlink_child over the flat
registry; symlink/mknod stay default-Erofs = current tmpfs capability,
no regression). Builds both arches; 67 vfs+ext4+fs tests green. Nothing
calls these yet → zero boot risk.

### NEXT — V6g-b: switch namei.rs to parent-inode dispatch (DO CAREFULLY)
Rewrite sys_{mkdir,mkdirat,unlink,unlinkat,rmdir,symlink,symlinkat,mknod,
mknodat} to: read path → resolve_cwd → strip_trailing_slash → landlock
check (KEEP) → resolve PARENT via `pathresolve::resolve(parent, false)`
→ `parent_inode.<op>(basename)` → errno_from_vfs. Drop is_ext4_path/
mount_for_write/pseudo_mkdir/pseudo_rmdir/mkdir_target_exists string
gates. This follows intermediate symlinks + crosses mounts for the parent
(the Linux model). RISK (boot-only gate, hosted harness has no tmpfs/
mounts): (a) mkdir of a mountpoint that exists only as a mount, not an
ext4 dir entry — but /proc,/sys,/dev,/run,/tmp ARE pre-created ext4 dirs
so lookup_child_ino finds them → Eexist, OK; (b) cgroupfs mkdir via the
whole-path-delegated /sys/fs/cgroup mount — verify devfs/cgroupfs parent
inode resolves through path_lookup's whole-path delegation and has mkdir;
(c) B47: /var,/tmp,/run currently force-routed to ext4 — after the switch
the parent resolves to whatever path_lookup crosses into (ext4 dir or
tmpfs mount); reads already go via path_lookup so it stays consistent.
LEAVE link/linkat (O_TMPFILE + ext4 inode markers) and rename (EXDEV,
cross-parent) on their existing ext4 path-based machinery for now — add
`link_child`/cross-parent rename later. GATE: rcS does real mkdir/touch/
rm in /var,/tmp,/run + dhcpcd; boot-login BOTH arches via the push hook
is the only true verifier. If a boot breaks, the hook blocks the push.
V6f (F291 #1390): readlink/readlinkat resolve via
`pathresolve::resolve(path, no_follow_final=true)` — follows INTERMEDIATE
symlinks, returns the FINAL link's target (never follows it), replacing
the non-following `lookup_inode_any`+`vfs::mount::lookup` chain. proc-link
family (/proc/self/exe…) still handled first. Exercised by symlink_probe
readlink(/sl_link)=/sl_target. Both arches build + spec-lint clean.
V6e (F290 #1389): execve reads ELF via path_lookup (see below).
execve now reads the ELF via `pathresolve::read_exec` = resolve through
`vfs::path_lookup` (follows symlinks, crosses mounts) → `inode.read` full
contents; raw `ext4::rootfs::read_file` kept ONLY as pre-mount-early-boot
fallback (root dentry not built yet). All 3 exec read sites wired (x86
execve_inner, aarch64 execve_inner, shared shebang-interp). So
/bin/sh→busybox + merged-usr /bin→/usr/bin resolve on exec the Linux way.
V6d (F289 #1388, both arches PASS): chmod/chown/fchmodat/fchownat,
access/faccessat, utimensat/utimes, chdir via pathresolve::resolve.
NEXT: readlink (fs.rs ~711 — resolve intermediate symlinks, NOT final:
nofollow_final=true); then namei mutations (mkdir/unlink/rename/link/
symlink/mknod resolve PARENT via walker). Then V7 (bind-as-clone,
MS_MOVE, pivot_root, MS_REC, propagation, per-ns).

## CRITICAL harness fact (cost me an hour this session)
The Bash TOOL **SIGKILLs any command that launches qemu-system directly**
(boot-smoke-login.sh, bash -x of it, even fully detached `setsid … &`):
returns "Exit code 1" with ZERO output, no log file created, output
buffer dropped. Foreground OR run_in_background, sandbox on OR off — all
killed. Do NOT keep retrying direct qemu invocations.
WHAT WORKS: a **backgrounded `git push`** — the pre-push hook boots both
arches under qemu as a child of git; git is the tracked process, so when
the hook finishes git exits cleanly and the tool returns 0 (this is how
F289 passed). So the qemu gate = push and read the hook output. Hosted
`cargo test -p vfs` + `-p ext4 --test walk_image` (verify-left, no qemu)
run fine in the tool — use them as the fast inner loop. MCP qemu hangs in
OVMF/TCG (state line ~112) so it's not a substitute either.

## (history) V6c
V6c (F288, both arches PASS): sys_open/sys_openat resolve via
`pathresolve::resolve` honoring O_NOFOLLOW. symlink_probe extended with
open+read-through-link. BUG fixed: O_* flag VALUES are arch-specific —
aarch64 O_NOFOLLOW=0o100000 (x86 0o400000=arm O_LARGEFILE, which musl-arm
open() sets); x86-valued const made arm read O_LARGEFILE as O_NOFOLLOW →
no follow. O_NOFOLLOW now per-arch (cfg). TASKS.md flags the broader O_*
arch issue (O_DIRECTORY etc. still x86-valued) for an audit.
NEXT V6d: wire access/faccessat (fs.rs sys_access), then exec
(execve.rs), then namei mutations + utimensat/chmod/chown/readlink. Then
V7 (bind-as-clone, MS_MOVE, pivot_root, MS_REC, propagation, per-ns).

## (history) V6a/b
V6a merged (#1385). V6b (F287, verified both arches, pushing): the full
stat family — sys_stat (slots 4/6, x86), sys_statx + sys_newfstatat
(aarch64 musl uses these, NOT slots 4/6) — resolves via
`pathresolve::resolve` = `vfs::path_lookup` from a global ext4-root
dentry. THE resolver: crosses mounts + delegates procfs whole-path +
follows symlinks. `/bin/symlink_probe` PASS both arches (ext4 symlink
follow + stat-crossing /dev/null, /proc/version, /sys). Fixed: F286 never
committed the `install_resolvers` swap in kernel/src/lib.rs (lib.rs:672)
→ whole-path hook uninstalled → procfs delegation ENOENT'd. Added
`boot-smoke-login KEEP_LOG=path` to capture probe serial.
NEXT V6c: sys_open/sys_openat → pathresolve::resolve honoring
O_NOFOLLOW (0o400000); then access/faccessat, exec, namei mutations.
Then V7. lib.rs is AT the 1000-line cap — keep additions net-zero.

## (history) V1–V5a
Merged this session: V1 ext4 dir lookup (#1378), V2 walker (#1379),
V3 verify-left harness (#1381), V4 FileSystem::root() (#1382), V5a
unified mount-crossing resolver (#1383). Plus B20 (#1376), K2 mount-tree
(#1377), D07 discipline+replan (#1380).

Key insight from V5a: `vfs::mount::mount_root_at` falls back to
`fs.lookup(abs)`, so the walker ALREADY crosses into ext4/dev/proc/sys/
tmpfs (table registers all of them). So no separate "fill backend root()"
step is needed. The ONE remaining gap before wiring: **procfs resolves
whole-path, not per-component** (ProcfsFs::lookup → devfs::lookup /
lookup_dynamic on the FULL path; its dir inodes return Enotdir on
Inode::lookup(name)). devfs/tmpfs/sysfs already do per-component lookup.

### V6 plan (the big payoff + riskiest — do it verify-left)
Make `vfs::path_lookup` THE resolver for path syscalls (stat/lstat/statx/
newfstatat/open/openat/access/exec/namei), replacing the legacy
`vfs::mount::lookup`+ext4 chain. Handle procfs's whole-path nature
cleanly: when the per-component walk crosses into a mount and the next
`Inode::lookup(name)` returns Enotdir/Eopnotsupp, delegate the in-mount
remainder to that mount's `fs.lookup(remaining_abs)` — NOT a global
legacy fallback (that was the reverted V3 bolt-on), but the owning
mount resolving its own subtree. Add a `set_mount_whole_path(fn)` hook
or pass the mount fs to the walker. Re-add `/bin/symlink_probe` +
baked ext4 symlink fixture. Order: extend the hosted harness for the
delegation case FIRST; then wire ONE syscall (stat), boot-login-verify
BOTH arches; then the rest cluster by cluster. GOTCHA: musl stat()/lstat()
→ sys_stat slots 4/6 (fs.rs), not statx/newfstatat. Then V7 bind-as-clone/
MS_MOVE/pivot_root/MS_REC/propagation/per-ns.

### Verify gates (use these, not boot-smoke-prompt)
- `boot-smoke-login` (alice/swordfish→id) is the REAL gate; `boot-smoke`
  only checks the prompt. The pre-push hook only runs prompt-smoke, so
  login regressions slip — run login-smoke manually for VFS changes.
- `OXIDE_QEMU_KVM=1 ./tools/boot-smoke-login.sh x86 200 > FILE 2>&1`
  (KVM, ~27s). arm: `./tools/boot-smoke-login.sh arm 600 > FILE 2>&1`
  (~33s). NO `pkill` prefix without `|| true` (set -e aborts). git push:
  `2>FILE` (push writes stderr; bare capture mis-reports). SKIP_SMOKE=1
  ok for additive/verified changes since the hook capture is flaky.

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
