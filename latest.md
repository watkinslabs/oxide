# Path Split-Truth Audit

Date: 2026-07-10
Scope: syscall path resolution, VFS namei/mount tree, ext4 inode wrapping/cache, procfs fd links.

## Executive Finding

The repeated live-gnome blockers are not GNOME-specific. GNOME/systemd is exposing one core class of bug:

> Code still treats rendered path strings as authoritative object identity in places where Linux uses `struct path` identity: `(vfsmount, dentry)` plus inode.

The system now has partial `VfsPath { mnt_id, dentry, inode }` support, but many syscall paths still do:

1. resolve `dirfd`/cwd/root to a string,
2. normalize or splice the string,
3. re-resolve the string through the current root/cwd/mount namespace.

That second lookup can land on the wrong bind location, wrong namespace root, wrong mount parent, stale dentry, or stale ext4 inode type. Each fix gets systemd farther because each systemd sandbox step is a chain of Linux path/mount operations.

## Current Status

The ext4 stale-inode slice is fixed enough to move the boot forward:

- Forced inode-reuse regression passes: regular file -> unlink -> mkdir reusing the same ino returns a new directory wrapper, not the stale regular-file `Arc`.
- `rename_overwrite_image` passes 6/6.
- `mount_propagation_pivot` passes 6/6.
- live-gnome reaches `Reached target multi-user.target` and `Started gdm.service`.
- The old private-tmp `ENOTDIR` blocker is gone in the post-fix boot.

New hosted harness result after stopping boot-driven iteration:

- Added `bind_clone_shares_source_superblock_and_staged_identity` in `crates/kernel/vfs/tests/mount_propagation_pivot.rs`.
- The harness models the systemd staged-root/procfs leaf bind shape without QEMU:
  - host root + procfs submount,
  - service namespace clone,
  - recursive bind of `/` to `/run/systemd/mount-rootfs`,
  - lookup of the staged proc leaf and its global proc alias,
  - bind clone under the walked staged proc parent.
- Assertions now pin Linux semantics:
  - bind is keyed by `(walked_parent_mnt_id, target_dentry)`,
  - rendered mountpoint is `/run/systemd/mount-rootfs/proc/sys/kernel/domainname`,
  - bind clone shares the source mount's `SuperBlock`,
  - bind clone reports source fstype `procfs`, not synthetic `bind`,
  - bind clone preserves `mnt_root` as the source leaf dentry,
  - remount-RO is visible on the cloned mount.
- Verification:
  - `cargo test -p vfs --test mount_propagation_pivot -- --nocapture`: 8/8 pass.
  - `cargo run -p xtask -- kernel --arch x86_64`: passes and compiles `syscalls`.
  - `OXIDE_STUB_BLOBS=1 cargo run -p xtask -- kernel --arch aarch64`: passes and compiles `syscalls`.
  - Plain `cargo run -p xtask -- kernel --arch aarch64` is blocked before compile by missing `/home/nd/oxide/images/output/live-gnome-aarch64-root.img`; this is an environment/rootfs availability issue, not a code compile failure.

Fix landed in the dirty tree:

- Added `vfs::mount::register_bind_clone_at()` and `register_bind_clone_under()`.
- `sys_mount(MS_BIND)` now uses the resolved source mount id to clone/share the source SB for real bind mounts.
- Removed the fake `BindFs` use from real `mount(MS_BIND)` handling.
- Removed the unconditional `/proc/mountinfo` row trace from `procfs::mounts`.

Why this matters:

- The previous implementation said "Linux binds share source SB" in comments but implemented real binds by creating a fresh synthetic `BindFs` superblock.
- That split truth can corrupt every consumer that compares path/mount identity through `/proc/self/mountinfo`, `statfs`, fstype/source fields, or mount-root fields.
- GNOME/systemd only exposed the contradiction; the bug class is kernel-wide bind/mount identity drift.

Second hosted correctness slice:

- Converted `crates/kernel/syscalls/src/perms_common.rs`:
  - `resolve_path_inode()` now resolves through `resolve_at_lookup()`.
  - `resolve_path_mnt()` now resolves through `resolve_at_lookup()`.
  - Removed the old `resolve_at_result()` string step followed by a second global path walk.
- Converted `crates/kernel/syscalls/src/utime_common.rs`:
  - `resolve_target()` keeps the Linux `utimensat(NULL)` fd-target behavior.
  - Non-null paths now resolve once through `resolve_at_lookup()`.
  - Removed the old `resolve_at_result()` string step followed by a second global path walk.
- Converted `crates/kernel/syscalls/src/137_statfs.rs`:
  - `sys_statfs()` now resolves once through `resolve_at_lookup(AT_FDCWD, LOOKUP_FOLLOW)`.
  - It reports `statfs_for_mount()` from the resolved `VfsPath.mnt_id`.
  - Removed path-string validation followed by `statfs_for_path()` string mount resolution.
- Affected syscall families:
  - `chmod/chown/lchown` through `resolve_path_mnt()`;
  - `file_getattr/file_setattr` through `resolve_path_inode()`;
  - `utime/utimes/utimensat` through `resolve_target()`;
  - `statfs` through the resolved mount id. `fstatfs` was already on the same shape via the fd's `mnt_id`.
- Added hosted VFS proof in `crates/kernel/vfs/tests/namei_at_bind.rs`:
  - `at_relative_bind_result_drives_readonly_mount_decision`
  - It marks a bind mount read-only, resolves a relative child from the bind's mounted root, and asserts the resulting `VfsPath.mnt_id` is the bind mount id whose `MNT_RDONLY` flag is set.
- Verification:
  - `cargo test -p vfs --test namei_at_bind -- --nocapture`: 3/3 pass.
  - `cargo run -p xtask -- kernel --arch x86_64`: passes and compiles `syscalls`.
  - `OXIDE_STUB_BLOBS=1 cargo run -p xtask -- kernel --arch aarch64`: passes and compiles `syscalls`.

Why this matters:

- The previous metadata/statfs helpers could resolve the right dirfd path, stringify it, then re-walk from the task root/cwd and land on a different mount.
- That is Linux-incompatible for bind mounts, chroot/pivot roots, and staged service mount namespaces.
- It can apply `EROFS`, idmap, permission decisions, and `statfs` `f_type/f_flags` reporting to the wrong mount even when the inode happens to be shared.

The current blocker is the same split-truth class in the mount namespace path:

- `systemd-resolved.service: Failed to set up mount namespacing: /proc/kallsyms: Device or resource busy`
- `Failed at step NAMESPACE ... status=226/NAMESPACE`
- `KALLSYMS-MOUNT` traces show repeated `mount(..., flags=0x5000)` = `MS_BIND|MS_REC`.
- Source is usually `/run/systemd/mount-rootfs/proc/kallsyms`; target renders as `/proc/kallsyms`.
- The syscall reaches `bind-under` repeatedly and no `bind-err` is logged, so the kernel is returning success from the bind attach path.
- systemd still repeats until its bind-remount-recursive convergence limit and reports `EBUSY`.

Interpretation:

- This is not an ext4 corruption issue and not a raw `register_bind_*` failure.
- It is almost certainly a visibility/identity failure: the kernel attaches a mount object, but `/proc/self/mountinfo` or later path lookup does not show the mount at the same `(vfsmount,dentry)` identity systemd asked for.
- The suspicious transformation is `sys_mount()` converting the mount target through `resolve_cwd()` + `canonical_mount_path()` and then re-walking by string. For procfd or bind-shared dentries, that can collapse a staged target under `/run/systemd/mount-rootfs/...` back to the global `/proc/...` display path.
- `/proc/mountinfo` currently renders every mount's stored global `mount_point_str()` from `vfs::mount::snapshot()` without reader-root/chroot projection, so systemd's check can miss a mount that was attached under the right object but rendered outside the service's expected root.

## Prior Live-GNOME Evidence: Fixed PrivateTmp `ENOTDIR`

Failing run after the procfd/domainname fix, before the ext4 icache fix:

- `gnome-boot-enotdir-lowtrace-resolved.log`
- First resolved spawn failure:
  - `[11.768] [ENOTDIR] op=resolve_path_flags why=walk tid=3235774466 start_mnt=1 root_mnt=1 path=/var/tmp/systemd-private-...-systemd-resolved.service-yw1FSB/tmp cwd=/`
  - journal: `systemd-resolved.service: Failed to spawn 'start' task: Not a directory`
- Component trace in `gnome-boot-private-tmp-walk-2.log`:
  - `[12.214] [ENOTDIR-WALK] comp=tmp cur=/var/tmp/systemd-private-...-systemd-resolved.service-8VPN5J mnt=1`

Interpretation:

- The walk had successfully reached the generated private tmp parent:
  `/var/tmp/systemd-private-...-systemd-resolved.service-*/`
- It failed before consuming final `tmp`.
- Therefore the generated private tmp parent dentry/inode was non-directory from VFS's point of view.

Confirmed cause:

- ext4 created that parent with `mkdir`, but VFS reused a stale cached inode object for the same ext4 inode number whose `FileType` was still non-directory.
- This is consistent with ext4 create paths invalidating page cache for newly allocated inode numbers but not consistently evicting/replacing stale VFS `SuperBlock` icache entries before `wrap_any_ino()` / `wrap_file()`.

Working-state note:

- Temporary ENOTDIR traces are present in:
  - `crates/kernel/syscalls/src/pathresolve/at.rs`
  - `crates/kernel/syscalls/src/pathresolve/lookup.rs`
  - `crates/kernel/syscalls/src/080_chdir.rs`
  - `crates/kernel/syscalls/src/161_chroot.rs`
  - `crates/kernel/syscalls/src/257_openat.rs`
  - `crates/kernel/vfs/src/namei/walk.rs`
- Ext4 fix exists in:
  - `crates/kernel/ext4/src/rootfs/ops.rs`
  - `crates/kernel/ext4/src/rootfs/inode/special.rs`
  - Added `forget_created_ino()` and used it in rootfs-level and direct inode-op create paths.
- Hosted tests and a bounded live-gnome boot prove this moved past the private-tmp failure.
- These traces must still be removed before committing.

## Active Live-GNOME Blocker: `/proc/kallsyms` Namespace `EBUSY`

Evidence:

- `gnome-boot-icache-reuse-fix.log` reaches:
  - `Reached target multi-user.target - Multi-User System.`
  - `Started gdm.service - GNOME Display Manager.`
- Same run fails service namespace setup:
  - `systemd-resolved.service: Failed to set up mount namespacing: /proc/kallsyms: Device or resource busy`
  - `systemd-resolved.service: Failed at step NAMESPACE ... Device or resource busy`
  - `status=226/NAMESPACE`
- `gnome-boot-kallsyms-trace.log` shows repeated successful bind-path execution:
  - `tag=entry flags=0x5000 target=/proc/kallsyms`
  - `tag=bind-in target=/proc/kallsyms source=/run/systemd/mount-rootfs/proc/kallsyms`
  - `tag=bind-resolved ... source_mnt=<nonzero> target_parent_mnt=<nonzero>`
  - `tag=bind-under ...`
  - no `bind-err`

Interpretation:

- `MS_BIND|MS_REC` attach is returning success, so systemd's `EBUSY` is not the direct syscall return.
- systemd is looping because its post-bind check does not observe the mount at the expected path in `/proc/self/mountinfo`.
- That is consistent with a split between attach identity and rendered path identity.
- Current code stores a rendered path on each `Mount`; `procfs::mounts::build_mountinfo()` emits that stored path globally.
- Linux mountinfo is per reader and path rendering is relative to the reader's root and mount namespace. The current renderer does not project through the task's root/chroot, so staged service-root paths can be invisible or misnamed to systemd.

## Highest-Risk Confirmed Sites

### 1. `resolve_at_result()` collapses dirfd path identity into a string

File: `crates/kernel/syscalls/src/pathresolve/at.rs`

Current behavior:

- `resolve_at_path()` returns a real `VfsPath` and uses `(dirfd.mnt_id, dirfd.dentry)` correctly.
- `resolve_at_result()` returns only `String`.
- For non-`AT_FDCWD` relative paths it does:
  - `f.dentry().absolute_path()`
  - `resolve_against_cwd(base, raw)`
- That loses the fd's `mnt_id`.

Known dangerous pattern:

```rust
let resolved = resolve_at_result(dirfd, raw)?;
resolve_path_result(resolved.as_str(), ...)
```

This is wrong whenever:

- dirfd is inside a bind mount sharing dentries with another path,
- dirfd is inside a moved/pivoted staging root,
- dirfd is in a service mount namespace,
- dirfd refers to a procfd/magic target,
- cwd/root changed after fd open.

Recommended contract:

- Stop using `resolve_at_result()` for authority.
- Add/standardize helpers that return:
  - existing target: `Result<VfsPath, i64>`
  - parent create target: `Result<(VfsPath parent, String leaf), i64>`
  - mountpoint target: `Result<VfsPath or Dentry + parent_mnt_id, i64>`
- Keep strings only for rendering/logging/mountinfo.

### 2. `fchdir()` re-resolves an fd by rendered dentry path

File: `crates/kernel/syscalls/src/081_fchdir.rs`

Risk lines:

- `file.dentry().absolute_path()`
- `resolve_path(&path, false)`
- writes `cwd` string and `cwd_vfs` from the second lookup.

Why this is wrong:

- Linux `fchdir(fd)` sets cwd from `file->f_path`, not from a rendered path.
- Current code throws away `file.mnt_id()` and re-resolves the dentry chain path in the current namespace.
- If fd was opened under `/run/systemd/mount-rootfs`, a bind mount, or a moved root, this can put cwd on the wrong mount.

Fix shape:

- Validate `file.inode().file_type() == Directory`.
- Set `cwd_vfs = VfsPath { mnt_id: file.mnt_id(), dentry: file.dentry().clone(), inode: file.inode().clone(), last_component: None }`.
- Set `cwd` string only as rendered display state, ideally via mount-aware rendering; do not use it as authority.

Fix status:

- Done: `sys_fchdir()` now stores the fd's own `f_path` into `cwd_vfs` and never re-resolves `file.dentry().absolute_path()`.
- Added `vfs::mount::render_path_for_mount()` so `cwd` display text is derived from the fd's mount identity, not the source dentry chain.
- Hosted proof: `bind_path_render_uses_file_mount_not_source_dentry_chain` resolves a child through a bind and asserts it renders as `/a/b/x`, not `/x`.

### 3. chmod/chown/xattr/utime helpers use string re-resolution

Files:

- `crates/kernel/syscalls/src/perms_common.rs`
- `crates/kernel/syscalls/src/utime_common.rs`

Risk sites:

- `resolve_path_inode()`: `resolve_at_result()` then `resolve()`.
- `resolve_path_mnt()`: `resolve_at_result()` then `resolve_path_result()`.
- `resolve_target()` in `utime_common`: `resolve_at_result()` then `resolve_path_result()`.

Why this matters:

- These mutate metadata and enforce EROFS/idmap through the second lookup's mount id.
- If the second lookup lands on a different mount, EROFS/idmap/permission decisions are applied to the wrong object.
- `resolve_at_target_mnt()` is the better pattern because it uses `resolve_at_lookup()` and returns `(inode, mnt_id)` directly.

Fix status:

- `perms_common::{resolve_path_inode,resolve_path_mnt}` are converted to `resolve_at_lookup()` directly and hosted-harnessed through bind-readonly path identity.
- Fixed: `utime_common::resolve_target()` now uses `resolve_at_lookup()` for non-null paths.
- Remaining: audit xattr callers separately; `resolve_xattr_at()` already uses `resolve_at_lookup()`.

### 4. old `stat()`/`lstat()` still goes through cwd string first

File: `crates/kernel/syscalls/src/004_stat.rs`

Risk:

- `resolve_cwd(&raw)` returns a string.
- Then `resolve_path_result()` is authoritative.

Impact:

- `stat()` from a cwd held by `fchdir()`/pivot/move may stat the wrong path if `cwd` string and `cwd_vfs` diverge.
- `newfstatat()`/`statx()` are better because they use `resolve_at_lookup()`.

Fix shape:

- Route legacy `stat/lstat` through `resolve_at_lookup(AT_FDCWD, path_ptr, flags)` so cwd_vfs/mnt_id is preserved.

Fix status:

- Done: `stat_impl()` now resolves directly through `resolve_at_lookup(AT_FDCWD, path_ptr, LookupFlags { follow/no_follow_final })`.
- Removed the `resolve_cwd()` string render plus `resolve_path_result()` second walk from legacy `stat()`/`lstat()`.
- The owning `mnt_id` returned by namei remains authoritative for idmap-out metadata, matching the existing `newfstatat()`/`statx()` path.

### 5. `readlink()` legacy path uses string cwd and inode-only resolver

Files:

- `crates/kernel/syscalls/src/089_readlink.rs`
- `crates/kernel/syscalls/src/267_readlinkat.rs`

Observation:

- `readlinkat()` is mostly correct: uses `resolve_at_path()` with `no_follow_final`.
- `readlink()` uses `resolve_cwd()` then `readlink_resolved_path()`.
- `readlink_resolved_path()` uses `resolve(path_s, true)`, which returns only inode and discards mount.

Impact:

- For ordinary symlink content this may work, but proc/magic links and bind-root-sensitive paths can diverge.
- Any future symlink implementation that needs mount context for magic jumps will be fragile.

Fix shape:

- Implement `readlink()` as `readlinkat(AT_FDCWD, path, ...)`.
- Prefer `VfsPath` in `readlink_resolved_path()` if keeping it.

Fix status:

- Done: `readlink()` now routes through `readlink_at_path(AT_FDCWD, raw, ...)` and no longer uses `resolve_cwd()`.
- Done: non-empty `readlinkat()` uses the same helper, so both paths resolve once through `resolve_at_path(dirfd, raw, no_follow_final)`.
- Removed the inode-only `resolve(path_s, true)` second walk. The final inode's own `get_link()` supplies ordinary symlink and procfs magic-link readlink text.

### 6. `statfs()` validates by string then calls mount resolver by string

File: `crates/kernel/syscalls/src/137_statfs.rs`

Risk:

- `resolve_at_result(AT_FDCWD, raw)` -> string.
- `resolve(abspath)` validates existence.
- `statfs_for_path(abspath)` calls mount resolution by string.

Impact:

- Can report the wrong filesystem for bind-mounted paths or paths under moved cwd/root.

Fix shape:

- Resolve once to `VfsPath`.
- Look up mount by `vp.mnt_id`.
- Run `statfs` on that mount/superblock.

Fix status:

- Done: `sys_statfs()` now resolves with `resolve_at_lookup()` and calls `statfs_for_mount()` on `vp.mnt_id`.

### 7. `openat()` stringifies before creation and dentry binding

File: `crates/kernel/syscalls/src/257_openat.rs`

Former mixed state:

- Some `openat2` paths use `resolve_at_path()` correctly.
- The common path still does `resolve_at_result()` into `path_str`.
- `O_CREAT` uses `resolve_parent(path_str)` and `vfs::mount::resolve_mount(path_str)`.
- `open_dentry(path_str, &inode)` reconstructs a dentry by string.

Risk:

- Creation can occur on the correct parent inode but then the fd dentry may be opened/bound at a different global path.
- `mnt_id` is sometimes derived from `resolve_mount(path_str)` rather than from the parent `VfsPath`.

Fix shape:

- Add `resolve_parent_at(dirfd, raw)` returning parent `VfsPath` and leaf.
- Create through `parent.inode`.
- Bind fd dentry under `parent.dentry` directly, not by global `path_str`.
- Use parent/created mount id from `parent.mnt_id`.

Fix status:

- Done: `openat()` now resolves the ordinary target through `resolve_at_path(dirfd, raw, flags)` even without `openat2` resolve modifiers, so existing-file opens carry the walked `VfsPath.dentry` and `mnt_id` into `File::new_at`.
- Done: `O_CREAT` now uses `resolve_parent_at(dirfd, raw)` and creates through `parent.inode`; the resulting fd dentry is attached with `open_dentry_at(parent.dentry, leaf, inode)`.
- Done: `vfs::file::open_dentry_at()` provides the non-string dcache attach primitive, with hosted coverage in `file_open_dentry::open_dentry_at_uses_supplied_parent`.
- Remaining caveat: `path_str` is still used for Landlock/procfd magic-link detection, fsnotify text, and the legacy backend string passed to `create_anonymous`; those are rendering/compat surfaces, not the fd authority path fixed here.

### 8. mkdir/mkdirat/mknod/link/symlink/unlink/rename share string-parent helpers

Files:

- `crates/kernel/syscalls/src/083_mkdir.rs`
- `crates/kernel/syscalls/src/258_mkdirat.rs`
- `crates/kernel/syscalls/src/133_mknod.rs`
- `crates/kernel/syscalls/src/086_link.rs`
- `crates/kernel/syscalls/src/265_linkat.rs`
- `crates/kernel/syscalls/src/087_unlink.rs`
- `crates/kernel/syscalls/src/263_unlinkat.rs`
- `crates/kernel/syscalls/src/082_rename.rs`
- `crates/kernel/syscalls/src/088_symlink.rs`
- `crates/kernel/syscalls/src/266_symlinkat.rs`
- shared helpers in `crates/kernel/syscalls/src/namei_common.rs`

Risk pattern:

- Callers build a resolved string via `resolve_at_result()`.
- Then call `resolve_parent(&p)` / `path_exists(&p)` / `parent_path(&p)` / `last_component(&p)`.
- These are not mount-authoritative; they rederive parent and target from global path strings.

Impact:

- Create/delete/rename can operate under wrong bind parent.
- `path_exists()` can test a different object than the one being created/replaced.
- fsnotify/inotify hooks may fire under the wrong rendered parent.

Fix shape:

- Replace string helpers with `VfsParent { parent: VfsPath, leaf: String }`.
- Existence check should be `d_lookup`/lookup relative to that exact parent.
- Notify can render separately, but not drive authority.

Fix status:

- Done: `vfs::d_drop_child(parent, leaf)` provides object-parent dcache eviction, with hosted coverage in `dcache_drop_unhash::d_drop_child_unhashes_from_object_parent`.
- Done: `namei_common::resolve_create_parent_at()` preserves the `*at` parent `(mnt_id,dentry,inode)` and leaf identity for create-family syscalls; rendered strings are now produced only for Landlock/logging/fsnotify.
- Done: `mkdir`/`mkdirat` create through `parent.inode`, check target existence relative to the exact parent, check read-only through `parent.mnt_id`, and drop child cache by object parent.
- Done: `mknod`/`mknodat` share the same parent-preserving path; `mknodat` no longer pre-resolves its dirfd-relative path into a global string.
- Done: `symlink`/`symlinkat` now create via the exact `newdirfd` parent identity; the target string remains stored verbatim, matching Linux.
- Done: `unlink`/`unlinkat` now use `resolve_unlink_parent_at()`, mutate `parent.inode`, capture the victim via `child_dentry(parent, leaf)`, check read-only through `parent.mnt_id`, and drop fallback cache by object parent. Rendered path text remains only for Landlock, AF_UNIX pathname registry-key compatibility, and fsnotify display; the AF_UNIX helper no longer calls path-based `d_delete_path()`.
- Done: `rmdir` and `unlinkat(..., AT_REMOVEDIR)` now share `do_rmdir_at(dirfd, raw)`, preserve the walked parent identity, invalidate/unlink the captured victim dentry, and return Linux dot/root errors (`rmdir(".")` `EINVAL`, `rmdir("..")` `ENOTEMPTY`, `rmdir("/")` `EBUSY`; plain `unlink` dot/root forms `EISDIR`).
- Done: `link`/`linkat` now resolve the source inode through the correct `*at` base and no-follow/follow flags, resolve the new name with `resolve_link_parent_at()`, mutate `parent.inode.link_child()`, drop dcache by object parent, and gate `EXDEV` by source/new-parent superblock instead of rendered mount-id strings. The only retained rendered source string is the existing `/proc/self/fd/N` special case for `AT_SYMLINK_FOLLOW`.
- Done: plain `rename`/`renameat`/`renameat2(flags=0|RENAME_NOREPLACE)` now resolve both parents with `resolve_rename_parent_at()`, preserve both `*at` parent identities, reject cross-mount moves by the resolved mount ids, use `vfs::namei::may_rename()`, mutate through `old_parent.inode.rename_child()`, and update dcache/inotify by captured object parents/dentries. Rendered path text remains only for Landlock display.
- Remaining: `RENAME_EXCHANGE` and `RENAME_WHITEOUT` still route through the old `FileSystem::{exchange,whiteout}` string hooks because VFS has no object-parent backend operation for those variants yet. Next slice: add resolved-parent exchange/whiteout inode ops for ext4/tmpfs or a generic VFS op, then delete the special legacy path in `082_rename.rs`.

## Mount Subsystem Split-Truth Sites

### 9. `sys_mount()` mixes target/source strings, dentries, and parent mount hints

File: `crates/kernel/syscalls/src/165_mount.rs`

Current state:

- Many recent fixes correctly add parent mount hints and mountpoint-dentry resolution.
- Still high risk because it computes:
  - `target = resolve_cwd(target_raw)` string
  - `source = resolve_cwd(source_raw)` string
  - `source_d = mount_dentry(&source)`
  - `source_mnt = resolve_path(&source).mnt_id`
  - `target_d = mount_dentry(&target)`
  - `target_parent_mnt = resolve_parent_path(&target).mnt_id`
  - dentry-chain rendering via `target_d.absolute_path()`

Known proven bug already fixed in this session:

- `/proc/self/fd/4` target canonicalized to `/proc/sys/kernel/domainname`.
- Same procfs leaf dentry was shared between staged `/run/systemd/mount-rootfs/proc/...` and real `/proc/...`.
- Bind attached under real `/proc`, not staged root.
- Fix retargeted procfd alias binds to source path when same inode but different dentry/path.

Remaining risk:

- Every branch that compares rendered dentry chain strings with resolved strings is fragile.
- The reliable input is the original walked target `VfsPath` plus parent mount id. That should be passed through explicitly.

### 10. `pivot_root()` resolves args to strings before mountpoint lookup

File: `crates/kernel/syscalls/src/155_pivot_root.rs`

Risk:

- Uses `resolve_cwd()` for both args.
- Then `resolve_mountpoint_dentry(&nr)` / `mount_dentry(&po)`.

Impact:

- Relative args after `MS_MOVE`/pivot can be string-stale.
- Comments already explain why mountpoint dentry must avoid crossing final mount, but the initial string conversion remains suspect.

Fix shape:

- Resolve both args directly through namei from cwd_vfs/root_vfs.
- Return exact `VfsPath`/mountpoint object, not an intermediate string.

### 11. `umount2()` has a known stale-string workaround, still risky

File: `crates/kernel/syscalls/src/166_umount2.rs`

Current behavior:

- Relative path tries `resolve_path_result(path_raw)` then takes `p.dentry.absolute_path()`.
- Falls back to `resolve_cwd()`.

Why risky:

- The comment acknowledges the issue: relative post-pivot `umount2(".")` must use live cwd dentry, not cwd string.
- But the code still converts the resolved dentry back to a string and then calls `resolve_path(trimmed)` later.

Fix shape:

- Keep the resolved `VfsPath` from the first lookup.
- Derive exact mountpoint from `vp.mnt_id` and root-dentry test directly.
- Only render for logs.

### 12. `move_mount()` / `open_tree()` collapse paths to strings

Files:

- `crates/kernel/syscalls/src/429_move_mount.rs`
- `crates/kernel/syscalls/src/428_open_tree.rs`

Risk:

- `move_mount()` uses `resolve_at_result()` for `to_path` and `from_path`, then re-resolves strings.
- `open_tree()` uses `resolve_at_result()` then `vfs::mount::resolve_mount(&abs)`.

Impact:

- Detached mount attach and existing mount move can target the wrong bind parent if the rendered path is ambiguous.

Current mitigation:

- `move_mount()` uses `target_vp.mnt_id` as a destination hint in some branches.

Still needed:

- Make `open_tree()` source resolution return the exact mount id from `VfsPath`, not a string-based `resolve_mount()`.
- Make `move_mount()` use one authoritative path walk for each argument.

### 13. `mount_setattr()` is comparatively correct

File: `crates/kernel/syscalls/src/442_mount_setattr.rs`

Good pattern:

- Handles detached fsmount `AT_EMPTY_PATH` specially.
- Attached path uses `resolve_at_lookup()` and applies changes to `vp.mnt_id`.

Residual watch:

- Propagation branch derives mountpoint via `mountpoint_of(vp.mnt_id)`, which is the right shape.

### 14. VFS mount table still carries rendered strings as state

Files:

- `crates/kernel/vfs/src/mount/model.rs`
- `crates/kernel/vfs/src/mount/graph.rs`
- `crates/kernel/vfs/src/mount/namespace.rs`
- `crates/kernel/vfs/src/mount/attrs.rs`

Important distinction:

- Rendered path strings are necessary for `/proc/mountinfo`.
- They must not be used as lookup authority.

Risks found:

- `mount::resolve_mount(path)` returns `(Mount, path.to_string())` by path string after `walk_to_mount()`.
- On cross-namespace failure it falls back to the caller's root mount with the same input path string. That is useful defensive behavior but dangerous if callers treat the returned string as a verified relative path inside that mount.
- `move_mount_m()` computes `to_abs` via `abs_string(to)`, pure dentry chain, even though comments elsewhere prove bind-shared dentries make pure dentry rendering wrong. If parent hints are correct this may only affect display, but verify it never drives authority.

Audit rule:

- Any function in `vfs::mount` that takes only `&str path` and returns a mount should be treated as legacy convenience unless it is demonstrably only rendering or smoke-test code.

## Ext4/VFS Inode Cache Split Truth

### 15. ext4 newly-created inode numbers can reuse stale VFS inode-cache entries

Files:

- `crates/kernel/ext4/src/rootfs/ops.rs`
- `crates/kernel/ext4/src/rootfs/inode/special.rs`
- `crates/kernel/vfs/src/superblock/icache.rs`

Evidence:

- `SuperBlock::iget(ino, build)` returns an existing live inode if present, without checking that the on-disk ext4 mode still matches the cached VFS `FileType`.
- ext4 create paths allocate/reuse inode numbers.
- Some create paths invalidate page cache by `InodeId`, but not VFS icache.
- The live failure is exactly stale-type shaped: a path created as directory is seen as non-directory during the next lookup.

Specific current suspect path:

- `Ext4StatInodeOps::mkdir()` creates a directory and then `wrap_any_ino(child)`.
- If `child` has a live stale VFS inode cached as regular/symlink/etc, `wrap_any_ino()` can return that old inode.
- Then walking `child/tmp` returns `ENOTDIR`.

Candidate fix shape:

- Any ext4 create allocating a new inode number must evict/replace the VFS inode-cache slot for that ino before wrapping.
- This must cover:
  - regular create
  - mkdir
  - symlink
  - mknod
  - anonymous/tmpfile
  - inode-op direct paths and rootfs helper paths
- It must be tested with forced inode reuse:
  1. create regular file,
  2. hold/drop enough refs to leave/clear dentry as appropriate,
  3. unlink,
  4. create directory reusing same ino,
  5. assert lookup sees `FileType::Directory` and can walk into a child.

Fix status:

- `RootfsState::forget_created_ino()` exists in the current dirty tree.
- It is applied to rootfs-level helpers and to direct `Ext4StatInodeOps::{mkdir,create,symlink,mknod}`.
- Hosted forced-reuse tests pass, and the bounded live-gnome boot moved past private-tmp `ENOTDIR`.
- Remaining work for this slice is cleanup of temporary diagnostics and final integrated boot verification after the active mountinfo blocker is fixed.

## Procfs / Magic-Link Path Identity

### 16. procfs fd links mostly preserve `VfsPath`, but readlink rendering is string-only

Files:

- `crates/kernel/procfs/src/proc_links.rs`
- `crates/kernel/procfs/src/live/self_files.rs`

Good:

- `get_link()` for `/proc/self/fd/N` can return `LinkTarget::Jump(VfsPath { mnt_id, dentry, inode })`.
- That is the right Linux magic-link behavior.

Risk:

- `readlink` target text is built from `file.dentry().absolute_path()`.
- That is acceptable as display text but not as identity.
- Any caller using `/proc/self/fd/N` display text as an authoritative path re-enters the split-truth hazard.

Known proven bug:

- mount target `/proc/self/fd/4` displayed/resolved as real `/proc/...` while source was staged `/run/systemd/mount-rootfs/proc/...`.
- Fix was to detect procfd alias + same inode and attach under the staged source context.

## Syscall Families Ranked by Risk

### Red: must convert away from string authority

- `fchdir`
- `stat/lstat`
- `chmod/chown` path helpers in `perms_common`
- `utime/utimensat` non-null path helper
- `mkdir/mkdirat/mknod/link/symlink/unlink/rename` parent/existence helpers
- `open/openat` common path and create branch
- `statfs`
- `mount`, `umount2`, `pivot_root`, `move_mount`, `open_tree`

### Yellow: partly correct, verify edge cases

- `newfstatat`
- `statx`
- `faccessat/access`
- `readlinkat`
- `name_to_handle_at`
- `mount_setattr`
- xattrat helpers

These use `resolve_at_lookup()` or `VfsPath` more directly, but need spot checks for follow/no-follow and AT_EMPTY_PATH details.

### Green-ish: fd-native operations

- `fstat`
- `fchmod`
- `fchown`
- `ftruncate`
- `fstatfs`
- `utimensat(NULL path)`

These operate on open `File`/`Inode` and generally preserve `mnt_id`. Still verify any helper that later renders/re-resolves.

## Recommended Refactor Plan

0. Keep adding hosted harnesses before each syscall-family conversion.

   - QEMU is now the final integration gate, not the development loop.
   - Every red syscall family below needs a hosted bind/chroot/pivot/dirfd fixture proving the exact Linux contract.
   - Required harness classes:
     - `dirfd` under bind: relative `*at` must stay in the fd's `(mnt,dentry)`.
     - cwd under bind/chroot: legacy non-at syscalls must use `cwd_vfs`, not `cwd` string.
     - staged root + procfd: mount target/source must use walked `VfsPath`, not `/proc/self/fd` text.
     - bind mount reporting: `mountinfo`, `statfs`, fstype/source/root fields must match Linux bind semantics.

1. Define path authority types. **Foundation first.**

   - `ResolvedPath = VfsPath`
   - `ResolvedParent { parent: VfsPath, leaf: String }`
   - `ResolvedMountpoint { mountpoint: Arc<Dentry>, parent_mnt_id: Option<u64>, crossed_mnt_id: Option<u64> }`
   - `ResolvedMountSource { path: VfsPath, rendered: String }`
   - `ResolvedMountTarget { mountpoint: Arc<Dentry>, parent_mnt_id: u64, existing_mnt_id: Option<u64>, rendered: String }`

2. Ban authoritative use of:

   - `Dentry::absolute_path()`
   - `resolve_cwd()`
   - `resolve_at_result()`
   - `resolve_against_cwd()`
   - `vfs::mount::resolve_mount(&str)`

   Allowed only for display/logging or transitional wrappers with explicit comments.

3. Add the hosted harness before changing more boot behavior.

   - Build a small mount namespace test that reproduces systemd's `bind_remount_recursive` shape:
     - root recursive bind to staged root,
     - procfs leaf under `/run/systemd/mount-rootfs/proc/kallsyms`,
     - target passed as a procfd or bind-shared dentry,
     - `MS_BIND|MS_REC` self-bind,
     - read mountinfo as the current task.
   - Assertions:
     - the new mount is keyed by `(walked_parent_mnt_id, target_dentry)`, not by pure dentry parent,
     - mountinfo contains the path systemd checks,
     - repeating the bind does not create an invisible stack that still fails convergence.

4. Convert syscall shared helpers first.

   - Replace `namei_common::resolve_parent()` with `resolve_parent_at(dirfd, raw, flags)`.
   - Replace `path_exists(&str)` with `exists_under(parent: &VfsPath, leaf: &str, follow/no-follow)`.
   - Replace `parent_path()/last_component()` authority use with fields from `ResolvedParent`.

5. Convert metadata syscalls next.

   - `stat/lstat` -> `resolve_at_lookup(AT_FDCWD, ...)`.
   - `chmod/chown/utime` helpers -> `resolve_at_lookup()`.
   - `statfs` -> `VfsPath.mnt_id`.

6. Convert create/delete/rename.

   - Done: `open/openat O_CREAT`
   - Done: `mkdir/mkdirat`
   - Done: `mknod/mknodat`
   - Done: `symlink/symlinkat`
   - Done: `unlink/unlinkat/rmdir`
   - Done: `link/linkat`
   - Plain `rename/renameat/renameat2` done; remaining `RENAME_EXCHANGE`/`RENAME_WHITEOUT` backend interface.

7. Convert mount syscalls. **This is the current integration blocker.**

   - Stop making `sys_mount()` authority from:
     - `target = resolve_cwd(target_raw)`
     - `target = canonical_mount_path(target)`
     - `target_d = mount_dentry(&target)`
     - `target_parent_mnt = resolve_parent_path(&target)`
     - `dentry_chain = target_d.absolute_path()`
   - Resolve source and target once into `VfsPath`-derived objects:
     - source existing path: `VfsPath { mnt_id, dentry, inode }`
     - target mountpoint dentry: final component dentry without crossing final mount when required,
     - target parent mount id: the `path.mnt` from the walked parent, not a later string lookup.
   - Done so far:
     - real `MS_BIND` clones now share source SB through `register_bind_clone_*`.
     - staged-proc bind identity + SB sharing is hosted-harnessed.
   - Still required:
     - replace `target = resolve_cwd(target_raw)`/`canonical_mount_path()` authority with one `VfsPath` walk.
     - replace source `mount_dentry(&source)` + `resolve_path(&source)` double walk with one source `VfsPath`.
     - make mountinfo root/source rendering call a shared VFS helper and test it hosted.
   - Thread the target parent mount id into every remaining legacy bind helper unconditionally when it is known, then delete the legacy fake-SB path once all callers use `register_bind_clone_*`.
   - Keep rendered strings only as mountinfo payload, derived from the walked mount context.
   - Make `canonical_mount_path()` non-authoritative or remove it from the mount attach path. Procfd/magic-link jumps should resolve to a `VfsPath`, not to a display string.
   - Make `/proc/self/mountinfo` render from the reader task's root/cwd/mount namespace view, not as a global list of stored absolute strings.

8. Fix ext4 inode-cache coherence. **First slice tested**

   - Before wrapping newly allocated ext4 inode number, invalidate/rebuild VFS icache slot.
   - Add forced inode-reuse tests.
   - Verify direct inode-op create paths and rootfs helper paths.
   - Current slice:
     - `RootfsState::forget_created_ino()` evicts the ext4 page cache slot and VFS `SuperBlock` icache slot for a freshly allocated inode number.
     - Rootfs helper creates call it for regular files, anonymous files, symlinks, device nodes, and directories.
     - Direct ext4 `InodeOps` creates now call it for `create`, `mkdir`, `symlink`, and `mknod`.
     - Regression `iop_create_reused_ino_rebuilds_cached_type` forces file->unlink->mkdir reuse of the same inode number while the stale regular-file `Arc` is live, then asserts the new wrapper is a directory and not the stale `Arc`.
   - Evidence:
     - `cargo test -p ext4 --test rename_overwrite_image iop_create_reused_ino_rebuilds_cached_type -- --nocapture` passed.
     - `cargo test -p ext4 --test rename_overwrite_image -- --nocapture` passed: 6/6.
     - `cargo test -p vfs --test mount_propagation_pivot -- --nocapture` passed: 6/6.
   - Still required:
     - live-gnome boot proof that `systemd-resolved` no longer fails with private-tmp `ENOTDIR`.
     - cleanup of temporary ENOTDIR traces before final PR.

9. Remove temporary diagnostics.

   - Remove all `[ENOTDIR]` / `[ENOTDIR-WALK]` temporary traces.
   - Keep only focused tests and production comments.

## Test Harnesses Needed

### Hosted VFS mount-context tests

- Build a shared dentry mounted at two paths; assert operations through each path keep distinct `mnt_id`.
- `fchdir(fd in bind)` then relative `stat/open/mkdir` must resolve under fd's mount, not dentry's global parent chain.
- `dirfd` relative `mkdirat/openat/chmodat/statx` inside bind must use fd's `mnt_id`.

### Ext4 inode reuse test

- Implemented first form on a writable ext4 image:
  1. create regular file,
  2. unlink it,
  3. create directory with same name and assert same inode number is reused,
  4. assert VFS wrapper type is Directory,
  5. assert the new wrapper is not the stale regular-file `Arc`.
- Follow-up still useful: create/walk a child under the reused directory through full namei.

### Systemd PrivateTmp harness

- Reproduce without full GNOME:
  - create `/var/tmp/systemd-private-<id>-unit/tmp`
  - execute the exact syscall sequence systemd uses for `PrivateTmp=`.
  - assert parent and child are directories and `stat()` / `newfstatat()` agree.

### Mount namespace mini-harness

- `open_tree(AT_RECURSIVE)` root clone.
- `move_mount` under staged root.
- bind `/proc/self/fd/N` leaf into staged proc.
- remount bind read-only.
- check mountinfo rendered path and `resolve_path_flags()` `mnt_id`.

## Current Working-State Warning

The tree is dirty with multiple prior changes and temporary traces. Before any final fix PR:

- Decide whether to keep and complete `forget_created_ino()` or replace it with a cleaner ext4/VFS icache API.
- Remove temporary traces in syscall and VFS namei files.
- Re-run:
  - `cargo test -p vfs --test mount_propagation_pivot -- --nocapture`
  - targeted ext4 inode-reuse test once added
  - live-gnome boot fail-fast for `systemd-resolved`, `status=226/NAMESPACE`, `Started gdm`, `Reached target graphical`
