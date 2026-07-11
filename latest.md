# Latest

Archive: `latest 2.md` holds the prior ledger through the xattr split-truth cleanup.

Active slice: filesystem syscall path identity. Goal is to remove lexical/string fallback authority from VFS-facing syscalls and make every path mutation operate on the resolved Linux `struct path` equivalent: `(mount id, dentry, inode)`.

Current diagnosis:
- Old `*at` helpers rendered dirfd/cwd/root to strings, normalized text, then re-walked from the global root on misses. That creates split truth after bind mounts, `MS_MOVE`, `pivot_root`, `chroot`, `open_tree`, and private mount namespace cloning.
- Parent-mutating syscalls (`mkdir*`, `unlink*`, `rmdir`, `rename`, `link*`, `symlink*`, `mknod*`, AF_UNIX `bind`) must resolve the parent once and mutate that parent inode/dentry directly. Whole-path cache invalidation and parent-string fsnotify hooks are wrong because multiple mounts can expose the same rendered string or the same dentry at different mount identities.
- Mount syscalls must preserve the walked mount id. `open_tree(AT_EMPTY_PATH)`, procfd targets, `move_mount`, `fspick`, `mount_setattr`, `umount2`, `pivot_root`, and `chroot(".")` all need live `VfsPath` inputs, not display strings.
- Mount namespace copy must remap task `cwd_vfs`/`root_vfs` mount ids from parent namespace mounts to cloned child namespace mounts. Keeping old ids after `CLONE_NEWNS` is stale-path identity.
- Inotify/fanotify watch setup and dirent hooks must key by inode/parent inode instead of re-resolving rendered parent paths.
- `/proc/<pid>/mounts`, `/proc/<pid>/mountinfo`, and `fdinfo mnt_id` must report the target task/open file mount namespace identity; hard-coded global mount views make userspace see the wrong namespace.

Harness coverage added/used:
- `crates/kernel/fs/tests/fs_syscall_model.rs`: hosted model over mounted ext4-like roots plus tmpfs/dev/proc/sys shapes, covering open/create, mkdir, rename, hardlink, symlink follow/nofollow, xattr follow/nofollow/dirfd, permissions, ownership, sticky directories, chmod/chown, mknod, cwd/fchdir, readonly xattr behavior, and logind-style cross-namespace visibility.
- `crates/kernel/vfs/tests/open_tree_recursive_clone.rs`: detached clone, recursive clone, hash-only clone, empty-path dirfd clone, and staged bind clone parent-mount behavior.
- `crates/kernel/vfs/tests/greeter_sysfs_after_pivot.rs`: sysfs visibility after pivot/root movement and shared propagation.
- `crates/kernel/vfs/tests/mount_propagation_pivot.rs`: namespace copy/remap and staged root/pivot mount behavior.

Verification so far:
- `cargo test -p fs --test fs_syscall_model -- --nocapture` passed.
- `cargo test -p vfs --test mount_propagation_pivot -- --nocapture` passed 10/10.
- `cargo test -p vfs --test open_tree_recursive_clone -- --nocapture` passed 4/4.
- `cargo test -p vfs --test greeter_sysfs_after_pivot -- --nocapture` passed 5/5.
- `cargo test -p vfs --lib -- --nocapture` passed 97/97.
- `cargo check -p syscalls` passed for x86_64 kernel target.
- `cargo check -p kmain` passed for x86_64 and aarch64 kernel targets.

Commit plan:
- Stage only the coherent path-identity slice: syscall pathresolve/namei/mount callers, VFS mount/namei/file-hook support, inotify watch resolution, proc mount/fdinfo namespace reporting, the hosted filesystem syscall model, and this ledger rotation.
- Exclude unrelated dirty work: ext4 internals, allocator poison/canary diagnostics, boot Cargo changes, netlink tests, MM debug, and generated boot logs.
- Commit as `fix(path): resolve filesystem syscalls by vfs identity` after staged diff/check pass.

Known remaining cleanup after this slice:
- Audit any remaining boot/rootfs-only `resolve_abs` or string-rendered setup helpers and either prove they are initialization-only or move them to identity-based helpers.
- Continue syscall surface modeling beyond the current filesystem harness until non-happy-path Linux semantics are covered across tmpfs/devfs/procfs/sysfs/ext4-backed operations.

Completed follow-up slice: Landlock path-beneath no longer stores or checks rendered path prefixes. Rules capture the parent fd's live `(mnt_id,dentry)` identity, and checks compare target `VfsPath` ancestry within the same mount. Existing-object checks (`openat`, `truncate`, `rename`, `unlink`, `rmdir`) pass resolved object identity; create/link/symlink/mknod checks pass the resolved parent identity before backend mutation because the destination child does not exist yet. This removes another string split-truth surface where bind mounts, chroot, or namespace movement could make a rendered prefix name the wrong object. Evidence: `cargo test -p security landlock -- --nocapture` passed 2/2; `cargo check -p syscalls` passed for x86_64 kernel target; `cargo test -p fs --test fs_syscall_model -- --nocapture` passed; `cargo check -p kmain` passed for x86_64 and aarch64 kernel targets.

Completed follow-up slice: the shared `*at` empty-path resolver no longer treats `path_ptr == NULL` as a real empty string. With `AT_EMPTY_PATH` set, callers such as `fchmodat`, `fchownat`, and xattr-at helpers could previously operate on `dirfd` instead of returning Linux's required `EFAULT` for a bad pathname pointer. `at_path_empty` now returns `Result<bool, errno>`, rejects NULL/out-of-range/unreadable pointers with `EFAULT`, and only reports empty for a successfully read zero-length C string. Evidence: `cargo check -p syscalls` passed for x86_64 kernel target; `cargo check -p kmain` passed for x86_64 and aarch64 kernel targets; `git diff --check` clean.

Completed follow-up slice: mount path rendering no longer strips a mount root by lexical byte prefix alone. `render_path_for_mount` and the internal recursive renderer now require the target dentry to be at/below the mount root by dentry ancestry before deriving a suffix. This prevents a bind rooted at `/foo` and mounted at `/mnt` from rendering sibling `/foobar` as `/mntbar`. Evidence: added `render_path_for_mount_rejects_lexical_prefix_sibling`; `cargo test -p vfs --test mount_path_projection -- --nocapture` passed 10/10; `cargo test -p vfs --test mount_propagation_pivot -- --nocapture` passed 10/10; `cargo test -p vfs --test open_tree_recursive_clone -- --nocapture` passed 4/4.

Completed follow-up slice: mountinfo field 4 (`root`) now uses dentry ancestry before trimming the superblock root prefix. The prior code used byte-prefix stripping, so a bind root `/foobar` with superblock root `/foo` could be reported as `/bar` even though it is not below `/foo`. Evidence: added `mountinfo_root_field_rejects_lexical_prefix_sibling`; `cargo test -p vfs --test mount_path_projection -- --nocapture` passed 11/11; `cargo test -p vfs --test mount_propagation_pivot -- --nocapture` passed 10/10; `cargo test -p vfs --test open_tree_recursive_clone -- --nocapture` passed 4/4; `cargo check -p syscalls` passed for x86_64 kernel target; `cargo check -p kmain` passed for x86_64 and aarch64 kernel targets.

Completed follow-up slice: the raw syscall path resolver no longer turns all-slash nonempty paths into `ENOENT`. `trim_mount_raw("///")` previously trimmed every slash and rejected the empty result, so `chdir("///")`, `chroot("///")`, `fspick("///")`, mount target resolution, and other callers of `resolve_path_raw`/`resolve_mount_target_raw` diverged from Linux root-path semantics. It now preserves true empty string as `ENOENT` but canonicalizes all-slash input to `/`. Evidence: `cargo test -p fs --test fs_syscall_model -- --nocapture` passed; `cargo check -p syscalls` passed for x86_64 kernel target; `cargo check -p kmain` passed for x86_64 and aarch64 kernel targets.
