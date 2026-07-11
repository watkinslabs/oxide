# Latest

Archived prior ledger: `latest-2.md`.

Active slice: open/install correctness. `openat` still inlines fd installation after path resolution instead of using the shared `vfs::file::install_open_at` helper; this keeps the O_CLOEXEC, file-open hook, fd allocation, and created-inode reference-drop contract split between syscall code and VFS. Landlock rule-prefix fix is committed as `6cdb13dc`.

Open/install slice complete: `openat` now routes final file construction, file open hook, fd allocation, and FD_CLOEXEC handling through `vfs::file::install_open_at`; stale string-path open helpers are gone from `open_common`; the helper now treats `O_TMPFILE` as exempt from the embedded `O_DIRECTORY` target check. Evidence: `cargo test -p vfs --lib -- --nocapture` passed 97/97; `cargo check -p kmain` passed for x86_64+aarch64 kernel targets.

Chmod AF_UNIX bypass removed: `bind(AF_UNIX)` already creates a real `S_IFSOCK` inode, so chmod now resolves the path and runs the normal chmod permission/EROFS/setattr path instead of returning success from the Unix registry. Evidence: `cargo check -p syscalls` passed for x86_64 kernel target; `cargo check -p kmain` passed for x86_64+aarch64 kernel targets.

Devpts smoke no longer depends on global absolute `vfs::resolve_abs`; slave validation uses the devpts filesystem root that `allocate_pair` already mirrors into. Evidence: `cargo check -p devpts` passed for x86_64 kernel target; `cargo check -p kmain` passed for x86_64+aarch64 kernel targets.

Xattr split-truth removal complete: legacy slots 188-199 are normal syscall shims routed through `syscalls::xattr_common`, path/fd/mount-id resolution now lives in the syscall crate, and `fs::xattr` only accepts already-resolved inodes plus user xattr buffers. The old global `(fsid, ino) -> xattr map` fallback is deleted; filesystems without `SimpleXattrs` now return `EOPNOTSUPP` instead of silently storing attributes outside the owning inode/filesystem. `getxattr` still maps missing names to `ENODATA`; unsupported backends are no longer collapsed into absence. Regression coverage added for unsupported-backend `EOPNOTSUPP` and fs-owned xattr round-trip. Evidence: `cargo test -p fs --lib xattr -- --nocapture` passed 5/5 xattr tests; `cargo check -p fs`, `cargo check -p vfs`, `cargo check -p syscalls`, and `cargo check -p kmain` passed for x86_64 kernel target; `cargo check -p kmain` passed for aarch64 kernel target.
