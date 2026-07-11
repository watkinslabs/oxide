# Latest

Archived prior ledger: `latest-2.md`.

Active slice: open/install correctness. `openat` still inlines fd installation after path resolution instead of using the shared `vfs::file::install_open_at` helper; this keeps the O_CLOEXEC, file-open hook, fd allocation, and created-inode reference-drop contract split between syscall code and VFS. Landlock rule-prefix fix is committed as `6cdb13dc`.

Open/install slice complete: `openat` now routes final file construction, file open hook, fd allocation, and FD_CLOEXEC handling through `vfs::file::install_open_at`; stale string-path open helpers are gone from `open_common`; the helper now treats `O_TMPFILE` as exempt from the embedded `O_DIRECTORY` target check. Evidence: `cargo test -p vfs --lib -- --nocapture` passed 97/97; `cargo check -p kmain` passed for x86_64+aarch64 kernel targets.

Chmod AF_UNIX bypass removed: `bind(AF_UNIX)` already creates a real `S_IFSOCK` inode, so chmod now resolves the path and runs the normal chmod permission/EROFS/setattr path instead of returning success from the Unix registry. Evidence: `cargo check -p syscalls` passed for x86_64 kernel target; `cargo check -p kmain` passed for x86_64+aarch64 kernel targets.
