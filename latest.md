# Latest

Archived prior ledger: `latest-2.md`.

Active slice: open/install correctness. `openat` still inlines fd installation after path resolution instead of using the shared `vfs::file::install_open_at` helper; this keeps the O_CLOEXEC, file-open hook, fd allocation, and created-inode reference-drop contract split between syscall code and VFS. Landlock rule-prefix fix is committed as `6cdb13dc`.
