// Namespace-mutating syscalls — unlink / mkdir / rmdir / rename —
// per `15§5` / `16§3`. Routed to the ext4 mount via dev_ext4 for
// real-fs paths; tmpfs/devfs/procfs paths return Erofs (those
// pseudo filesystems don't accept create/remove from userspace).
//
// All handlers migrated to per-file modules (one syscall = one file,
// docs/53 §0): 082_rename, 083_mkdir, 084_rmdir, 086_link,
// 087_unlink, 088_symlink, 133_mknod, 258_mkdirat, 259_mknodat,
// 263_unlinkat, 264_renameat, 265_linkat, 266_symlinkat,
// 316_renameat2. Shared helpers live in namei_common.rs.

#![cfg(target_os = "oxide-kernel")]
