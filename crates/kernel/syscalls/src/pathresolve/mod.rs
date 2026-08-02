// Module manifest: `root` owns root/chroot state; `cred` owns VFS cred snapshots;
// `lookup` owns path walking; `exec`
// owns executable reads; `at` owns dirfd/*at helpers.

#![cfg(target_os = "oxide-kernel")]

mod at;
mod cred;
mod exec;
mod lookup;
mod root;

pub(crate) use at::at_path_empty;
pub use at::{AT_FDCWD, resolve_at_lookup, resolve_at_lookup_cred, resolve_at_lookup_maybe_null, resolve_at_or_dirfd, resolve_at_or_fd, resolve_at_path, resolve_confined, resolve_parent_at, resolve_parent_at_flags};
pub use cred::{current_cred, current_cred_real, file_cred_for};
pub use exec::{exec_permission, open_exec, read_exec_inode};
pub use lookup::{dup_fd_target, procfd_path, resolve_mount_target_raw, resolve_path_raw};
pub use root::root_dentry;
