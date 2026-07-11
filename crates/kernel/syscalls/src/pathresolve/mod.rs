// Module manifest: `root` owns root/chroot state; `cred` owns VFS cred snapshots;
// `lookup` owns path walking; `exec`
// owns executable reads; `at` owns dirfd/*at helpers.

#![cfg(target_os = "oxide-kernel")]

mod at;
mod cred;
mod exec;
mod lookup;
mod root;

pub use at::{AT_FDCWD, resolve_at_lookup, resolve_at_path, resolve_confined, resolve_parent_at};
pub use cred::{current_cred, current_cred_real};
pub use exec::{read_exec, read_exec_inode};
pub use lookup::{dup_fd_target, procfd_path, resolve_mount_target_raw, resolve_path_raw};
pub use root::root_dentry;
