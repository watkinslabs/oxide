// Module manifest: `root` owns root/chroot state; `cred` owns VFS cred snapshots;
// `lookup` owns path walking; `dcache` owns cache invalidation/moves; `exec`
// owns executable reads; `at` owns dirfd/*at helpers.

#![cfg(target_os = "oxide-kernel")]

mod at;
mod cred;
mod dcache;
mod exec;
mod lookup;
mod root;

pub use at::{AT_FDCWD, resolve_at, resolve_at_lookup, resolve_at_path, resolve_at_result, resolve_confined, resolve_cwd};
pub use cred::{current_cred, current_cred_real};
pub use dcache::{d_delete_path, d_drop_path, d_invalidate_path, d_move_path, mount_dentry};
pub use exec::{read_exec, read_exec_inode};
pub use lookup::{resolve, resolve_parent_path, resolve_path, resolve_path_flags, resolve_path_result, resolve_result};
pub use root::root_dentry;
