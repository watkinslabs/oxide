// statfs(2)/fstatfs(2) — slots 137/138. Handlers split one-per-file per
// docs/53 §0; this module re-exports them so existing call sites
// (`crate::statfs::sys_statfs`) keep resolving. Shared helpers live in
// `statfs_common`.

#![cfg(target_os = "oxide-kernel")]

pub use crate::s137_statfs::sys_statfs;
pub use crate::s138_fstatfs::sys_fstatfs;
