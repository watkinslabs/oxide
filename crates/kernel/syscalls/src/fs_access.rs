// access(2) / faccessat(2) handlers now live in their own per-syscall
// modules (`53§0`): `s021_access.rs`, `s269_faccessat.rs`; the shared
// `do_access` helper lives in `fs_access_common.rs`. Re-exported here
// so `crate::fs_access::sys_*` dispatch paths keep resolving.
#![cfg(target_os = "oxide-kernel")]

pub use crate::s021_access::sys_access;
pub use crate::s269_faccessat::sys_faccessat;
