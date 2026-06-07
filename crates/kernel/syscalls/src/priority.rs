// getpriority / setpriority (slots 140/141). Per docs/53 §0 each syscall
// lives in its own file; the shared which/who target resolution lives in
// priority_common (also used by ioprio_set/get, slots 251/252). This
// module re-exports the two handlers and the common module so existing
// `crate::priority::{...}` paths keep resolving.

#![cfg(target_os = "oxide-kernel")]

#[path = "priority_common.rs"] pub mod priority_common;
#[path = "140_getpriority.rs"] mod s140_getpriority;
#[path = "141_setpriority.rs"] mod s141_setpriority;

pub use s140_getpriority::sys_getpriority;
pub use s141_setpriority::sys_setpriority;
