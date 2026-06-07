// poll / ppoll — per-syscall modules (docs/53 §0). This file is now
// the module root: each handler lives in its own `<NNN>_<name>.rs`
// (slot 7 poll, slot 271 ppoll); `monotonic_ns` shared via
// `poll_common`. Re-exported here so `crate::poll::sys_poll` /
// `sys_ppoll` keep resolving (fs.rs re-export + dispatch).

#![cfg(target_os = "oxide-kernel")]

#[path = "poll_common.rs"] pub mod poll_common;
#[path = "007_poll.rs"]    pub mod s007_poll;
#[path = "271_ppoll.rs"]   pub mod s271_ppoll;

pub use s007_poll::sys_poll;
pub use s271_ppoll::sys_ppoll;
