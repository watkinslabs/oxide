// Thin re-export shim per `52§8` migration policy. Implementation
// lives in `crates/vfs/src/inode_times.rs` (Stage B-1). Existing
// `crate::inode_times::*` call sites compile unchanged; this shim
// disappears once Stage C rewrites imports to `vfs::inode_times::*`.

#![cfg(target_os = "oxide-kernel")]

pub use vfs::inode_times::*;
