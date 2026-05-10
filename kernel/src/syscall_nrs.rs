// Thin re-export shim per `52§8` migration policy. The Linux x86_64
// NR table moved to `crates/syscall/src/nrs.rs` so domain crates
// (vfs, ipc, net, etc.) can reference NR constants without depending
// on `kernel`. Existing `crate::syscall_nrs::NR_*` call sites compile
// unchanged; this shim disappears once Stage C rewrites imports to
// `syscall::nrs::*`.

#![cfg(target_os = "oxide-kernel")]
#![allow(dead_code)]

pub use syscall::nrs::*;
