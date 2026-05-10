// Thin re-export shim per `52§8` migration. Implementation lives in
// `crates/cpu`. Existing `crate::cpu_topology::*` callers compile
// unchanged; shim disappears at Stage C.

#![cfg(target_os = "oxide-kernel")]

pub use cpu::*;
