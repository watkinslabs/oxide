// Thin re-export shim per `52§8` migration. Implementation lives in
// `crates/cpu`. Existing `crate::cpu_topology::*` callers compile
// unchanged; shim disappears at Stage C. Not cfg-gated — kernel
// lib.rs + smp.rs + sched/* reference these symbols from hosted
// test builds too (the cpu crate is target-clean).

pub use cpu::*;
