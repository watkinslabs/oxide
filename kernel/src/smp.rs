// Thin re-export shim per `52§8` migration. Implementation lives in
// `crates/smp` (the cross-arch SMP orchestration). Existing
// `crate::smp::*` callers compile unchanged; shim disappears at
// Stage C.

pub use ::smp::*;
