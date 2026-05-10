// Thin re-export shim per `52§8` migration. Implementation lives in
// `crates/sched/src/kthread.rs`. Existing `crate::kthread::*` callers
// (lib.rs boot smoke) compile unchanged; shim disappears at Stage C.

pub use sched::kthread::*;
