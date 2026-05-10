// Thin re-export shim per `52§8` migration. Implementation lives in
// `crates/userfaultfd`. Existing `crate::userfaultfd::*` callers
// compile unchanged; shim disappears at Stage C.

pub use userfaultfd::*;
