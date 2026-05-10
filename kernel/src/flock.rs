// Thin re-export shim per `52§8` migration. Implementation lives in
// `crates/flock`. Existing `crate::flock::*` callers compile
// unchanged; shim disappears at Stage C.

pub use ::flock::*;
