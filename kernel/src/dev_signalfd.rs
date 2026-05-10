// Thin re-export shim per `52§8` migration. Implementation lives in
// `crates/signalfd`. Existing `crate::dev_signalfd::*` callers
// compile unchanged; shim disappears at Stage C.

pub use signalfd::*;
