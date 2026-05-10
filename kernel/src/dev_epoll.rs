// Thin re-export shim per `52§8` migration. Implementation lives in
// `crates/epoll`. Existing `crate::dev_epoll::*` callers compile
// unchanged; shim disappears at Stage C.

pub use epoll::*;
