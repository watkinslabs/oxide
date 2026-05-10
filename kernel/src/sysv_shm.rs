// Thin re-export shim per `52§8` migration. Implementation lives in
// `crates/ipc/src/sysv_shm.rs`. Existing `crate::sysv_shm::*` callers
// compile unchanged; shim disappears at Stage C.

pub use ipc::sysv_shm::*;
