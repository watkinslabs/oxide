// AF_UNIX socket primitives for kernel networking and hosted builds.
//
// Module manifest:
// - types.rs     : shared public types (`UnixEnd`, `EndCred`).
// - events.rs    : helper wake-notification routines for epoll/read waiters.
// - stream.rs    : stream socketpair implementation (`UnixPair`).
// - msg_pair.rs  : seqpacket/datagram socketpair implementation (`UnixMsgPair`).
// - dgram.rs     : bound AF_UNIX datagram queue implementation (`UnixDgramQueue`).
// - listener.rs  : path registry / listener accept queue helpers.
// - gc.rs        : serialized SCM_RIGHTS cycle collection.
// - gc_test_support.rs: deterministic hosted collector schedules.
// - test_support.rs: canonical hosted AF_UNIX fixture serialization.
// - tests.rs     : unit tests for the AF_UNIX data paths.

extern crate alloc;

pub mod events;
pub mod types;
pub mod stream;
pub mod msg_pair;
pub mod dgram;
pub mod listener;
pub mod gc;
#[cfg(test)]
pub(crate) mod gc_test_support;
#[cfg(test)]
pub(crate) mod test_support;

#[cfg(target_os = "oxide-kernel")]
pub(crate) use events::{wake_msgpair_peer_subs, wake_peer_subs};

pub use types::{EndCred, UnixEnd};

pub use stream::{UnixPair, UnixRing, UnixStreamError};
pub use msg_pair::{UnixMsg, UnixMsgError, UnixMsgKind, UnixMsgPair, UnixMsgRing};
pub use dgram::{UnixDgram, UnixDgramQueue};
pub use listener::{unix_path_display, unix_path_is_abstract, UnixAddr, UnixAddrKey, UnixConnectError, UnixListener, UnixRegistry};
pub use gc::{classify_files, collect as collect_scm_rights, inflight_rights, register_file, transfer_guard, GcLink, GcNode, GcPin, GcRights, GcTransferGuard};
#[cfg(target_os = "oxide-kernel")]
pub use gc::bind_file;

#[cfg(test)]
mod tests;
