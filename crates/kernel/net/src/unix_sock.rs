// AF_UNIX socket primitives for kernel networking and hosted builds.
//
// Module manifest:
// - types.rs     : shared public types (`UnixEnd`, `EndCred`).
// - events.rs    : helper wake-notification routines for epoll/read waiters.
// - stream.rs    : stream socketpair implementation (`UnixPair`).
// - msg_pair.rs  : seqpacket/datagram socketpair implementation (`UnixMsgPair`).
// - dgram.rs     : bound AF_UNIX datagram queue implementation (`UnixDgramQueue`).
// - listener.rs  : listener state, shutdown, accept queue, and waiters.
// - registry.rs  : path registry for listeners and datagram queues.
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
pub mod registry;
pub mod gc;
#[cfg(test)]
pub(crate) mod gc_test_support;
#[cfg(test)]
pub(crate) mod test_support;

#[cfg(target_os = "oxide-kernel")]
pub(crate) use events::{wake_msgpair_peer_subs, wake_peer_subs};

pub use types::{EndCred, UnixEnd};

pub use stream::{UnixPair, UnixRing, UnixStreamError, UnixStreamSendError};
pub use msg_pair::{UnixMsg, UnixMsgError, UnixMsgKind, UnixMsgPair, UnixMsgRing, UnixMsgSendError};
pub use dgram::{UnixDgram, UnixDgramQueue};
pub use listener::{UnixAddr, UnixAddrKey, UnixConnectError, UnixListener};
pub use registry::{unix_path_display, unix_path_is_abstract, UnixRegistry};
pub use gc::{bind_file, classify_files, collect as collect_scm_rights, inflight_rights, register_file, transfer_guard, GcLink, GcNode, GcPin, GcRights, GcTransferGuard};

#[cfg(test)]
mod tests;
