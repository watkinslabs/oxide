// AF_UNIX socket primitives for kernel networking and hosted builds.
//
// Module manifest:
// - types.rs     : shared public types (`UnixEnd`, `EndCred`).
// - events.rs    : helper wake-notification routines for epoll/read waiters.
// - stream.rs    : stream socketpair implementation (`UnixPair`).
// - msg_pair.rs  : seqpacket/datagram socketpair implementation (`UnixMsgPair`).
// - dgram.rs     : bound AF_UNIX datagram queue implementation (`UnixDgramQueue`).
// - listener.rs  : path registry / listener accept queue helpers.
// - tests.rs     : unit tests for the AF_UNIX data paths.

extern crate alloc;

pub mod events;
pub mod types;
pub mod stream;
pub mod msg_pair;
pub mod dgram;
pub mod listener;

#[cfg(target_os = "oxide-kernel")]
pub(crate) use events::{wake_msgpair_peer_subs, wake_peer_subs};

pub use types::{EndCred, UnixEnd};

pub use stream::{UnixPair, UnixRing};
pub use msg_pair::{UnixMsg, UnixMsgPair, UnixMsgRing};
pub use dgram::{UnixDgram, UnixDgramQueue};
pub use listener::{unix_path_display, unix_path_is_abstract, UnixListener, UnixRegistry};

#[cfg(test)]
mod tests;
