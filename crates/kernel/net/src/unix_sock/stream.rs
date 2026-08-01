// Module manifest:
// - types.rs     : stream pair, directional ring, and public error types.
// - pair.rs      : pair construction, endpoint identity, names, and credentials.
// - send.rs      : byte and ancillary-data writes plus reader notification.
// - read.rs      : plain reads, peeking, and atomic blocking-read parking.
// - coalesce.rs  : control-buffer-less receive boundaries (rights / sender change).
// - recv.rs      : transactional boundary-aware recvmsg reads.
// - lifecycle.rs : shutdown, release, reset, EOF, and readiness state.
// - trace.rs     : feature-gated D-Bus stream diagnostics.

mod coalesce;
mod lifecycle;
mod pair;
mod read;
mod recv;
mod send;
#[cfg(feature = "debug-dbus")]
mod trace;
mod types;

#[cfg(target_os = "oxide-kernel")]
pub use lifecycle::ArmStreamRead;
#[cfg(target_os = "oxide-kernel")]
pub use lifecycle::ArmStreamWrite;
#[cfg(target_os = "oxide-kernel")]
pub use read::ReadOutcome;
pub use recv::StreamFiles;
pub use types::{UnixPair, UnixRing, UnixStreamError, UnixStreamSendError};
