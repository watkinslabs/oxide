// Socket work-layer manifest.
// - `error`: typed work errors and backend translations.
// - `message`: kernel-owned send inputs and outcomes.
// - `target`: retained open-file classification.
// - `send`: family routing, retry, and SIGPIPE completion.
// - `address`: kernel-snapshot socket-address decoding and UNIX lookup.
// - `control*`: SCM and raw IP ancillary policy.
// - `packet`: AF_PACKET message transmission.
// - `batch`: lazy sendmmsg import/publication policy.
// - `receive`: SCM_RIGHTS receive descriptor publication.
// - `filter`: common socket-filter target and mutation work.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod address;
mod batch;
mod control;
mod control_raw;
mod error;
mod filter;
mod message;
mod packet;
mod receive;
mod send;
mod target;

pub use batch::{BatchIo, BatchSpec, send_batch};
pub use error::{Error, KResult};
pub use filter::{FilterError, FilterFile};
pub use message::{Message, SendOutcome};
pub use receive::{ReceiveFdResult, install_received_fds};
pub use send::{ImportMode, MessageIo, SendContext, send, send_io, write, writev};
pub use target::{SendFile, SendKind};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod control_raw_tests;
#[cfg(test)]
mod receive_tests;
#[cfg(test)]
mod filter_tests;
#[cfg(test)]
#[path = "tests/netlink_preflight.rs"]
mod netlink_preflight_tests;
