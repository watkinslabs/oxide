//! Socket extended-error state.
//!
//! Module manifest:
//! - `uapi`  — extended-error wire constants: origins, per-origin codes,
//!   timestamp selectors, receive-memory budget.
//! - `entry` — one queue record plus the per-origin constructors that decide
//!   which `sock_extended_err` fields each origin owns.
//! - `queue` — the socket-owned queue and its pending-errno relationship.
//! - `abi`   — `MSG_ERRQUEUE` wire encoding and the name/offender ladders.
//! - `poll`   — the readiness bits the error state contributes.
//! - `report` — local-origin reporting for host-detected transmit failures.
//! - `pathmtu` — `IPV6_RECVPATHMTU`'s one-slot report, collected by an
//!   ORDINARY receive rather than by the error queue.
//! - `zerocopy` — `MSG_ZEROCOPY` completion policy, shared by every family.

pub mod abi;
mod entry;
mod queue;
mod poll;
mod report;
pub mod pathmtu;
mod uapi;
mod zerocopy;

#[cfg(test)] mod tests;

pub use entry::SocketErrorEntry;
pub use poll::error_poll_mask;
pub use report::{report_send_failure, report_send_failure_pmtu};
pub use zerocopy::{complete_send as complete_zerocopy_send, notifies as zerocopy_notifies};
pub use queue::{icmp_origin, SocketError};
pub use uapi::*;
