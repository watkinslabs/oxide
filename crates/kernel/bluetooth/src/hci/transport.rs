//! The contract a transport driver implements.
//!
//! A transport carries whole H:4 frames in both directions and knows nothing
//! about their contents. Everything above — credits, events, connections — is
//! the core's, so a new bus is a new implementation of this one trait and no
//! change anywhere else. Byte-oriented buses reassemble with `packet::H4Decoder`
//! before handing a frame up; packet-oriented buses hand theirs up directly.

extern crate alloc;
use alloc::string::String;
use syscall::errno::Errno;

/// A controller's transport. `open` and `close` bracket the controller's
/// usable life; `send` carries one whole frame with its packet-type prefix
/// already applied by the core.
pub trait HciTransport: Send + Sync {
    /// Bring the transport up. Called before any frame is sent. # C: driver
    fn open(&self) -> Result<(), Errno>;

    /// Take the transport down. Every frame in flight is abandoned. # C: driver
    fn close(&self);

    /// Send one whole H:4 frame, prefix byte included. # C: driver
    fn send(&self, frame: &[u8]) -> Result<(), Errno>;

    /// Bus this transport attaches by, one of the `HCI_*` bus values. Reported
    /// to the monitor and to the device-info ioctl. # C: O(1)
    fn bus(&self) -> u8;

    /// Human-readable driver name for the device listing. # C: O(1)
    fn driver_name(&self) -> String;
}

/// What a transport reports upward when it has a frame or has failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportEvent {
    /// One complete frame arrived.
    Frame(alloc::vec::Vec<u8>),
    /// The transport failed irrecoverably; the controller must go down.
    Failed,
}

#[cfg(test)]
#[path = "tests/transport.rs"]
mod tests;
