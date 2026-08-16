#![no_std]

//! Bluetooth subsystem (`docs/62`).
//!
//! Module manifest:
//! - `uapi`: every wire and ABI constant, one module per protocol.
//! - `hci`: controller abstraction — framing, command credits, event dispatch,
//!   connection tracking, the setup sequence, and the transport contract a
//!   driver implements.
//! - `l2cap`: channels, signalling, configuration, ERTM, LE credit flow.
//! - `smp`: pairing, key derivation, key storage, security-level sufficiency.
//! - `rfcomm`: multiplexer, DLCs, credit flow, the TTY binding.
//! - `sco`: synchronous voice links and their parameter negotiation.
//! - `mgmt`: the management command and event surface.
//! - `sock`: the `AF_BLUETOOTH` family — its four protocols and their sockets.

extern crate alloc;

pub mod uapi;
pub mod hci;
pub mod l2cap;
pub mod smp;
pub mod rfcomm;
pub mod sco;
pub mod mgmt;
pub mod sock;

pub use uapi::bt::{BdAddr, AF_BLUETOOTH, BDADDR_ANY};
