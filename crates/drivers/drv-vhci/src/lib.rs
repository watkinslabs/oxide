#![no_std]

//! Virtual HCI transport (`docs/62§4`).
//!
//! A process opens the character device and presents a Bluetooth controller to
//! the host stack through it: it writes the traffic a controller would report
//! and reads the traffic the stack would send one. That makes it a real
//! transport implementing the one transport contract, with no bus underneath —
//! which is what makes the whole stack exercisable on a machine that has no
//! Bluetooth hardware, and on both architectures alike.
//!
//! Module manifest:
//! - `protocol`: the write protocol as pure decisions.
//! - `device`: the per-description state and the transport implementation.
//! - `node`: the character-device file operations.

extern crate alloc;

pub mod protocol;
pub mod device;
pub mod node;

pub use device::VhciDevice;
pub use protocol::{parse_write, CreateFlags, WriteAction};
