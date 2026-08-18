//! Shared SCSI host, LUN scan, command, and disk owners.
//!
//! Module manifest:
//! - `command`: bounded CDB construction and opcode contracts.
//! - `transport`: host-to-transport address and execution boundary.
//! - `scan`: LUN inquiry/capacity discovery and common `sd*` publication.
//! - `disk`: block-device translation above one discovered LUN.
//! - `block_transport`: adapts an existing block endpoint below the common disk layer.

#![no_std]

extern crate alloc;
#[cfg(test)] extern crate std;

mod block_transport;
mod command;
mod disk;
mod scan;
mod transport;
#[cfg(test)] mod tests;

pub use block_transport::BlockTransport;
pub use command::{Command, READ_10, READ_16, READ_CAPACITY_10, READ_CAPACITY_16, SERVICE_ACTION_IN_16,
    SYNCHRONIZE_CACHE_10, TEST_UNIT_READY, WRITE_10, WRITE_16};
pub use disk::{Disk, init, publish, publish_block_transport, publish_lun};
pub use scan::{ScannedLun, scan_and_publish, scan_lun};
pub use transport::{DataDirection, Lun, Transport};
