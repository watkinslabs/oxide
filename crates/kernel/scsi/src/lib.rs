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
mod recovery;
mod scan;
mod sg;
mod transport;
#[cfg(test)] mod tests;

pub use block_transport::BlockTransport;
pub use command::{caching_mode_page_writeback, Command, MAX_CDB_BYTES, READ_10, READ_16, READ_CAPACITY_10, READ_CAPACITY_16, SERVICE_ACTION_IN_16,
    MODE_SENSE_6, SYNCHRONIZE_CACHE_10, TEST_UNIT_READY, WRITE_10, WRITE_16};
pub use disk::{Disk, init, publish, publish_block_transport, publish_lun};
pub use recovery::{ALUA_TRANSITION_DELAY_MS, BlockDisposition, DEFAULT_RETRIES, QUEUE_RETRY_DELAY_MS, SenseHeader,
    block_disposition};
pub use scan::{ScannedLun, scan_and_publish, scan_lun};
pub use sg::{SG_IO, SG_IO_HDR_BYTES, SgHeader, SgIoTarget, command_allowed, sg_target};
pub use transport::{CommandCompletion, DataDirection, Lun, SENSE_BYTES, Transport};
