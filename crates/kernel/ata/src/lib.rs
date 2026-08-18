//! ATA identity, taskfile, and SCSI-translation owners.
//!
//! Module manifest:
//! - `device`: driver-facing live ATA execution boundary.
//! - `identity`: Linux `HDIO_GET_IDENTITY` presentation contract.
//! - `legacy`: Linux HDIO raw-command ABI adapters.
//! - `target`: canonical block-`dev_t` lookup.
//! - `sat`: SCSI ATA PASS-THROUGH translation.
//! - `taskfile`: ATA register and completion values.

#![no_std]

extern crate alloc;
#[cfg(test)] extern crate std;

mod device;
mod identity;
mod legacy;
mod sat;
mod target;
mod taskfile;
#[cfg(test)] mod tests;

pub use device::Device;
pub use identity::{HDIO_GET_IDENTITY, IDENTIFY_BYTES};
pub use legacy::{DRIVE_CMD_BYTES, DRIVE_TASK_BYTES, HDIO_DRIVE_CMD, HDIO_DRIVE_TASK, drive_cmd, drive_cmd_data_bytes, drive_task};
pub use sat::scsi_transport;
pub use target::{IdentityTarget, identity_target, register_target, unregister_target};
pub use taskfile::{Protocol, Taskfile, TaskfileResult, STATUS_BUSY, STATUS_DF, STATUS_DRQ, STATUS_ERR};
