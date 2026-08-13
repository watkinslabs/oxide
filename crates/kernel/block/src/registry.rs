//! Canonical block-driver and disk registry. `core.rs` owns driver-major and
//! per-driver minor allocation; `scsi.rs` owns reusable `sd*` identities.

mod core;
mod root;
mod scsi;
#[cfg(test)] mod tests;

pub use core::*;
pub use root::{RootSpec, parse_root_spec, resolve_root_spec};
pub use scsi::{reserve_scsi_disk_name, ScsiDiskName};
