//! Canonical block-driver and disk registry. `core.rs` owns driver-major and
//! per-driver minor allocation; `partition.rs` owns disk child publication;
//! `scsi.rs` owns reusable `sd*` identities.

mod core;
mod gate;
mod partition;
mod root;
mod scsi;
#[cfg(test)] mod tests;

pub use core::*;
pub use gate::*;
pub use partition::{Partition, partition_by_dev, partition_by_label, partition_by_name, partition_by_uuid, partition_by_uuid_offset, rescan_partitions, start_deferred_partition_scans};
pub use root::{RootSpec, parse_root_spec, resolve_root_spec};
pub use scsi::{reserve_scsi_disk_name, ScsiDiskName};
