//! Which registered disk a mount is on.
//!
//! A mount holds a block device, not a name: the name, and the I/O counters
//! the write reports are computed from, belong to the registered disk that
//! device IS. Identity is the device object itself — two disks can carry
//! identical filesystems, and only the object says which one this mount reads
//! and writes.
//!
//! A mount whose device is not a registered disk — a fixture image under a
//! test, a device the registry never published — has no disk here, and every
//! caller treats that as "no name, no counters" rather than inventing either.

use alloc::string::String;
use alloc::sync::Arc;

use crate::Mount;

/// The registered disk this mount's device is, if it is one. # C: O(N disks)
pub fn disk_of(m: &Mount) -> Option<Arc<block::registry::Disk>> {
    block::registry::snapshot().into_iter().find(|d| Arc::ptr_eq(&d.dev, &m.dev))
}

/// The name that disk is published under. # C: O(N disks)
pub fn name_of(m: &Mount) -> Option<String> { disk_of(m).map(|d| d.name.clone()) }

/// 512-byte sectors written to this mount's disk since it was registered, or
/// zero when the mount is not on a registered disk. # C: O(N disks)
pub fn sectors_written(m: &Mount) -> u64 {
    match disk_of(m) {
        Some(d) => d.stats.snapshot().3,
        None => 0,
    }
}
