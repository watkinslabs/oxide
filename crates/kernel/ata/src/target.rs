//! Canonical block-device lookup for live ATA endpoints.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Devices, Spinlock};

use crate::{Device, IDENTIFY_BYTES};

struct TargetRecord { dev_t: u32, device: Arc<dyn Device> }
static TARGETS: Spinlock<Vec<TargetRecord>, Devices> = Spinlock::new(Vec::new());

/// A resolved live ATA endpoint. # C: O(1)
#[derive(Clone)]
pub struct IdentityTarget { device: Arc<dyn Device> }

impl IdentityTarget {
    /// Return the Linux `struct hd_driveid` page, including the string-field
    /// byte-order conversion. # C: O(1)
    pub fn hdio_identity(&self) -> Option<[u8; IDENTIFY_BYTES]> {
        let mut page = self.device.identify_page()?;
        crate::identity::normalize_identity(&mut page);
        Some(page)
    }

    /// Retain the taskfile-capable endpoint for another ATA ABI. # C: O(1)
    pub fn device(&self) -> Arc<dyn Device> { Arc::clone(&self.device) }
}

/// Resolve the ATA device attached to a canonical block `dev_t`. # C: O(devices)
pub fn identity_target(dev_t: u32) -> Option<IdentityTarget> {
    TARGETS.lock().iter().find(|entry| entry.dev_t == dev_t)
        .map(|entry| IdentityTarget { device: Arc::clone(&entry.device) })
}

/// Register or replace the live ATA owner for a newly published block node.
/// Failure is allocation-only so callers can roll the block publication back.
/// # C: O(devices)
pub fn register_target(dev_t: u32, device: Arc<dyn Device>) -> bool {
    let mut targets = TARGETS.lock();
    if let Some(existing) = targets.iter_mut().find(|entry| entry.dev_t == dev_t) {
        existing.device = device;
        return true;
    }
    if targets.try_reserve(1).is_err() { return false; }
    targets.push(TargetRecord { dev_t, device });
    true
}

/// Drop a departed or shut-down ATA endpoint from the canonical lookup.
/// # C: O(devices)
pub fn unregister_target(dev_t: u32) -> bool {
    let mut targets = TARGETS.lock();
    let Some(index) = targets.iter().position(|entry| entry.dev_t == dev_t) else {
        return false;
    };
    targets.remove(index);
    true
}
