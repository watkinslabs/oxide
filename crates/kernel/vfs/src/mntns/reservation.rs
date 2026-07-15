use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::fs::KResult;
use crate::types::VfsError;

use super::{sysctl_mount_max, MntNamespaceRef};

/// Owner-retaining mount reservation. Uncommitted drop aborts the reservation.
pub struct MountReservation {
    namespace: MntNamespaceRef,
    num: u64,
    complete: bool,
}

impl MountReservation {
    /// Reserve slots against the exact retained namespace owner. # C: O(1)
    pub fn reserve(namespace: &MntNamespaceRef, num: u64) -> KResult<Self> {
        if num != 0 {
            let max = sysctl_mount_max();
            loop {
                let pend = namespace.pending_mounts.load(Ordering::Acquire);
                let live = namespace.nr_mounts.load(Ordering::Acquire);
                if live.saturating_add(pend).saturating_add(num) > max {
                    return Err(VfsError::Enospc);
                }
                if namespace.pending_mounts.compare_exchange(
                    pend, pend + num, Ordering::AcqRel, Ordering::Acquire).is_ok() { break; }
            }
        }
        Ok(Self { namespace: Arc::clone(namespace), num, complete: false })
    }

    /// Numeric mount-table key valid while this reservation pins its owner.
    /// # C: O(1)
    pub fn namespace_id(&self) -> u64 { self.namespace.id() }

    /// Commit reserved slots into the live mount count. # C: O(1)
    pub fn commit(mut self) {
        if self.num != 0 {
            let pend = self.namespace.pending_mounts.load(Ordering::Acquire);
            self.namespace.pending_mounts.store(
                pend.saturating_sub(self.num), Ordering::Release);
            self.namespace.nr_mounts.fetch_add(self.num, Ordering::AcqRel);
        }
        self.complete = true;
    }
}

impl Drop for MountReservation {
    fn drop(&mut self) {
        if self.complete || self.num == 0 { return; }
        let pend = self.namespace.pending_mounts.load(Ordering::Acquire);
        self.namespace.pending_mounts.store(
            pend.saturating_sub(self.num), Ordering::Release);
    }
}
