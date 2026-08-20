// Canonical interface-table storage and its BH-safe lock.

use alloc::vec::Vec;
#[cfg(not(target_os = "oxide-kernel"))]
use core::sync::atomic::{AtomicU32, Ordering};
use sync::{Spinlock, Socket as SocketLockClass};

use super::IfaceEntry;

/// The interface table is read from NET_RX softirq and mutated from process
/// control paths, so its lock excludes networking bottom halves.
pub(crate) struct IfaceRegistryLock(Spinlock<RegistryInner, SocketLockClass>);

impl IfaceRegistryLock {
    pub(super) const fn new(value: RegistryInner) -> Self { Self(Spinlock::new(value)) }

    #[inline]
    pub(super) fn lock(&self)
        -> sync::LockBhGuard<'_, RegistryInner, SocketLockClass, sched::bh::SchedBh>
    {
        self.0.lock_bh::<sched::bh::SchedBh>()
    }
}

pub(crate) struct RegistryInner {
    next: u32,
    pub(crate) entries: Vec<IfaceEntry>,
}

#[cfg(not(target_os = "oxide-kernel"))]
static NEXT_IFACE_ID_BLOCK: AtomicU32 = AtomicU32::new(1);
#[cfg(not(target_os = "oxide-kernel"))]
const IFACE_ID_BLOCK_STRIDE: u32 = 1_000_000;

impl RegistryInner {
    pub(super) const fn new() -> Self { Self { next: 0, entries: Vec::new() } }

    /// Allocate a process-global hosted ID block; the kernel has one registry. # C: O(1)
    pub(super) fn alloc_id(&mut self) -> u32 {
        if self.next == 0 {
            #[cfg(not(target_os = "oxide-kernel"))]
            { self.next = NEXT_IFACE_ID_BLOCK.fetch_add(IFACE_ID_BLOCK_STRIDE, Ordering::Relaxed); }
            #[cfg(target_os = "oxide-kernel")]
            { self.next = 1; }
        }
        let id = self.next;
        self.next += 1;
        id
    }
}
