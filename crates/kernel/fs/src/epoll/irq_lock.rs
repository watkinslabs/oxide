//! IRQ-safe epoll callback state and ready-list allocation boundary.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use sync::{Spinlock, TaskList as TaskListClass};

use super::{EpItem, EpollData};

/// Poll wake callbacks can run from a device interrupt. Process readers must
/// exclude a same-CPU callback for the full guard lifetime.
pub(super) struct EpollIrqLock<T>(Spinlock<T, TaskListClass>);

impl<T> EpollIrqLock<T> {
    pub(super) const fn new(value: T) -> Self { Self(Spinlock::new(value)) }

    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    pub(super) fn lock(
        &self,
    ) -> sync::IrqGuard<'_, T, TaskListClass, hal_x86_64::X86IrqGate> {
        self.0.lock_irqsave::<hal_x86_64::X86IrqGate>()
    }

    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    pub(super) fn lock(
        &self,
    ) -> sync::IrqGuard<'_, T, TaskListClass, hal_aarch64::ArmIrqGate> {
        self.0.lock_irqsave::<hal_aarch64::ArmIrqGate>()
    }

    #[cfg(not(target_os = "oxide-kernel"))]
    pub(super) fn lock(&self) -> sync::Guard<'_, T, TaskListClass> { self.0.lock() }
}

impl EpollData {
    /// Grow ready storage from process context before publishing a new epitem.
    /// Entry count bounds queued items, so callback-side push cannot allocate.
    pub(super) fn reserve_ready_for(&self, entries: usize) {
        if self.ready.lock().capacity() >= entries { return; }
        let mut replacement = VecDeque::<Arc<EpItem>>::with_capacity(entries);
        let mut ready = self.ready.lock();
        if ready.capacity() >= entries { return; }
        while let Some(item) = ready.pop_front() { replacement.push_back(item); }
        *ready = replacement;
    }
}
