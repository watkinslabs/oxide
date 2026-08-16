// System-core callbacks per `32a§7`.
//
// The subsystems with no device to hang from — interrupt controllers, the
// timer, the clocksource — register here. The walk runs with interrupts
// disabled and one CPU online, so the registration table is a fixed array: an
// allocation on this path has nowhere to fail to.

use core::sync::atomic::{AtomicUsize, Ordering};

use sync::{Spinlock, TaskList as PowerListClass};

use crate::decide::{Error, KResult};

/// Registrations the table holds. Boot-path core subsystems only.
pub const MAX_SYSCORE: usize = 16;

/// One subsystem's core callbacks.
pub struct SyscoreOps {
    /// Named in the failure log, and in the statistics record.
    pub name: &'static str,
    /// Runs with interrupts off, one CPU online. Failure aborts the suspend.
    pub suspend: Option<fn() -> KResult<()>>,
    /// Runs with interrupts off, one CPU online. Cannot fail.
    pub resume: Option<fn()>,
    /// Runs on the terminal transitions (`32§5`), not on suspend.
    pub shutdown: Option<fn()>,
}

impl SyscoreOps {
    /// A table with a name and no callbacks. # C: O(1)
    pub const fn named(name: &'static str) -> Self {
        SyscoreOps { name, suspend: None, resume: None, shutdown: None }
    }
}

/// The registration table, in registration order.
pub struct SyscoreList {
    entries: Spinlock<[Option<&'static SyscoreOps>; MAX_SYSCORE], PowerListClass>,
    len: AtomicUsize,
}

impl SyscoreList {
    /// An empty table. # C: O(1)
    pub const fn new() -> Self {
        SyscoreList { entries: Spinlock::new([None; MAX_SYSCORE]), len: AtomicUsize::new(0) }
    }

    /// Append `ops`. Returns false when the table is full, which is a
    /// build-time miscount rather than a runtime condition.
    /// # C: O(1)
    pub fn register(&self, ops: &'static SyscoreOps) -> bool {
        let mut e = self.entries.lock();
        let n = self.len.load(Ordering::Acquire);
        if n >= MAX_SYSCORE { return false; }
        e[n] = Some(ops);
        self.len.store(n + 1, Ordering::Release);
        true
    }

    /// Registrations so far. # C: O(1)
    pub fn len(&self) -> usize { self.len.load(Ordering::Acquire) }

    /// Whether nothing has registered. # C: O(1)
    pub fn is_empty(&self) -> bool { self.len() == 0 }

    /// Suspend every registration in reverse order.
    ///
    /// On failure the entries already suspended resume, in forward order,
    /// which is their own reverse — and the failing entry is not resumed,
    /// because its suspend did not complete.
    /// # C: O(N)
    /// # Ctx: IRQ-off, single-CPU
    pub fn suspend_all(&self) -> Result<(), &'static str> {
        let n = self.len();
        let snapshot = *self.entries.lock();
        for i in (0..n).rev() {
            let Some(ops) = snapshot[i] else { continue };
            let Some(f) = ops.suspend else { continue };
            if f().is_err() {
                for j in (i + 1)..n {
                    if let Some(r) = snapshot[j].and_then(|o| o.resume) { r(); }
                }
                return Err(ops.name);
            }
        }
        Ok(())
    }

    /// Resume every registration in forward order.
    /// # C: O(N)
    /// # Ctx: IRQ-off, single-CPU
    pub fn resume_all(&self) {
        let n = self.len();
        let snapshot = *self.entries.lock();
        for entry in snapshot.iter().take(n) {
            if let Some(r) = entry.and_then(|o| o.resume) { r(); }
        }
    }

    /// Run every shutdown callback, in reverse order. # C: O(N)
    pub fn shutdown_all(&self) {
        let n = self.len();
        let snapshot = *self.entries.lock();
        for i in (0..n).rev() {
            if let Some(s) = snapshot[i].and_then(|o| o.shutdown) { s(); }
        }
    }
}

/// The machine's core-callback table.
pub static SYSCORE: SyscoreList = SyscoreList::new();

/// Register a core subsystem's callbacks. # C: O(1)
pub fn register_syscore(ops: &'static SyscoreOps) -> bool { SYSCORE.register(ops) }

/// Suspend the core subsystems, naming the one that refused.
/// # C: O(N)
/// # Ctx: IRQ-off, single-CPU
pub fn syscore_suspend() -> KResult<()> {
    if super::wakeup::pm_wakeup_pending() { return Err(Error::Busy); }
    match SYSCORE.suspend_all() { Ok(()) => Ok(()), Err(_name) => Err(Error::Io) }
}

/// Resume the core subsystems.
/// # C: O(N)
/// # Ctx: IRQ-off, single-CPU
pub fn syscore_resume() { SYSCORE.resume_all(); }

#[cfg(test)]
#[path = "syscore/tests.rs"]
mod tests;
