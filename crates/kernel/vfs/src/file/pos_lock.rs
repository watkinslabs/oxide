//! `file->f_pos_lock` — the per-description cursor lock.
//!
//! A SLEEPING mutex, as in the reference, and not for tidiness. The region it
//! covers reads the cursor, submits the I/O, waits for the device and writes
//! the cursor back — so its owner parks off-CPU INSIDE the critical section,
//! every time the page it wants is not already cached. A spinning lock there
//! hands the CPU away while still held; every later operation on the same
//! description then spins for a lock whose owner is not running. A second CPU
//! hides it by running the owner, which is why this survived every gate in the
//! tree; one CPU cannot, and the machine stops.
//!
//! `vfs` sits BELOW `sched` in the dependency order and so cannot name the
//! scheduler's mutex. It has exactly one sleepable lock of its own —
//! `i_rwsem`, which reaches the scheduler through installed park/schedule/wake
//! hooks — and this is its exclusive side under the name the cursor uses.
//! Reusing it keeps ONE sleepable-lock implementation in this crate rather
//! than a second one that could sleep differently.

use crate::inode::rwsem::{InodeRwsem, InodeRwsemWriteGuard};

/// Linux `struct file.f_pos_lock`.
pub(crate) struct FilePosLock(InodeRwsem);

impl FilePosLock {
    /// # C: O(1)
    pub(crate) const fn new() -> Self { Self(InodeRwsem::new()) }

    /// Linux `mutex_lock(&file->f_pos_lock)` in `__fdget_pos`. Sleeps while
    /// another operation on this description owns the cursor.
    /// # C: O(contention)
    /// # Sleeps: yes, while contended
    pub(crate) fn lock(&self) -> InodeRwsemWriteGuard<'_> { self.0.write() }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Per-THREAD: `sync`'s preempt ops are process-global, so while these are
    // installed every sibling test's lock traffic runs them too.
    std::thread_local! {
        static DEPTH: core::cell::Cell<i64> = const { core::cell::Cell::new(0) };
    }
    fn up() { DEPTH.with(|d| d.set(d.get() + 1)); }
    fn down() { DEPTH.with(|d| d.set(d.get() - 1)); }
    static COUNTING: sync::PreemptOps = sync::PreemptOps { disable: up, enable: down };

    /// The cursor lock must not be a SPINNING lock. Its critical section waits
    /// for block I/O, so holding it with preemption disabled strands the CPU on
    /// a lock whose owner is parked — the uniprocessor wedge. A spinning lock
    /// leaves the preempt gate raised for the whole section; a sleeping one
    /// takes its internal gate and releases it before returning.
    #[test]
    fn holding_the_cursor_lock_leaves_preemption_enabled() {
        sync::set_preempt_ops(&COUNTING);
        DEPTH.with(|d| d.set(0));
        let lk = FilePosLock::new();
        let g = lk.lock();
        assert_eq!(DEPTH.with(core::cell::Cell::get), 0,
            "f_pos_lock is held across block I/O; it must not disable preemption");
        drop(g);
        assert_eq!(DEPTH.with(core::cell::Cell::get), 0);
    }

    #[test]
    fn the_cursor_lock_is_exclusive_and_released_on_drop() {
        let lk = FilePosLock::new();
        {
            let _g = lk.lock();
            assert_eq!(lk.0.debug_state(), (0, true), "held exclusive");
        }
        assert_eq!(lk.0.debug_state(), (0, false), "released on drop");
    }
}
