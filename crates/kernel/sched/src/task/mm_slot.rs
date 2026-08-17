//! The task's user address-space slot: reading it, pinning it, and replacing
//! it.
//!
//! Lives apart from the signal machinery it used to share a file with because
//! its correctness question is its own: `mm_pin_lock` is a spinlock, and the
//! address space it guards is released by a teardown that SLEEPS. The split
//! between what runs under the pin and what runs after it is the whole point
//! of this module.

use alloc::sync::Arc;

use vmm::AddressSpace;

use super::Task;

impl Task {
    /// Borrow `mm` (the `Arc<AddressSpace>` if set). Read-only;
    /// callers must observe the single-mutator invariant per the
    /// `mm` field doc.
    /// # SAFETY: caller is in IRQ-off / preempt-off context, OR
    /// holds a guarantee that no concurrent execve runs against
    /// this task on another CPU.
    /// # C: O(1)
    pub unsafe fn mm_ref(&self) -> Option<&Arc<AddressSpace>> {
        self.debug_check_canary("mm_ref");
        // SAFETY: caller asserts no concurrent writer; UnsafeCell::get is the supported deref pattern for shared interior mutability under documented external synchronization.
        unsafe { (&*self.mm.get()).as_ref() }
    }

    /// Pin this task's current user mm for a cross-task observer. The pin lock
    /// closes concurrent exec/exit replacement before cloning the Arc, so the
    /// returned mm remains valid after the task resumes or exits.
    /// # C: O(1); # Lk: TaskList
    pub fn clone_mm(&self) -> Option<Arc<AddressSpace>> {
        let _pin = self.mm_pin_lock.lock();
        // SAFETY: mm_pin_lock serializes this observer with replace_mm below.
        unsafe { (&*self.mm.get()).as_ref().map(Arc::clone) }
    }

    /// OOM compatibility spelling for [`Self::clone_mm`].
    /// # C: O(1); # Lk: TaskList
    pub fn clone_mm_for_oom(&self) -> Option<Arc<AddressSpace>> { self.clone_mm() }

    /// Atomically replace `mm` with `new`. The displaced Arc is NOT dropped
    /// here — it is parked in this CPU's `active_mm` slot (Linux `exit_mm`
    /// keeps `active_mm`+`mm_count`; `mmdrop` runs after the next switch):
    /// on exit/signal-death the caller clears `mm` BEFORE the final
    /// `schedule()`, so an in-place drop of the last Arc would free the
    /// page-table root while it is still live in CR3/TTBR0 (GAP-2
    /// use-after-free → random exec/ld.so corruption). `execve` is safe by
    /// ordering (it `activate`s the new root BEFORE calling this) but parks
    /// through the same choke-point.
    /// # SAFETY: caller is the running task on its CPU OR holds
    /// the runqueue invariant for this task; preempt-off. Not safe
    /// to call on an actively-scheduled task from another CPU.
    /// # C: O(1)
    pub unsafe fn replace_mm(&self, new: Option<Arc<AddressSpace>>) {
        // Owning a user address space is what makes a task a user-mode thread:
        // a helper started from the kernel that reaches `execve` stops being a
        // kernel thread at exactly this point, and from here on its exit
        // notifies a real parent instead of auto-reaping. The borrowed-mm
        // sibling below deliberately does NOT clear the bit — a kernel thread
        // that borrows someone else's mm is still a kernel thread.
        if new.is_some() { self.kernel_thread.store(false, core::sync::atomic::Ordering::Release); }
        // SAFETY: this fn is itself `unsafe` and forwards its contract
        // unchanged — caller is the running task on its own CPU (or holds the
        // runqueue invariant for it) with preempt off, so the mm slot has a
        // single mutator across the swap.
        unsafe { self.replace_mm_inner(new, true); }
    }

    /// The same swap for an mm this task only BORROWED (a kernel thread
    /// running `kthread_use_mm`). Releasing a borrow must not latch the lent
    /// address space's resident-set peak onto the borrower: the peak belongs
    /// to the process that owns the pages, and folding it into a kernel
    /// thread's own accounting invents a residency that thread never had.
    /// # SAFETY: same contract as [`Self::replace_mm`].
    /// # C: O(1)
    pub unsafe fn replace_borrowed_mm(&self, new: Option<Arc<AddressSpace>>) {
        // SAFETY: this fn is itself `unsafe` and forwards `replace_mm`'s
        // contract unchanged — caller is the running task on its own CPU with
        // preempt off, so the mm slot has a single mutator across the swap.
        unsafe { self.replace_mm_inner(new, false); }
    }

    /// Swap the mm slot and hand the departing address space BACK to the
    /// caller, still alive.
    ///
    /// The pin covers the slot and the registry membership either side of it,
    /// and nothing else. It deliberately does NOT cover the departing mm's
    /// release: that release is the last reference in the `execve` case, and
    /// the last reference runs a full address-space teardown which walks the
    /// page table and SLEEPS. Sleeping under this spinlock stopped the machine
    /// — a task in `execve` reporting `scheduling while atomic` forever, with
    /// this exact acquisition named as the lock it held.
    ///
    /// Returning the Arc rather than dropping it is what makes that
    /// structural: the release cannot move back inside the pinned section
    /// without changing this signature.
    /// # SAFETY: caller is the running task on its own CPU with preempt off,
    /// so the mm slot has a single mutator across the swap.
    /// # C: O(1)
    unsafe fn swap_mm_slot(&self, new: Option<Arc<AddressSpace>>) -> Option<Arc<AddressSpace>> {
        let _pin = self.mm_pin_lock.lock();
        // Publish before changing the slot. A concurrent reader sees this
        // candidate either before it shares `new` (and filters it out during
        // revalidation) or after the swap; it cannot miss an existing sharer.
        if let Some(mm) = new.as_ref() { crate::registry::track_mm_before_replace(self, mm); }
        // SAFETY: `mm_pin_lock` held above serializes this read with every
        // replacement, so it is a stable comparison with the incoming Arc.
        let keeps_old_membership = unsafe {
            (&*self.mm.get()).as_ref().is_some_and(|old| new.as_ref().is_some_and(|next| Arc::ptr_eq(old, next)))
        };
        // SAFETY: see fn-level contract; single-mutator on this CPU.
        let old = unsafe { core::mem::replace(&mut *self.mm.get(), new) };
        // Now the authoritative slot no longer names `old`, so dropping that
        // bucket membership cannot hide a current sharer. Keeping this inside
        // the same pin closes the interval in the other direction too.
        if !keeps_old_membership {
            if let Some(mm) = old.as_ref() { crate::registry::untrack_mm_after_replace(self, mm); }
        }
        old
    }

    unsafe fn replace_mm_inner(&self, new: Option<Arc<AddressSpace>>, latch_rss: bool) {
        self.debug_check_canary("replace_mm");
        // SAFETY: forwards this fn's contract unchanged.
        let old = unsafe { self.swap_mm_slot(new) };
        // Everything below runs with the pin RELEASED, and everything below
        // may sleep. The reference stashes the departing mm during the swap
        // and releases it in a separate step run outside the exec locks, doing
        // the resident-set latch there too — this is that step.
        //
        // Linux latches `signal_struct::maxrss` from the departing mm, so an
        // `execve(2)` does not reset the process's `ru_maxrss` to the new
        // image's residency.
        if let (true, Some(m)) = (latch_rss, old.as_ref()) {
            crate::rusage_charge::latch_hiwater_rss(self, m.accounting_snapshot().hiwater_rss_pages);
        }
        #[cfg(target_os = "oxide-kernel")]
        if let Some(m) = old {
            m.debug_lifetime_event(b"task-replace-mm-old");
            crate::live::schedule::park_active_mm(m);
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        drop(old); // hosted: no live CR3 to protect
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SchedClass, Task};

    fn task() -> Task { Task::new(2234, "mm-slot", SchedClass::Normal { weight: 1024 }) }

    /// The property that keeps the machine alive: the departing address space
    /// comes back OUT of the pinned section, still alive, so its release — a
    /// page-table walk that sleeps — runs with the spinlock dropped.
    ///
    /// A task in `execve` released the old mm inside the pin and reported
    /// `scheduling while atomic` forever, naming this lock. The reference
    /// stashes the departing mm during the swap and releases it in a separate
    /// step outside the exec locks.
    #[test]
    fn the_departing_mm_leaves_the_pinned_section_alive() {
        let t = task();
        let old = vmm::AddressSpace::new(0).expect("hosted address space");
        let keep = Arc::clone(&old);
        // SAFETY: hosted single-threaded test; this task is not scheduled.
        unsafe { t.replace_mm(Some(old)); }

        let new = vmm::AddressSpace::new(0).expect("hosted address space");
        // SAFETY: hosted single-threaded test; `t` is not on any runqueue, so the
        // swap has no concurrent mm reader to race.
        let returned = unsafe { t.swap_mm_slot(Some(new)) };
        let returned = returned.expect("the swap must hand the old mm back, not drop it");
        assert!(Arc::ptr_eq(&returned, &keep), "a different address space came back");
        assert!(Arc::strong_count(&returned) >= 2, "the caller and this test both hold it");
    }

    /// ...and the pin really is free by then, so the release cannot deadlock
    /// or sleep under it. `try_lock` succeeding is the whole assertion: it
    /// fails if the guard is still alive anywhere up the call chain.
    #[test]
    fn the_pin_is_released_before_the_caller_touches_the_departing_mm() {
        let t = task();
        let old = vmm::AddressSpace::new(0).expect("hosted address space");
        // SAFETY: hosted single-threaded test; this task is not scheduled.
        unsafe { t.replace_mm(Some(old)); }

        let new = vmm::AddressSpace::new(0).expect("hosted address space");
        // SAFETY: hosted single-threaded test; the only reference to `t`'s mm slot
        // is this thread, so nothing observes the departing mm mid-swap.
        let returned = unsafe { t.swap_mm_slot(Some(new)) };
        assert!(t.mm_pin_lock.try_lock().is_some(),
            "mm_pin_lock still held while the caller owns the departing mm");
        drop(returned);
    }

    /// Replacing with the SAME address space keeps its registry membership and
    /// still hands the Arc back — the identity path must not become a special
    /// case that releases under the pin.
    #[test]
    fn replacing_an_mm_with_itself_still_returns_it() {
        let t = task();
        let mm = vmm::AddressSpace::new(0).expect("hosted address space");
        // SAFETY: hosted single-threaded test; this task is not scheduled.
        unsafe { t.replace_mm(Some(Arc::clone(&mm))); }
        // SAFETY: hosted single-threaded test replacing the slot with the same mm;
        // `t` is unscheduled, so no concurrent reader can see the identity swap.
        let returned = unsafe { t.swap_mm_slot(Some(Arc::clone(&mm))) };
        assert!(Arc::ptr_eq(&returned.expect("same mm handed back"), &mm));
        assert!(t.mm_pin_lock.try_lock().is_some());
    }
}
