//! Deadline PI parameter publication and donor identity.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::super::Task;
use crate::deadline::DlParams;
use crate::pi_prio::{PiDlParams, PiDonorKey};
use crate::{SchedClass, SchedPriority};
use super::{class_id, load_priority, priority_for_class, SchedClassId, TaskSched};

/// Immutable deadline reservation selected by PI; live CBS state remains task-owned.
pub(super) struct DlPiState {
    // Task construction still happens in a fixed kernel-stack frame. Keep the
    // uncommon borrowed reservation out of line instead of inflating every
    // constructor frame with another full deadline entity.
    inner: Box<DlPiStorage>,
}

struct DlPiStorage {
    seq: AtomicU64,
    used: AtomicBool,
    absolute: AtomicU64,
    runtime: AtomicU64,
    deadline: AtomicU64,
    period: AtomicU64,
    bw: AtomicU64,
    density: AtomicU64,
    flags: AtomicU64,
    top: UnsafeCell<Option<Weak<Task>>>,
}

// SAFETY: scalar fields use sequence publication; top is written only while
// TaskPi and the stable owner rq are held and cloned under the same protocol.
unsafe impl Sync for DlPiState {}

impl DlPiState {
    pub(super) fn new() -> Self {
        let mut slot = Box::<DlPiStorage>::new_uninit();
        let storage = slot.as_mut_ptr();
        // SAFETY: every field of the fresh allocation is written exactly once
        // before assume_init, and no reference to the storage exists yet.
        let inner = unsafe {
            core::ptr::addr_of_mut!((*storage).seq).write(AtomicU64::new(0));
            core::ptr::addr_of_mut!((*storage).used).write(AtomicBool::new(false));
            core::ptr::addr_of_mut!((*storage).absolute).write(AtomicU64::new(0));
            core::ptr::addr_of_mut!((*storage).runtime).write(AtomicU64::new(0));
            core::ptr::addr_of_mut!((*storage).deadline).write(AtomicU64::new(0));
            core::ptr::addr_of_mut!((*storage).period).write(AtomicU64::new(0));
            core::ptr::addr_of_mut!((*storage).bw).write(AtomicU64::new(0));
            core::ptr::addr_of_mut!((*storage).density).write(AtomicU64::new(0));
            core::ptr::addr_of_mut!((*storage).flags).write(AtomicU64::new(0));
            core::ptr::addr_of_mut!((*storage).top).write(UnsafeCell::new(None));
            slot.assume_init()
        };
        Self { inner }
    }

    /// Publish one effective parameter entity while TaskPi and owner rq are held. # C: O(1)
    pub(super) fn store(&self, donor: Option<&Arc<Task>>, key: PiDonorKey, used: bool) {
        self.write_begin();
        // SAFETY: TaskPi plus stable owner rq excludes every donor-link writer.
        unsafe { *self.inner.top.get() = donor.map(Arc::downgrade); }
        self.inner.absolute.store(key.deadline, Ordering::Relaxed);
        self.inner.runtime.store(key.dl_params.runtime, Ordering::Relaxed);
        self.inner.deadline.store(key.dl_params.deadline, Ordering::Relaxed);
        self.inner.period.store(key.dl_params.period, Ordering::Relaxed);
        self.inner.bw.store(key.dl_params.bw, Ordering::Relaxed);
        self.inner.density.store(key.dl_params.density, Ordering::Relaxed);
        self.inner.flags.store(key.dl_params.flags, Ordering::Relaxed);
        self.inner.used.store(used, Ordering::Relaxed);
        self.write_end();
    }

    pub(super) fn clear(&self) {
        self.store(None, PiDonorKey::default(), false);
    }

    pub(super) fn set_used(&self, used: bool) {
        self.write_begin();
        self.inner.used.store(used, Ordering::Relaxed);
        self.write_end();
    }

    /// Effective borrowed entity snapshot. # C: O(1) expected
    pub(super) fn snapshot(&self) -> (bool, u64, DlParams) {
        loop {
            let seq = self.inner.seq.load(Ordering::Acquire);
            if seq & 1 != 0 { core::hint::spin_loop(); continue; }
            let used = self.inner.used.load(Ordering::Relaxed);
            let absolute = self.inner.absolute.load(Ordering::Relaxed);
            let params = DlParams { runtime: self.inner.runtime.load(Ordering::Relaxed),
                deadline: self.inner.deadline.load(Ordering::Relaxed),
                period: self.inner.period.load(Ordering::Relaxed),
                bw: self.inner.bw.load(Ordering::Relaxed),
                density: self.inner.density.load(Ordering::Relaxed),
                flags: self.inner.flags.load(Ordering::Relaxed) };
            if self.inner.seq.load(Ordering::Acquire) == seq { return (used, absolute, params); }
        }
    }

    #[cfg(test)]
    pub(super) fn top(&self) -> Option<Arc<Task>> {
        // SAFETY: caller holds TaskPi or stable owner rq against donor replacement.
        unsafe { (&*self.inner.top.get()).as_ref().and_then(Weak::upgrade) }
    }

    fn write_begin(&self) {
        let seq = self.inner.seq.fetch_add(1, Ordering::AcqRel);
        hal::kassert!(seq & 1 == 0, "concurrent deadline PI writers");
    }

    fn write_end(&self) {
        let seq = self.inner.seq.fetch_add(1, Ordering::Release);
        hal::kassert!(seq & 1 != 0, "deadline PI write ended without owner");
    }
}

impl TaskSched {
    /// Owner-local absolute deadline used by the ready tree. # C: O(1)
    pub(crate) fn effective_dl_deadline(&self) -> u64 { self.dl.abs_deadline() }
    /// Special state selected from the effective reservation. # C: O(1)
    pub(crate) fn effective_dl_special(&self) -> bool {
        self.effective_dl_params().is_special()
    }
    /// Immutable reservation selected by PI. # C: O(1) expected
    pub(crate) fn effective_dl_params(&self) -> DlParams {
        let (borrowed, _, params) = self.dl_pi.snapshot();
        if borrowed { params } else { self.dl.params() }
    }
    /// Whether the task currently consumes a waiter's reservation. # C: O(1) expected
    pub(crate) fn uses_borrowed_dl(&self) -> bool { self.dl_pi.snapshot().0 }

    /// Publish the selected donor under TaskPi and stable owner rq. # C: O(1)
    pub(crate) fn store_top_donor(&self, donor: Option<(&Arc<Task>, PiDonorKey)>) {
        let normal = load_priority(&self.normal_prio);
        let normal_id = class_id(normal);
        let base = self.normal_class();
        let base_deadline = self.dl.abs_deadline();
        let state = donor.map(|(task, key)| {
            let effective = crate::pi_prio::class_with_key(base, base_deadline, key);
            let borrowed = matches!((effective, key.class),
                (SchedClass::Deadline, SchedClass::Deadline))
                && (!matches!(base, SchedClass::Deadline) || key.special
                    || crate::deadline::dl_time_before(key.deadline, base_deadline));
            (task, key, effective, borrowed)
        });
        self.begin_publish();
        match state {
            Some((task, key, effective, borrowed)) => {
                let (prio, donor_id) = priority_for_class(key.class);
                self.has_donor.store(true, Ordering::Relaxed);
                self.donor_prio.store(prio.raw(), Ordering::Relaxed);
                self.donor_class.store(donor_id as u8, Ordering::Relaxed);
                self.dl_pi.store(Some(task), key, borrowed);
                let (effective_prio, effective_id) = priority_for_class(effective);
                self.prio.store(effective_prio.raw(), Ordering::Relaxed);
                self.class.store(effective_id as u8, Ordering::Relaxed);
            }
            None => {
                self.has_donor.store(false, Ordering::Relaxed);
                self.donor_prio.store(SchedPriority::Idle.raw(), Ordering::Relaxed);
                self.donor_class.store(SchedClassId::Idle as u8, Ordering::Relaxed);
                self.dl_pi.clear();
                self.prio.store(normal.raw(), Ordering::Relaxed);
                self.class.store(normal_id as u8, Ordering::Relaxed);
            }
        }
        self.end_publish();
    }

    #[cfg(test)]
    /// Concrete donor snapshot under TaskPi or stable owner rq. # C: O(1)
    pub(crate) fn top_donor(&self) -> Option<Arc<Task>> { self.dl_pi.top() }
}

impl Task {
    /// Configured absolute deadline before PI selection. # C: O(1)
    pub(crate) fn configured_dl_deadline(&self) -> u64 { self.sched.dl.abs_deadline() }
    /// Configured special-entity state before PI selection. # C: O(1)
    pub(crate) fn configured_dl_special(&self) -> bool { self.sched.dl.params().is_special() }
    /// Owner-local absolute deadline used by EDF ordering. # C: O(1)
    pub fn effective_dl_deadline(&self) -> u64 { self.sched.effective_dl_deadline() }
    /// Special state selected from the effective reservation. # C: O(1)
    pub fn effective_dl_special(&self) -> bool { self.sched.effective_dl_special() }
    /// Immutable reservation selected by PI. # C: O(1)
    pub(crate) fn effective_dl_params(&self) -> DlParams { self.sched.effective_dl_params() }
    /// Whether PI selected another task's reservation. # C: O(1)
    pub(crate) fn uses_borrowed_dl(&self) -> bool { self.sched.uses_borrowed_dl() }
    /// Coherent waiter key captured under TaskPi and rq. # C: O(1)
    pub(crate) fn pi_donor_key_unlocked(&self) -> PiDonorKey {
        let p = self.effective_dl_params();
        PiDonorKey { class: self.sched_class(), deadline: self.effective_dl_deadline(),
            special: p.is_special(), dl_params: PiDlParams { runtime: p.runtime,
                deadline: p.deadline, period: p.period, bw: p.bw,
                density: p.density, flags: p.flags } }
    }
    /// Reconcile owner-local CBS state after publishing a PI donor. # C: O(1)
    pub(crate) fn replenish_pi_unlocked(&self, now: u64) {
        crate::deadline::live::replenish_pi(self, now);
    }
    /// Publish the selected donor under TaskPi and stable rq. # C: O(1)
    pub(crate) fn set_pi_top_task_unlocked(&self,
        donor: Option<(&Arc<Task>, PiDonorKey)>) { self.sched.store_top_donor(donor); }
    #[cfg(test)]
    /// Concrete donor snapshot under TaskPi or stable rq. # C: O(1)
    pub(crate) fn pi_top_task_unlocked(&self) -> Option<Arc<Task>> { self.sched.top_donor() }
}
