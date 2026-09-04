// Applying and undoing a PI-futex priority boost on a live task.
//
// The ORDERING rule (which class wins) is in the non-gated `crate::pi_prio`
// and is hosted-tested there; this file owns only the runqueue-visible half:
// update normal state, move the task between class trees, and restore it.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicPtr, Ordering};
use crate::{SchedClass, Task, TaskPiState};

pub use crate::pi_prio::{base_class, is_boosted};

pub type WaiterChangeHook = fn(&Arc<Task>);
static WAITER_CHANGE_HOOK: AtomicPtr<()> =
    AtomicPtr::new(core::ptr::null_mut());

fn publish_hook(slot: &AtomicPtr<()>, hook: WaiterChangeHook) -> bool {
    slot.compare_exchange(core::ptr::null_mut(), hook as *const () as *mut (),
        Ordering::AcqRel, Ordering::Acquire).is_ok()
}

fn invoke_hook(slot: &AtomicPtr<()>, task: &Arc<Task>) {
    let raw = slot.load(Ordering::Acquire);
    if raw.is_null() { return; }
    // SAFETY: slots contain only values converted from valid WaiterChangeHook function pointers.
    let hook = unsafe { core::mem::transmute::<*mut (), WaiterChangeHook>(raw) };
    hook(task);
}

/// Install the IPC rtmutex-adjust callback without introducing sched -> IPC.
/// The callback is invoked only after a scheduler transaction has released
/// TaskPi and rq, so it may acquire RtMutexWait and begin a fresh transaction.
/// # C: O(1)
pub fn install_waiter_change_hook(hook: WaiterChangeHook) {
    assert!(publish_hook(&WAITER_CHANGE_HOOK, hook),
        "scheduler waiter-change hook already has a different owner");
}

#[cfg(test)]
static TEST_WAITER_CHANGE_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
#[cfg(test)]
static TEST_WAITER_CHANGE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Scoped observer for lock-boundary tests; it never mutates the production singleton.
#[cfg(test)]
pub(crate) struct TestWaiterChangeHook {
    _serial: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for TestWaiterChangeHook {
    fn drop(&mut self) { TEST_WAITER_CHANGE_HOOK.store(core::ptr::null_mut(), Ordering::Release); }
}

#[cfg(test)]
pub(crate) fn scoped_test_waiter_change_hook(hook: WaiterChangeHook) -> TestWaiterChangeHook {
    let serial = TEST_WAITER_CHANGE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    assert!(publish_hook(&TEST_WAITER_CHANGE_HOOK, hook),
        "scheduler test waiter-change hook already installed");
    TestWaiterChangeHook { _serial: serial }
}

/// Linux `rt_mutex_adjust_pi`: tell IPC that a blocked task's coherent waiter
/// key may have changed. Caller holds neither TaskPi, rq, nor RtMutexWait.
/// # C: callback-defined
pub fn notify_waiter_change(task: &Arc<Task>) {
    invoke_hook(&WAITER_CHANGE_HOOK, task);
    #[cfg(test)]
    invoke_hook(&TEST_WAITER_CHANGE_HOOK, task);
}

/// Record a new BASE class for a task that may be boosted right now.
///
/// `sched_setscheduler` on a boosted task updates canonical normal state while
/// the stronger donated effective state remains active. The new normal state
/// takes effect at deboost, or immediately when it outranks the donation.
/// # C: O(N_cpus · log N)
#[cfg(test)]
pub(crate) fn set_base_class(task: &Arc<Task>, new: SchedClass) {
    assert!(!matches!(new, SchedClass::Deadline),
        "PI base update cannot bypass deadline admission");
    super::runqueue::set_normal_class(task, new);
}

/// Publish the concrete top PI donor. The donor's effective deadline entity is
/// borrowed without changing the owner's configured reservation.
/// # C: O(N_cpus · log N)
pub fn apply_boost(task: &Arc<Task>, donor: Option<Arc<Task>>) {
    let donor = donor.map(|donor| {
        let key = donor_key(&donor);
        (donor, key)
    });
    apply_boost_keyed(task, donor);
}

/// Capture one coherent waiter-node key under donor TaskPi and rq. # C: O(N_cpus)
pub fn donor_key(task: &Arc<Task>) -> crate::pi_prio::PiDonorKey {
    let _stable = super::rq_locate::task_rq_lock_with(
        &|cpu| {
            // SAFETY: global_for accepts every CPU index and returns only a
            // permanently allocated, fully installed runqueue.
            unsafe { super::runqueue::global_for(cpu) }
        }, task);
    task.pi_donor_key_unlocked()
}

/// Publish donor identity and the key selected under RtMutexWait. # C: O(N_cpus · log N)
pub fn apply_boost_keyed(task: &Arc<Task>, donor: Option<(Arc<Task>, crate::pi_prio::PiDonorKey)>) {
    let now = super::schedule::change_clock_now();
    super::runqueue::mutate_effective_if(task,
        |task| {
            let (effective, special) = effective_target(task, donor.as_ref());
            task.sched_class() != effective
                || matches!(effective, SchedClass::Deadline)
                    && task.effective_dl_special() != special
        },
        |task| publish_top(task, donor.as_ref(), now));
}

/// Edit one task's intrusive PI waiter tree and publish its cached top donor
/// in the same `TaskPi -> rq` transaction. The caller may hold an rtmutex wait
/// lock; `edit` must only link/unlink already allocated waiter nodes.
/// # C: O(log N_owned + N_cpus · log N_rq)
pub fn update_owner_waiters<F>(task: &Arc<Task>, edit: F) -> bool
where F: FnOnce(&mut TaskPiState) {
    update_owner_waiters_with(
        &|cpu| unsafe { super::runqueue::global_for(cpu) }, task, edit)
}

/// Injected form of [`update_owner_waiters`] used to exercise the exact
/// TaskPi/rq transaction against hosted runqueues. # C: O(log N_owned + log N_rq)
pub(crate) fn update_owner_waiters_with<'a, R, F>(get_rq: &R, task: &'a Arc<Task>, edit: F) -> bool
where
    R: Fn(u32) -> Option<&'a super::runqueue::Runqueue>,
    F: FnOnce(&mut TaskPiState),
{
    use super::rq_locate::{SchedChange, StableTaskGuard};
    use super::runqueue::RqIrq;

    let mut pi = task.pi_lock.lock_irqsave::<RqIrq>();
    let before = pi.top_identity();
    edit(&mut pi);
    let after = pi.top_identity();
    if before == after { return false; }
    let donor = pi.top_donor();
    let moves_queue = {
        let (effective, special) = effective_target(task, donor.as_ref());
        task.sched_class() != effective
            || matches!(effective, SchedClass::Deadline)
                && task.effective_dl_special() != special
    };
    let stable = super::rq_locate::__task_rq_lock_with(get_rq, task, pi);
    match stable {
        StableTaskGuard::Owned(lock) if moves_queue => {
            let now = super::schedule::change_clock_now();
            let _change = SchedChange::from_lock(lock, task, now);
            publish_top(task, donor.as_ref(), now);
        }
        StableTaskGuard::Owned(_) | StableTaskGuard::OffRq(_) => {
            publish_top(task, donor.as_ref(), super::schedule::change_clock_now());
        }
    }
    true
}

fn publish_top(task: &Task,
    donor: Option<&(Arc<Task>, crate::pi_prio::PiDonorKey)>, now: u64) {
    task.set_pi_top_task_unlocked(donor.map(|(task, key)| (task, *key)));
    task.replenish_pi_unlocked(now);
}

fn effective_target(task: &Task,
    donor: Option<&(Arc<Task>, crate::pi_prio::PiDonorKey)>) -> (SchedClass, bool) {
    let base = task.normal_sched_class();
    let base_deadline = task.configured_dl_deadline();
    let effective = donor.map(|(_, key)| crate::pi_prio::class_with_key(base, base_deadline, *key))
        .unwrap_or(base);
    let borrowed = donor.is_some_and(|(_, key)| matches!(key.class, SchedClass::Deadline)
        && (!matches!(base, SchedClass::Deadline)
            || key.special || crate::deadline::dl_time_before(key.deadline, base_deadline)));
    if borrowed {
        let key = donor.unwrap().1;
        (effective, key.special)
    } else {
        (effective, task.configured_dl_special())
    }
}

/// Drop any PI boost and return `task` to its base class.
/// # C: O(N_cpus · log N)
pub fn deboost(task: &Arc<Task>) {
    apply_boost(task, None);
}

#[cfg(test)]
mod hook_tests {
    use super::*;
    use core::sync::atomic::AtomicBool;
    use std::sync::{Arc as StdArc, Barrier};

    fn hook_a(_task: &Arc<Task>) {}
    fn hook_b(_task: &Arc<Task>) {}

    #[test]
    fn callback_publication_has_no_claimed_before_ready_state() {
        let claimed = StdArc::new(AtomicBool::new(false));
        let old_slot = StdArc::new(AtomicPtr::new(core::ptr::null_mut()));
        let entered = StdArc::new(Barrier::new(2));
        let release = StdArc::new(Barrier::new(2));
        let c = StdArc::clone(&claimed);
        let s = StdArc::clone(&old_slot);
        let e = StdArc::clone(&entered);
        let r = StdArc::clone(&release);
        let old = std::thread::spawn(move || {
            c.store(true, Ordering::Release);
            e.wait();
            r.wait();
            s.store(hook_a as *const () as *mut (), Ordering::Release);
        });
        entered.wait();
        assert!(claimed.load(Ordering::Acquire));
        assert!(old_slot.load(Ordering::Acquire).is_null(),
            "positive control did not expose claimed-before-published callback state");
        release.wait();
        old.join().unwrap();

        let slot = AtomicPtr::new(core::ptr::null_mut());
        assert!(publish_hook(&slot, hook_a));
        assert!(!slot.load(Ordering::Acquire).is_null(),
            "one atomic publication must make the callback immediately ready");
    }

    #[test]
    fn callback_slot_rejects_every_second_registration() {
        let slot = AtomicPtr::new(core::ptr::null_mut());
        assert!(publish_hook(&slot, hook_a));
        assert!(!publish_hook(&slot, hook_a));
        assert!(!publish_hook(&slot, hook_b));
    }
}
