// Zero-lag retention through per-entity embedded timer nodes. The intrusive
// queue owns entity state until expiry, so task exit is safe without a lookup
// and no scheduler-lock or hard-IRQ path allocates.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use super::bw::{Admission, PendingUse, DL_BW};
use super::cbs::DlSched;
use super::entity::{DlEntity, DlEntityState, InactiveReservation};
use super::params::DlParams;
use crate::Task;

struct Queue {
    head: Option<Arc<DlEntityState>>,
}

impl Queue {
    const fn new() -> Queue { Queue { head: None } }
    fn earliest(&self) -> u64 {
        self.head.as_ref().and_then(|entity| entity_timer(entity)).map_or(u64::MAX, |h| h.at())
    }
}

static QUEUE: sync::Spinlock<Queue, sync::DlReplenish> = sync::Spinlock::new(Queue::new());
static EARLIEST_NS: AtomicU64 = AtomicU64::new(u64::MAX);
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
fn reprogram() { crate::timers::reprogram_local(); }
#[cfg(not(any(target_os = "oxide-kernel", test, feature = "hosted")))]
fn reprogram() {}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
macro_rules! q_lock { () => { QUEUE.lock_irqsave::<hal_x86_64::X86IrqGate>() }; }
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
macro_rules! q_lock { () => { QUEUE.lock_irqsave::<hal_aarch64::ArmIrqGate>() }; }
#[cfg(not(target_os = "oxide-kernel"))]
macro_rules! q_lock { () => { QUEUE.lock() }; }

/// Absolute zero-lag instant for the current reservation and instance.
/// # C: O(1)
pub fn zero_lag(p: &DlParams, s: &DlSched) -> u64 {
    if p.runtime == 0 { return s.deadline; }
    let lag = (s.runtime as i128 * p.period as i128) / p.runtime as i128;
    s.deadline.wrapping_sub(lag as u64)
}

/// Retain `bw` until `at`. `false` means this entity generation already owns
/// an inactive token, so a concurrent leave must not mint a second booking.
/// # C: O(N armed)
pub fn arm(task: &Task, at: u64, bw: u64, clear_on_expire: bool) -> bool {
    let entity = &task.sched.dl;
    let mut generation = NEXT_ID.fetch_add(1, Ordering::AcqRel) & ((1u64 << 62) - 1);
    if generation == 0 { generation = 1; }
    let Some(held) = entity.arm_inactive(generation, at, bw, clear_on_expire) else { return false };
    {
        let mut queue = q_lock!();
        insert(&mut queue, Arc::clone(held.entity()), at);
        EARLIEST_NS.store(queue.earliest(), Ordering::Release);
    }
    reprogram();
    true
}

/// Earliest inactive expiry, or `u64::MAX`. # C: O(1)
pub fn earliest_ns() -> u64 { EARLIEST_NS.load(Ordering::Acquire) }

fn cancel(held: &InactiveReservation) {
    let removed = {
        let mut queue = q_lock!();
        let removed = remove(&mut queue, held.entity());
        EARLIEST_NS.store(queue.earliest(), Ordering::Release);
        removed
    };
    drop(removed);
    reprogram();
}

/// Admission for a task whose policy and attached booking can differ. A
/// pending ordinary token is replaced under the bandwidth lock on re-entry.
/// # C: O(N armed)
pub(crate) fn admit(entity: &DlEntity, cap: u64, want_dl: bool, is_dl: bool,
                    current: &DlParams, wanted: &DlParams) -> Result<Admission, ()> {
    let pending = entity.inactive();
    let admitted = DL_BW.admit_pending(cap, want_dl, is_dl, current.bw, wanted.bw,
        current.is_special(), wanted.is_special(), pending.as_ref())?;
    match (pending, admitted.pending_use()) {
        (Some(held), PendingUse::Reused) => {
            cancel(&held);
            entity.consume_inactive(&held, true);
        }
        (Some(held), PendingUse::Expired) => {
            cancel(&held);
            entity.consume_inactive(&held, false);
            entity.clear();
        }
        _ => {}
    }
    Ok(admitted)
}

/// Release every retained booking whose zero-lag instant has arrived.
/// # C: O(due · N armed)
/// # Ctx: timer IRQ
pub fn expire(now: u64) {
    loop {
        let due = {
            let mut queue = q_lock!();
            let due = pop_due(&mut queue, now);
            EARLIEST_NS.store(queue.earliest(), Ordering::Release);
            due
        };
        match due {
            Due::Pending => break,
            Due::Stale(node) => drop(node),
            Due::Ready(held) => expire_claim(held),
        }
    }
}

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
fn expire_claim(held: InactiveReservation) {
    let Some(task) = held.owner().and_then(|owner| owner.upgrade()) else {
        if DL_BW.release_inactive(&held) { held.finish_expiry(); }
        return;
    };
    if !held.same_entity(&task.sched.dl.state_ref()) { return; }
    #[cfg(test)]
    if crate::live::runqueue::global().is_none() {
        if DL_BW.release_inactive(&held) { held.finish_expiry(); }
        return;
    }
    let get_rq = |cpu| unsafe { crate::live::runqueue::global_for(cpu) };
    match crate::live::rq_locate::task_rq_lock_with(&get_rq, &task) {
        crate::live::rq_locate::StableTaskGuard::Owned(_lock) => {
            if held.same_entity(&task.sched.dl.state_ref())
                && DL_BW.release_inactive(&held) { held.finish_expiry(); }
        }
        crate::live::rq_locate::StableTaskGuard::OffRq(_pi) => {
            if held.same_entity(&task.sched.dl.state_ref())
                && DL_BW.release_inactive(&held) { held.finish_expiry(); }
        }
    };
}

#[cfg(not(any(target_os = "oxide-kernel", test, feature = "hosted")))]
fn expire_claim(held: InactiveReservation) {
    let Some(task) = held.owner().and_then(|owner| owner.upgrade()) else {
        if DL_BW.release_inactive(&held) { held.finish_expiry(); }
        return;
    };
    let _pi = task.pi_lock.lock();
    if held.same_entity(&task.sched.dl.state_ref())
        && DL_BW.release_inactive(&held) { held.finish_expiry(); }
}

fn entity_timer(entity: &Arc<DlEntityState>) -> Option<InactiveReservation> {
    entity.inactive_timer()
}

fn insert(queue: &mut Queue, entity: Arc<DlEntityState>, at: u64) {
    let mut link = core::ptr::from_mut(&mut queue.head);
    loop {
        // SAFETY: QUEUE is exclusively held and `link` names one of its links.
        let Some(current) = (unsafe { &*link }).as_ref().map(Arc::clone) else { break };
        let current_at = entity_timer(&current).map_or(u64::MAX, |held| held.at());
        if super::cbs::dl_time_before(at, current_at) { break; }
        // SAFETY: QUEUE is held and each embedded inactive node is linked once.
        link = core::ptr::from_mut(unsafe { current.inactive_next_mut() });
    }
    // SAFETY: QUEUE is held and `entity` is not linked in this queue yet.
    let next = unsafe { entity.inactive_next_mut() };
    // SAFETY: QUEUE is exclusively held and `link` names its insertion slot.
    *next = unsafe { &mut *link }.take();
    // SAFETY: QUEUE is exclusively held and `link` names its insertion slot.
    unsafe { *link = Some(entity); }
}

fn remove(queue: &mut Queue, target: &Arc<DlEntityState>) -> Option<Arc<DlEntityState>> {
    let mut link = core::ptr::from_mut(&mut queue.head);
    loop {
        // SAFETY: QUEUE is exclusively held and `link` names one of its links.
        let Some(current) = (unsafe { &*link }).as_ref().map(Arc::clone) else { break };
        if Arc::ptr_eq(&current, target) {
            // SAFETY: QUEUE is exclusively held and `link` names the matched slot.
            let removed = unsafe { &mut *link }.take().expect("inactive link just observed");
            // SAFETY: QUEUE is held and this is the node being unlinked.
            let next = unsafe { removed.inactive_next_mut() }.take();
            // SAFETY: QUEUE is exclusively held and `link` names the matched slot.
            unsafe { *link = next; }
            return Some(removed);
        }
        // SAFETY: QUEUE is held and each embedded inactive node is linked once.
        link = core::ptr::from_mut(unsafe { current.inactive_next_mut() });
    }
    None
}

enum Due {
    Pending,
    Stale(Arc<DlEntityState>),
    Ready(InactiveReservation),
}

fn pop_due(queue: &mut Queue, now: u64) -> Due {
    let Some(head) = queue.head.as_ref() else { return Due::Pending };
    let Some(held) = entity_timer(head) else {
        let node = queue.head.take().expect("inactive head just observed");
        // SAFETY: QUEUE is held and the stale head is being unlinked.
        queue.head = unsafe { node.inactive_next_mut() }.take();
        return Due::Stale(node);
    };
    if super::cbs::dl_time_before(now, held.at()) { return Due::Pending; }
    let node = queue.head.take().expect("inactive head just observed");
    // SAFETY: QUEUE is held and the head is being unlinked.
    queue.head = unsafe { node.inactive_next_mut() }.take();
    Due::Ready(held)
}

#[cfg(test)]
pub(crate) fn clear_for_tests() {
    loop {
        let node = {
            let mut queue = q_lock!();
            let node = queue.head.take();
            if let Some(node) = node.as_ref() {
                // SAFETY: QUEUE is held and its head is being unlinked.
                queue.head = unsafe { node.inactive_next_mut() }.take();
            }
            EARLIEST_NS.store(queue.earliest(), Ordering::Release);
            node
        };
        if node.is_none() { break; }
    }
}

#[cfg(test)]
#[path = "tests/inactive.rs"] mod tests;
