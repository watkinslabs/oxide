// Replenishment queue: the throttled `SCHED_DEADLINE` entities, ordered by the
// instant their next instance starts.
//
// This is the half of the class that makes an exhausted budget an ENFORCEMENT.
// Throttling a task without a way to bring it back would simply delete it from
// the schedule; the queue below is folded into the one-shot timer deadline, so
// the hardware interrupt that ends a throttle is programmed for the exact
// instant the next period begins rather than for the next accounting tick.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use sync::{DlReplenish as DlReplenishClass, Spinlock};

use crate::Task;
use super::entity::{DlEntityState, ReplenishmentClaim};

/// Throttled entities keyed `(replenishment instant, tid)`.
struct Queue {
    head: Option<Arc<DlEntityState>>,
}

impl Queue {
    const fn new() -> Queue { Queue { head: None } }
    fn earliest(&self) -> u64 {
        self.head.as_ref().map_or(u64::MAX, |entity| entity.replenish_at())
    }
}

static QUEUE: Spinlock<Queue, DlReplenishClass> = Spinlock::new(Queue::new());

/// Earliest queued replenishment instant, published for the one-shot programmer
/// to read without taking the queue. `u64::MAX` = nothing throttled.
static EARLIEST_NS: AtomicU64 = AtomicU64::new(u64::MAX);
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
fn reprogram() { crate::timers::reprogram_local(); }
#[cfg(not(any(target_os = "oxide-kernel", test, feature = "hosted")))]
fn reprogram() {}

/// Timer-owned replenishment generation. Effects commit only while this exact
/// claim remains current under the task's stable scheduler lock.
pub(super) struct DueReplenishment {
    pub(super) task: Arc<Task>,
    pub(super) claim: ReplenishmentClaim,
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
macro_rules! q_lock { () => { QUEUE.lock_irqsave::<hal_x86_64::X86IrqGate>() }; }
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
macro_rules! q_lock { () => { QUEUE.lock_irqsave::<hal_aarch64::ArmIrqGate>() }; }
#[cfg(not(target_os = "oxide-kernel"))]
macro_rules! q_lock { () => { QUEUE.lock() }; }

/// Park `task` until `at`, the instant its next instance begins.
/// # C: O(N armed)
pub fn arm(task: &Arc<Task>, at: u64) {
    let entity = task.sched.dl.state_ref();
    entity.set_replenish_owner(Arc::downgrade(task));
    let removed = {
        let mut g = q_lock!();
        let removed = remove(&mut g, &entity);
        let mut generation = NEXT_ID.fetch_add(1, Ordering::AcqRel) & ((1u64 << 62) - 1);
        if generation == 0 { generation = 1; }
        task.sched.dl.arm_replenish(generation, at);
        insert(&mut g, Arc::clone(&entity), at);
        EARLIEST_NS.store(g.earliest(), Ordering::Release);
        removed
    };
    drop(removed);
    reprogram();
}

/// Cancel `task`'s pending replenishment — it left the deadline class, exited,
/// or was replenished inline because its instant had already passed.
/// # C: O(N)
pub fn disarm(task: &Task) {
    // Every task exit runs this; the overwhelming majority have never been
    // throttled, and taking the global queue lock for each of them would put a
    // machine-wide serialisation point on the exit path.
    if task.sched.dl.replenish_at() == 0 { return; }
    let entity = task.sched.dl.state_ref();
    let removed = {
        let mut g = q_lock!();
        task.sched.dl.cancel_replenish();
        let removed = remove(&mut g, &entity);
        EARLIEST_NS.store(g.earliest(), Ordering::Release);
        removed
    };
    drop(removed);
    reprogram();
}

/// Earliest queued replenishment instant, or `u64::MAX`. Lock-free.
/// # C: O(1)
pub fn earliest_ns() -> u64 {
    let replenish = EARLIEST_NS.load(Ordering::Acquire);
    let inactive = super::inactive::earliest_ns();
    match (replenish, inactive) {
        (u64::MAX, other) | (other, u64::MAX) => other,
        (a, b) if super::cbs::dl_time_before(a, b) => a,
        (_, b) => b,
    }
}

/// Take one entity whose replenishment instant has arrived.
///
/// Collect-then-release: the caller re-enqueues each returned task under the
/// runqueue lock, which ranks BELOW this queue, so holding both at once would
/// invert the order (`06§3.6`).
/// # C: O(1)
/// # Ctx: timer IRQ
pub(super) fn take_due(now: u64) -> Option<DueReplenishment> {
    loop {
        let (entity, claim) = {
            let mut g = q_lock!();
            let head = g.head.as_ref()?;
            let at = head.replenish_at();
            if super::cbs::dl_time_before(now, at) { return None; }
            let entity = g.head.take().expect("replenishment head just observed");
            // SAFETY: QUEUE is held and its head is being unlinked.
            g.head = unsafe { entity.replenish_next_mut() }.take();
            EARLIEST_NS.store(g.earliest(), Ordering::Release);
            let claim = entity.claim_replenish();
            (entity, claim)
        };
        let Some(claim) = claim else { continue };
        let Some(owner) = entity.replenish_owner() else {
            let _ = claim.finish();
            continue;
        };
        let Some(task) = owner.upgrade() else {
            let _ = claim.finish();
            continue;
        };
        return Some(DueReplenishment { task, claim });
    }
}

#[cfg(test)]
pub(super) fn clear_for_tests() {
    loop {
        let node = {
            let mut queue = q_lock!();
            let node = queue.head.take();
            if let Some(node) = node.as_ref() {
                // SAFETY: QUEUE is held and its head is being unlinked.
                queue.head = unsafe { node.replenish_next_mut() }.take();
            }
            EARLIEST_NS.store(queue.earliest(), Ordering::Release);
            node
        };
        if node.is_none() { break; }
    }
}

fn insert(queue: &mut Queue, entity: Arc<DlEntityState>, at: u64) {
    entity.set_replenish_at(at);
    let mut link = core::ptr::from_mut(&mut queue.head);
    loop {
        // SAFETY: QUEUE is exclusively held and `link` names one of its links.
        let Some(current) = (unsafe { &*link }).as_ref().map(Arc::clone) else { break };
        if super::cbs::dl_time_before(at, current.replenish_at()) { break; }
        // SAFETY: QUEUE is held and each embedded replenish node is linked once.
        link = core::ptr::from_mut(unsafe { current.replenish_next_mut() });
    }
    // SAFETY: QUEUE is held and `entity` is not linked in this queue yet.
    let next = unsafe { entity.replenish_next_mut() };
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
            let removed = unsafe { &mut *link }.take().expect("replenishment link just observed");
            // SAFETY: QUEUE is held and this is the node being unlinked.
            let next = unsafe { removed.replenish_next_mut() }.take();
            // SAFETY: QUEUE is exclusively held and `link` names the matched slot.
            unsafe { *link = next; }
            return Some(removed);
        }
        // SAFETY: QUEUE is held and each embedded replenish node is linked once.
        link = core::ptr::from_mut(unsafe { current.replenish_next_mut() });
    }
    None
}
