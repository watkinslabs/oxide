// Replenishment queue: the throttled `SCHED_DEADLINE` entities, ordered by the
// instant their next instance starts.
//
// This is the half of the class that makes an exhausted budget an ENFORCEMENT.
// Throttling a task without a way to bring it back would simply delete it from
// the schedule; the queue below is folded into the one-shot timer deadline, so
// the hardware interrupt that ends a throttle is programmed for the exact
// instant the next period begins rather than for the next accounting tick.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use sync::{DlReplenish as DlReplenishClass, Spinlock};

use crate::Task;

/// Throttled entities keyed `(replenishment instant, tid)`.
struct Queue {
    entries: alloc::collections::BTreeMap<(u64, u32), Weak<Task>>,
}

impl Queue {
    const fn new() -> Queue { Queue { entries: alloc::collections::BTreeMap::new() } }
    fn earliest(&self) -> u64 { self.entries.keys().next().map(|(t, _)| *t).unwrap_or(u64::MAX) }
}

static QUEUE: Spinlock<Queue, DlReplenishClass> = Spinlock::new(Queue::new());

/// Earliest queued replenishment instant, published for the one-shot programmer
/// to read without taking the queue. `u64::MAX` = nothing throttled.
static EARLIEST_NS: AtomicU64 = AtomicU64::new(u64::MAX);

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
macro_rules! q_lock { () => { QUEUE.lock_irqsave::<hal_x86_64::X86IrqGate>() }; }
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
macro_rules! q_lock { () => { QUEUE.lock_irqsave::<hal_aarch64::ArmIrqGate>() }; }
#[cfg(not(target_os = "oxide-kernel"))]
macro_rules! q_lock { () => { QUEUE.lock() }; }

/// Park `task` until `at`, the instant its next instance begins.
/// # C: O(log N)
pub fn arm(task: &Arc<Task>, at: u64) {
    task.dl.set_replenish_at(at);
    let mut g = q_lock!();
    g.entries.retain(|(_, tid), _| *tid != task.tid);
    g.entries.insert((at, task.tid), Arc::downgrade(task));
    EARLIEST_NS.store(g.earliest(), Ordering::Release);
}

/// Cancel `task`'s pending replenishment — it left the deadline class, exited,
/// or was replenished inline because its instant had already passed.
/// # C: O(N)
pub fn disarm(task: &Task) {
    // Every task exit runs this; the overwhelming majority have never been
    // throttled, and taking the global queue lock for each of them would put a
    // machine-wide serialisation point on the exit path.
    if task.dl.replenish_at() == 0 { return; }
    task.dl.set_replenish_at(0);
    let mut g = q_lock!();
    let before = g.entries.len();
    g.entries.retain(|(_, tid), _| *tid != task.tid);
    if g.entries.len() != before { EARLIEST_NS.store(g.earliest(), Ordering::Release); }
}

/// Earliest queued replenishment instant, or `u64::MAX`. Lock-free.
/// # C: O(1)
pub fn earliest_ns() -> u64 { EARLIEST_NS.load(Ordering::Acquire) }

/// Take every entity whose replenishment instant has arrived.
///
/// Collect-then-release: the caller re-enqueues each returned task under the
/// runqueue lock, which ranks BELOW this queue, so holding both at once would
/// invert the order (`06§3.6`).
/// # C: O(due · log N)
/// # Ctx: timer IRQ
pub fn take_due(now: u64) -> Vec<Arc<Task>> {
    let mut out = Vec::new();
    if earliest_ns() > now { return out; }
    let mut g = q_lock!();
    loop {
        let Some((&key, _)) = g.entries.iter().next() else { break };
        if key.0 > now { break; }
        let entry = g.entries.remove(&key).expect("key just observed");
        // A dead task is simply dropped: its reservation was released when it
        // left the class or exited.
        if let Some(t) = entry.upgrade() {
            // Another path already replenished this entity (a wakeup whose
            // instance had genuinely restarted, or a policy change). The stamp
            // no longer names this entry, so acting on it would replenish an
            // instance nobody throttled.
            if t.dl.replenish_at() == key.0 { out.push(t); }
        }
    }
    EARLIEST_NS.store(g.earliest(), Ordering::Release);
    out
}
