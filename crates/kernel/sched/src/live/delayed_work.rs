// `delayed_work` — Linux `queue_delayed_work` (`skizm.md` §2, Step 8).
//
// A work item that runs after a delay instead of at the next drain. Linux backs
// it with a `timer_list` that queues the work when it expires; the same split
// here — a deadline list walked by the tick, handing due items to the workqueue,
// which is where they run in process context and may sleep.
//
// The list is a bounded array behind an irqsave lock for the same reason the
// workqueue ring is: `queue_delayed_work` must be callable from a hard IRQ, so
// it can neither allocate nor spin on a lock process context holds.

use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Spinlock, Workqueue as WorkClass};

use super::workqueue::{queue_work_on, WorkFn};

/// Concurrent delayed items. One slot per pending item; `queue_delayed_work`
/// reports failure rather than growing in an ISR.
pub const DELAYED_CAPACITY: usize = 32;

#[derive(Copy, Clone)]
struct Delayed {
    deadline_ns: u64,
    cpu: usize,
    func: WorkFn,
    arg: usize,
}

struct Pending {
    items: [Option<Delayed>; DELAYED_CAPACITY],
    /// Refused because the table was full — surfaced so saturation is visible.
    dropped: u64,
}

impl Pending {
    const fn new() -> Self { Self { items: [None; DELAYED_CAPACITY], dropped: 0 } }
}

static PENDING: Spinlock<Pending, WorkClass> = Spinlock::new(Pending::new());
/// Earliest pending deadline, so the tick can skip the walk entirely when
/// nothing is due — the common case.
static EARLIEST_NS: AtomicU64 = AtomicU64::new(u64::MAX);

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
type DwIrq = hal_x86_64::X86IrqGate;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
type DwIrq = hal_aarch64::ArmIrqGate;
#[cfg(not(target_os = "oxide-kernel"))]
type DwIrq = sync::NoopIrq;

/// Run `func(arg)` on `cpu` once `now_ns + delay_ns` has passed (Linux
/// `queue_delayed_work_on`). Returns false if the table is full.
///
/// Safe from any context, including a hard IRQ: no allocation, irqsave lock.
/// # C: O(DELAYED_CAPACITY)
/// # Ctx: any, including hard IRQ
pub fn queue_delayed_work_on(cpu: usize, func: WorkFn, arg: usize,
    now_ns: u64, delay_ns: u64) -> bool
{
    let deadline_ns = now_ns.saturating_add(delay_ns);
    let mut g = PENDING.lock_irqsave::<DwIrq>();
    let Some(slot) = g.items.iter_mut().find(|s| s.is_none()) else {
        g.dropped += 1;
        return false;
    };
    *slot = Some(Delayed { deadline_ns, cpu, func, arg });
    drop(g);
    // Publish the new earliest so the tick's fast path stays a single compare.
    EARLIEST_NS.fetch_min(deadline_ns, Ordering::AcqRel);
    true
}

/// Items refused because the table was full.
/// # C: O(1)
pub fn dropped() -> u64 { PENDING.lock_irqsave::<DwIrq>().dropped }

/// Pending (not yet due) item count.
/// # C: O(DELAYED_CAPACITY)
pub fn pending() -> usize {
    PENDING.lock_irqsave::<DwIrq>().items.iter().filter(|s| s.is_some()).count()
}

/// Hand every item whose deadline has passed to the workqueue. Called from the
/// timer tick; the single `EARLIEST_NS` compare is the whole cost when nothing
/// is due.
/// # C: O(1) typical; O(DELAYED_CAPACITY) when something is due
/// # Ctx: any, including hard IRQ
pub fn tick(now_ns: u64) -> usize {
    if EARLIEST_NS.load(Ordering::Acquire) > now_ns { return 0; }
    let mut due: [Option<Delayed>; DELAYED_CAPACITY] = [None; DELAYED_CAPACITY];
    let mut n = 0;
    let mut next = u64::MAX;
    {
        let mut g = PENDING.lock_irqsave::<DwIrq>();
        for slot in g.items.iter_mut() {
            let Some(item) = *slot else { continue };
            if item.deadline_ns <= now_ns {
                *slot = None;
                due[n] = Some(item);
                n += 1;
            } else if item.deadline_ns < next {
                next = item.deadline_ns;
            }
        }
    }
    // Queue OUTSIDE the pending lock: `queue_work_on` takes the workqueue ring
    // lock, and holding two ISR-reachable locks at once is how a deadlock gets
    // built. Nothing here needs them held together.
    EARLIEST_NS.store(next, Ordering::Release);
    let mut queued = 0;
    for item in due.iter().flatten() {
        if queue_work_on(item.cpu, item.func, item.arg) { queued += 1; }
    }
    queued
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reset() {
        let mut g = PENDING.lock_irqsave::<DwIrq>();
        for s in g.items.iter_mut() { *s = None; }
        g.dropped = 0;
        drop(g);
        EARLIEST_NS.store(u64::MAX, Ordering::Release);
    }

    fn noop(_arg: usize) {}

    #[test]
    fn nothing_is_due_before_the_deadline() {
        reset();
        assert!(queue_delayed_work_on(0, noop, 1, 1_000, 500));
        assert_eq!(pending(), 1);
        assert_eq!(tick(1_400), 0, "not yet due");
        assert_eq!(pending(), 1);
    }

    #[test]
    fn a_due_item_is_handed_to_the_workqueue_exactly_once() {
        reset();
        assert!(queue_delayed_work_on(0, noop, 2, 1_000, 500));
        assert_eq!(tick(1_500), 1, "due at exactly the deadline");
        assert_eq!(pending(), 0);
        assert_eq!(tick(9_999), 0, "must not fire twice");
    }

    #[test]
    fn the_earliest_deadline_gates_the_walk() {
        reset();
        assert!(queue_delayed_work_on(0, noop, 3, 0, 900));
        assert!(queue_delayed_work_on(0, noop, 4, 0, 100));
        // Only the 100 item is due; the 900 one stays and becomes the earliest.
        assert_eq!(tick(200), 1);
        assert_eq!(pending(), 1);
        assert_eq!(EARLIEST_NS.load(Ordering::Acquire), 900);
    }

    #[test]
    fn a_full_table_refuses_rather_than_dropping_silently() {
        reset();
        for i in 0..DELAYED_CAPACITY {
            assert!(queue_delayed_work_on(0, noop, i, 0, 1_000));
        }
        assert!(!queue_delayed_work_on(0, noop, 999, 0, 1_000));
        assert_eq!(dropped(), 1, "a refusal must be counted, not hidden");
        reset();
    }
}
