// `tasklet` — Linux `include/linux/interrupt.h` (`skizm.md` §2, Step 8).
//
// A one-shot callback that runs in SOFTIRQ context. The middle rung between the
// two things this kernel already had:
//
//   softirq slot   static, one handler per slot, registered at boot
//   tasklet        dynamic, scheduled per event, runs in the same context
//   work item      dynamic, runs in process context and MAY SLEEP
//
// So a driver ISR with a bounded, non-sleeping bottom half no longer has to
// claim a whole static softirq slot for it, and no longer has to reach for the
// workqueue (a context switch) just to get deferral.
//
// The Linux guarantee kept here: **the same tasklet never runs on two CPUs at
// once.** That is what lets a tasklet body touch its own state without a lock,
// and it is the property that distinguishes a tasklet from a bare softirq.
// Enforced by a per-slot RUNNING claim.
//
// Bounded array behind an irqsave lock, for the same reason as the workqueue
// ring: `schedule()` is callable from a hard IRQ, so it can neither allocate nor
// spin on a lock process context holds.

use core::sync::atomic::{AtomicBool, Ordering};

use sync::{Spinlock, Workqueue as TaskletClass};

/// Tasklet body. A bare `fn(usize)` — `07§5` forbids `dyn` here, and the arg
/// matches Linux's `unsigned long data`.
pub type TaskletFn = fn(usize);

/// Concurrently-registered tasklets.
pub const TASKLET_CAPACITY: usize = 32;

#[derive(Copy, Clone)]
struct Slot {
    func: TaskletFn,
    arg: usize,
    /// Scheduled and not yet run. Re-scheduling an already-pending tasklet is a
    /// no-op, exactly as Linux's `tasklet_schedule` is.
    pending: bool,
}

struct Table {
    slots: [Option<Slot>; TASKLET_CAPACITY],
    dropped: u64,
}

impl Table {
    const fn new() -> Self { Self { slots: [None; TASKLET_CAPACITY], dropped: 0 } }
}

static TABLE: Spinlock<Table, TaskletClass> = Spinlock::new(Table::new());
/// Per-slot "currently executing" claim, enforcing the never-on-two-CPUs rule.
static RUNNING: [AtomicBool; TASKLET_CAPACITY] =
    [const { AtomicBool::new(false) }; TASKLET_CAPACITY];

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
type TlIrq = hal_x86_64::X86IrqGate;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
type TlIrq = hal_aarch64::ArmIrqGate;
#[cfg(not(target_os = "oxide-kernel"))]
type TlIrq = sync::NoopIrq;

/// Register a tasklet, returning its handle (Linux `tasklet_init`). `None` when
/// the table is full.
/// # C: O(TASKLET_CAPACITY)
pub fn init(func: TaskletFn, arg: usize) -> Option<usize> {
    let mut g = TABLE.lock_irqsave::<TlIrq>();
    let idx = g.slots.iter().position(|s| s.is_none())?;
    g.slots[idx] = Some(Slot { func, arg, pending: false });
    Some(idx)
}

/// Unregister (Linux `tasklet_kill`). Refuses while the body is executing —
/// freeing a tasklet out from under itself is the bug this prevents.
/// # C: O(1)
pub fn kill(handle: usize) -> bool {
    if handle >= TASKLET_CAPACITY { return false; }
    if RUNNING[handle].load(Ordering::Acquire) { return false; }
    let mut g = TABLE.lock_irqsave::<TlIrq>();
    g.slots[handle] = None;
    true
}

/// Mark a tasklet for execution at the next drain (Linux `tasklet_schedule`).
/// Scheduling one that is already pending is a no-op — the run that has not
/// happened yet will observe whatever state prompted this call.
///
/// Safe from any context, including a hard IRQ.
/// # C: O(1)
/// # Ctx: any, including hard IRQ
pub fn schedule(handle: usize) -> bool {
    if handle >= TASKLET_CAPACITY { return false; }
    let mut g = TABLE.lock_irqsave::<TlIrq>();
    let ok = match g.slots[handle].as_mut() {
        Some(slot) => { slot.pending = true; true }
        None => { g.dropped += 1; false }
    };
    drop(g);
    // Raise OUTSIDE the table lock: `raise` is one atomic OR, but holding two
    // ISR-reachable locks at once is how a deadlock gets built.
    #[cfg(target_os = "oxide-kernel")]
    if ok { softirq::raise(softirq::Slot::Tasklet); }
    ok
}

/// Softirq handler: drain every pending tasklet.
#[cfg(target_os = "oxide-kernel")]
fn drain_softirq() {
    // SAFETY: softirq context, which is exactly what a tasklet body is promised.
    unsafe { let _ = run_pending(); }
}

/// Install the tasklet drain. Boot, once.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn init_softirq() { softirq::set_handler(softirq::Slot::Tasklet, drain_softirq); }

/// Run every pending tasklet (Linux `tasklet_action`). Called from softirq
/// context.
///
/// The body runs with the table lock RELEASED, so a tasklet may schedule
/// others, and with the slot's RUNNING claim held, so the same tasklet cannot
/// begin on a second CPU.
/// # SAFETY: softirq or process context — a tasklet body may not sleep, but it
/// may take locks that softirq context is allowed to take.
/// # C: O(TASKLET_CAPACITY + work)
pub unsafe fn run_pending() -> usize {
    let mut ran = 0;
    for idx in 0..TASKLET_CAPACITY {
        let taken = {
            let mut g = TABLE.lock_irqsave::<TlIrq>();
            match g.slots[idx].as_mut() {
                Some(slot) if slot.pending => { slot.pending = false; Some((slot.func, slot.arg)) }
                _ => None,
            }
        };
        let Some((func, arg)) = taken else { continue };
        // Claim the slot. Losing means another CPU is already inside this
        // tasklet; Linux re-queues in that case rather than running it twice.
        if RUNNING[idx].swap(true, Ordering::AcqRel) {
            let mut g = TABLE.lock_irqsave::<TlIrq>();
            if let Some(slot) = g.slots[idx].as_mut() { slot.pending = true; }
            continue;
        }
        func(arg);
        RUNNING[idx].store(false, Ordering::Release);
        ran += 1;
    }
    ran
}

/// Schedules refused because the handle was not registered.
/// # C: O(1)
pub fn dropped() -> u64 { TABLE.lock_irqsave::<TlIrq>().dropped }

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicUsize;

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static SUM: AtomicUsize = AtomicUsize::new(0);

    fn body(arg: usize) {
        HITS.fetch_add(1, Ordering::AcqRel);
        SUM.fetch_add(arg, Ordering::AcqRel);
    }

    fn reset() {
        let mut g = TABLE.lock_irqsave::<TlIrq>();
        for s in g.slots.iter_mut() { *s = None; }
        g.dropped = 0;
        drop(g);
        for r in RUNNING.iter() { r.store(false, Ordering::Release); }
        HITS.store(0, Ordering::Release);
        SUM.store(0, Ordering::Release);
    }

    #[test]
    fn a_scheduled_tasklet_runs_once_per_schedule() {
        reset();
        let h = init(body, 5).unwrap();
        assert!(schedule(h));
        // SAFETY: host test, single-threaded softirq-equivalent context.
        assert_eq!(unsafe { run_pending() }, 1);
        assert_eq!(HITS.load(Ordering::Acquire), 1);
        assert_eq!(SUM.load(Ordering::Acquire), 5);
        // Not re-scheduled, so a second drain does nothing.
        // SAFETY: as above.
        assert_eq!(unsafe { run_pending() }, 0);
        assert_eq!(HITS.load(Ordering::Acquire), 1);
    }

    #[test]
    fn scheduling_an_already_pending_tasklet_coalesces() {
        reset();
        let h = init(body, 1).unwrap();
        assert!(schedule(h));
        assert!(schedule(h));
        assert!(schedule(h));
        // SAFETY: host test.
        assert_eq!(unsafe { run_pending() }, 1, "three schedules, one run");
        assert_eq!(HITS.load(Ordering::Acquire), 1);
    }

    #[test]
    fn a_running_tasklet_cannot_be_killed() {
        reset();
        let h = init(body, 0).unwrap();
        RUNNING[h].store(true, Ordering::Release);
        assert!(!kill(h), "freeing a tasklet mid-body is the bug this prevents");
        RUNNING[h].store(false, Ordering::Release);
        assert!(kill(h));
    }

    #[test]
    fn scheduling_an_unregistered_handle_is_refused_and_counted() {
        reset();
        let h = init(body, 0).unwrap();
        assert!(kill(h));
        assert!(!schedule(h), "a killed tasklet must not run again");
        assert_eq!(dropped(), 1);
        assert!(!schedule(TASKLET_CAPACITY), "out-of-range handle");
    }

    #[test]
    fn a_tasklet_body_may_schedule_another() {
        // The table lock is released across the body, so this must not
        // self-deadlock — the same property the workqueue drain needs.
        reset();
        static OTHER: AtomicUsize = AtomicUsize::new(usize::MAX);
        fn first(_a: usize) {
            let o = OTHER.load(Ordering::Acquire);
            if o != usize::MAX { schedule(o); }
        }
        let second = init(body, 9).unwrap();
        OTHER.store(second, Ordering::Release);
        let first_h = init(first, 0).unwrap();
        assert!(schedule(first_h));
        // SAFETY: host test.
        let ran = unsafe { run_pending() };
        assert!(ran >= 1);
        // SAFETY: host test; drain whatever the first body queued.
        unsafe { run_pending(); }
        assert_eq!(SUM.load(Ordering::Acquire), 9, "the queued tasklet ran");
        OTHER.store(usize::MAX, Ordering::Release);
    }
}
