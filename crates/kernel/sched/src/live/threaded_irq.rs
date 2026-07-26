// Threaded IRQ handlers — Linux `request_threaded_irq` (`skizm.md` §2, Step 8b).
//
// Splits a device interrupt into the two halves Linux splits it into:
//
//   hard handler   runs in the ISR. Must be short and must not sleep. Returns
//                  whether the threaded half should run (Linux's
//                  `IRQ_WAKE_THREAD` vs `IRQ_HANDLED`).
//   thread handler runs in PROCESS context on a `kworker`. MAY SLEEP, may take
//                  a mutex, may do I/O.
//
// This is what a driver needs when servicing an interrupt genuinely requires
// blocking — an I2C/SPI transfer, a firmware handshake — and it is why the
// workqueue had to exist first. Without it the only options were "do it in the
// ISR" (illegal if it sleeps) or "spin in the ISR waiting for the device"
// (the IRQs-off stall this whole campaign is about).
//
// The registry is a bounded array behind an irqsave lock: `dispatch` runs in
// the ISR, so it can neither allocate nor spin on a lock process context holds.

use sync::{Spinlock, Workqueue as IrqClass};

use super::workqueue::queue_work_on;

/// Hard-IRQ half. Returns true to run the threaded half.
pub type HardFn = fn(u32) -> bool;
/// Threaded half — runs on a kworker and MAY SLEEP.
pub type ThreadFn = fn(u32);

/// Concurrently-registered threaded IRQs.
pub const IRQ_CAPACITY: usize = 32;

#[derive(Copy, Clone)]
struct Registered {
    irq: u32,
    hard: Option<HardFn>,
    thread: ThreadFn,
    /// CPU whose kworker runs the threaded half.
    cpu: usize,
}

struct Table {
    slots: [Option<Registered>; IRQ_CAPACITY],
    /// Threaded halves that could not be queued (the target ring was full).
    lost: u64,
}

impl Table {
    const fn new() -> Self { Self { slots: [None; IRQ_CAPACITY], lost: 0 } }
}

static TABLE: Spinlock<Table, IrqClass> = Spinlock::new(Table::new());

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
type TiIrq = hal_x86_64::X86IrqGate;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
type TiIrq = hal_aarch64::ArmIrqGate;
#[cfg(not(target_os = "oxide-kernel"))]
type TiIrq = sync::NoopIrq;

/// Trampoline: the workqueue takes `fn(usize)`, so the irq number rides in the
/// arg and the threaded half is looked up again here. Looking it up rather than
/// capturing keeps the work item a bare fn pointer — `07§5` forbids `dyn` here.
fn run_thread_half(irq_arg: usize) {
    let irq = irq_arg as u32;
    let handler = {
        let g = TABLE.lock_irqsave::<TiIrq>();
        g.slots.iter().flatten().find(|r| r.irq == irq).map(|r| r.thread)
    };
    // Called with the table lock RELEASED: the threaded half is allowed to
    // sleep, and sleeping under a spinlock is the thing this exists to avoid.
    if let Some(f) = handler { f(irq); }
}

/// Register a threaded handler (Linux `request_threaded_irq`).
///
/// `hard` may be `None`, matching Linux's "no primary handler" form: the
/// threaded half then runs on every interrupt.
/// # C: O(IRQ_CAPACITY)
pub fn request(irq: u32, hard: Option<HardFn>, thread: ThreadFn, cpu: usize) -> bool {
    let mut g = TABLE.lock_irqsave::<TiIrq>();
    if g.slots.iter().flatten().any(|r| r.irq == irq) { return false; }
    let Some(idx) = g.slots.iter().position(|s| s.is_none()) else { return false };
    g.slots[idx] = Some(Registered { irq, hard, thread, cpu });
    true
}

/// Unregister (Linux `free_irq`).
/// # C: O(IRQ_CAPACITY)
pub fn free(irq: u32) -> bool {
    let mut g = TABLE.lock_irqsave::<TiIrq>();
    let Some(idx) = g.slots.iter().position(|s| s.is_some_and(|r| r.irq == irq)) else {
        return false;
    };
    g.slots[idx] = None;
    true
}

/// Threaded halves lost because the target kworker ring was full.
/// # C: O(1)
pub fn lost() -> u64 { TABLE.lock_irqsave::<TiIrq>().lost }

/// Dispatch `irq` from the ISR: run the hard half, and queue the threaded half
/// if it asked for one. Returns true if a threaded half was queued.
/// # SAFETY: hard-IRQ context. The hard half must not sleep.
/// # C: O(IRQ_CAPACITY) + hard half
/// # Ctx: hard IRQ
pub unsafe fn dispatch(irq: u32) -> bool {
    let found = {
        let g = TABLE.lock_irqsave::<TiIrq>();
        g.slots.iter().flatten().find(|r| r.irq == irq).copied()
    };
    let Some(r) = found else { return false };
    // The hard half runs with the table lock RELEASED — it is device code and
    // must not be run under a lock the threaded path also takes.
    let wake = match r.hard { Some(h) => h(irq), None => true };
    if !wake { return false; }
    if queue_work_on(r.cpu, run_thread_half, irq as usize) { return true; }
    // Ring full: count it rather than silently losing the interrupt's
    // deferred work, so saturation is visible.
    TABLE.lock_irqsave::<TiIrq>().lost += 1;
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};


    /// These modules own a single GLOBAL table, and cargo runs tests in
    /// parallel threads, so two tests sharing it produce order-dependent
    /// results — which showed up as an abort, not a clean assertion failure.
    /// Serialising is the honest fix; per-test slot partitioning is not
    /// possible when `add` picks the first free slot.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static HARD: AtomicUsize = AtomicUsize::new(0);
    static THREAD: AtomicUsize = AtomicUsize::new(0);

    fn hard_wake(_irq: u32) -> bool { HARD.fetch_add(1, Ordering::AcqRel); true }
    fn hard_handled(_irq: u32) -> bool { HARD.fetch_add(1, Ordering::AcqRel); false }
    fn threaded(_irq: u32) { THREAD.fetch_add(1, Ordering::AcqRel); }

    fn reset() -> std::sync::MutexGuard<'static, ()> {
        let serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut g = TABLE.lock_irqsave::<TiIrq>();
        for s in g.slots.iter_mut() { *s = None; }
        g.lost = 0;
        drop(g);
        HARD.store(0, Ordering::Release);
        THREAD.store(0, Ordering::Release);
        serial
    }

    #[test]
    fn a_hard_half_that_wakes_queues_the_threaded_half() {
        let _g = reset();
        assert!(request(41, Some(hard_wake), threaded, 5));
        // SAFETY: host test standing in for ISR context.
        assert!(unsafe { dispatch(41) });
        assert_eq!(HARD.load(Ordering::Acquire), 1);
        // Queued, not yet run — it runs on a kworker.
        assert_eq!(THREAD.load(Ordering::Acquire), 0);
        assert_eq!(super::super::workqueue::pending_on(5), 1);
    }

    #[test]
    fn a_hard_half_that_handles_it_queues_nothing() {
        let _g = reset();
        assert!(request(42, Some(hard_handled), threaded, 6));
        // SAFETY: host test.
        assert!(!unsafe { dispatch(42) }, "IRQ_HANDLED must not wake the thread");
        assert_eq!(HARD.load(Ordering::Acquire), 1);
        assert_eq!(super::super::workqueue::pending_on(6), 0);
    }

    #[test]
    fn no_hard_half_means_the_thread_always_runs() {
        let _g = reset();
        assert!(request(43, None, threaded, 7));
        // SAFETY: host test.
        assert!(unsafe { dispatch(43) });
        assert_eq!(super::super::workqueue::pending_on(7), 1);
    }

    #[test]
    fn dispatching_an_unregistered_irq_is_a_no_op() {
        let _g = reset();
        // SAFETY: host test.
        assert!(!unsafe { dispatch(999) });
        assert_eq!(HARD.load(Ordering::Acquire), 0);
    }

    #[test]
    fn request_rejects_a_duplicate_and_free_removes_it() {
        let _g = reset();
        assert!(request(44, Some(hard_wake), threaded, 0));
        assert!(!request(44, Some(hard_wake), threaded, 0), "one handler per irq");
        assert!(free(44));
        assert!(!free(44), "freeing twice must report failure");
        assert!(request(44, Some(hard_wake), threaded, 0), "the slot is reusable");
    }
}
