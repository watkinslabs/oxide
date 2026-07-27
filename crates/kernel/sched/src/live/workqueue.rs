// Workqueue + per-CPU `kworker` — Linux `kernel/workqueue.c` (`skizm.md` §2,
// Step 4a).
//
// The one place in this kernel where work that MUST SLEEP can be handed off
// from a context that must not. A softirq or a hard-IRQ handler cannot block,
// cannot take a sleeping mutex, and cannot do I/O; it queues the work here and
// a `kworker` kthread runs it in process context, where all three are legal.
//
// This is what separates a workqueue from a softirq, and it is the whole
// reason to have both: `softirq::raise` defers work that must still be quick
// and non-blocking; `queue_work` defers work that is allowed to sleep.
//
// Deliberate subset (`skizm.md` §7, labelled as required): no concurrency
// management (Linux's `worker_pool` growing threads when one blocks), no
// rescuer threads, no NUMA pools, no `WQ_UNBOUND`. One pinned worker per CPU
// running items in FIFO order.
//
// **The queue is a bounded per-CPU ring, not an allocating list.** `queue_work`
// is callable from hard-IRQ context, which is its entire point, so it must not
// allocate and must not spin on a lock a process-context holder owns — hence a
// fixed ring behind an irqsave lock. A full ring returns `false` rather than
// dropping silently or growing in an ISR; Linux's `queue_work` likewise returns
// a bool, and the caller decides. `WORK_CAPACITY` is per CPU.

extern crate alloc;

use core::sync::atomic::{AtomicU64, Ordering};

use cpu::MAX_CPUS;
use sync::{Spinlock, Workqueue as WorkClass};

use super::WaitList;

/// A queued item. A bare `fn(usize)` rather than a boxed closure: `07§5`
/// forbids `dyn` on these paths, and an embedded arg matches Linux's
/// `container_of(work, ...)` idiom without an allocation.
pub type WorkFn = fn(usize);

#[derive(Copy, Clone)]
struct Work {
    func: WorkFn,
    arg: usize,
}

/// Per-CPU ring depth. Deep enough that a burst of deferrals from one ISR
/// storm fits; small enough to stay a fixed cost per CPU.
pub const WORK_CAPACITY: usize = 64;

struct Ring {
    items: [Option<Work>; WORK_CAPACITY],
    head: usize,
    tail: usize,
    len: usize,
    /// Items refused because the ring was full — surfaced by `dropped_on` so a
    /// saturating queue is visible instead of silent.
    dropped: u64,
}

impl Ring {
    const fn new() -> Self {
        Self { items: [None; WORK_CAPACITY], head: 0, tail: 0, len: 0, dropped: 0 }
    }

    fn push(&mut self, w: Work) -> bool {
        if self.len == WORK_CAPACITY {
            self.dropped += 1;
            return false;
        }
        self.items[self.tail] = Some(w);
        self.tail = (self.tail + 1) % WORK_CAPACITY;
        self.len += 1;
        true
    }

    fn pop(&mut self) -> Option<Work> {
        if self.len == 0 {
            return None;
        }
        let w = self.items[self.head].take();
        self.head = (self.head + 1) % WORK_CAPACITY;
        self.len -= 1;
        w
    }
}

const EMPTY: Spinlock<Ring, WorkClass> = Spinlock::new(Ring::new());
static QUEUE: [Spinlock<Ring, WorkClass>; MAX_CPUS] = [EMPTY; MAX_CPUS];
static WAIT: [WaitList; MAX_CPUS] = [const { WaitList::new() }; MAX_CPUS];
/// Items completed per CPU — lets `flush_on` observe forward progress and
/// gives the tests something to assert without a global barrier.
static DONE: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Arch IRQ gate for the ring. `queue_work` runs in hard-IRQ context, so the
/// process-context side must mask interrupts or the ISR spins on it forever
/// (`06§3.1`) — the same rule every other ISR-shared lock in this tree follows.
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
type WqIrq = hal_x86_64::X86IrqGate;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
type WqIrq = hal_aarch64::ArmIrqGate;
#[cfg(not(target_os = "oxide-kernel"))]
type WqIrq = sync::NoopIrq;

#[inline]
fn this_cpu() -> usize {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_x86_64::X86CpuOps::current_cpu() as usize).min(MAX_CPUS - 1) }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_aarch64::ArmCpuOps::current_cpu() as usize).min(MAX_CPUS - 1) }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// Queue `func(arg)` to run in process context on `cpu` (Linux
/// `queue_work_on`). Returns false if that CPU's ring is full or the index is
/// out of range — the caller decides, nothing is dropped silently.
///
/// Safe from ANY context, including a hard-IRQ handler: no allocation, and the
/// ring lock is irqsave.
/// # C: O(1)
/// # Ctx: any, including hard IRQ
pub fn queue_work_on(cpu: usize, func: WorkFn, arg: usize) -> bool {
    if cpu >= MAX_CPUS {
        return false;
    }
    let queued = QUEUE[cpu].lock_irqsave::<WqIrq>().push(Work { func, arg });
    if queued {
        // Wake outside the ring lock: the worker's first act is to take it.
        WAIT[cpu].wake_one();
    }
    queued
}

/// Queue on the calling CPU (Linux `queue_work` on the bound workqueue).
/// # C: O(1)
/// # Ctx: any, including hard IRQ
pub fn queue_work(func: WorkFn, arg: usize) -> bool {
    queue_work_on(this_cpu(), func, arg)
}

/// Items this CPU's worker has completed. Monotonic.
/// # C: O(1)
pub fn completed_on(cpu: usize) -> u64 {
    if cpu >= MAX_CPUS { return 0; }
    DONE[cpu].load(Ordering::Acquire)
}

/// Items refused because the ring was full. Non-zero means the queue is
/// saturating and the capacity or the producer needs looking at.
/// # C: O(1)
pub fn dropped_on(cpu: usize) -> u64 {
    if cpu >= MAX_CPUS { return 0; }
    QUEUE[cpu].lock_irqsave::<WqIrq>().dropped
}

/// Pending items on `cpu`.
/// # C: O(1)
pub fn pending_on(cpu: usize) -> usize {
    if cpu >= MAX_CPUS { return 0; }
    QUEUE[cpu].lock_irqsave::<WqIrq>().len
}

/// Run every item currently queued on `cpu`, in FIFO order. Each item is
/// popped BEFORE it runs and the lock is released across the call, so a work
/// function may sleep, may take a mutex, and may queue more work.
/// # SAFETY: process context only — the items are permitted to sleep.
/// # C: O(queued work)
unsafe fn drain(cpu: usize) {
    loop {
        // The pop MUST be its own statement. In `while let Some(w) =
        // lock().pop()`, the temporary guard lives for the whole loop body, so
        // the ring lock would be held across the work call — and a work item
        // that queues more work then deadlocks against itself. Binding the
        // popped value first ends the guard's temporary scope here.
        let next = QUEUE[cpu].lock_irqsave::<WqIrq>().pop();
        let Some(w) = next else { return };
        (w.func)(w.arg);
        DONE[cpu].fetch_add(1, Ordering::AcqRel);
    }
}

/// Missed-wakeup backstop, same idiom as `ksoftirqd`/`ktimers`: a `queue_work`
/// landing between the emptiness check and the park would otherwise wait for
/// the next producer.
const BACKSTOP_NS: u64 = 100_000_000;

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn now_ns() -> u64 { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 }
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn now_ns() -> u64 { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 }
#[cfg(not(target_os = "oxide-kernel"))]
fn now_ns() -> u64 { 0 }

/// Linux `worker_thread`: run queued items, yielding between batches so a
/// flood stays preemptible, then park until `queue_work` wakes us.
/// # C: O(queued work) per wake
#[cfg(target_os = "oxide-kernel")]
extern "C" fn kworker(arg: usize) -> ! {
    let my_cpu = if arg < MAX_CPUS { arg } else { 0 };
    loop {
        if pending_on(my_cpu) != 0 {
            // SAFETY: process-context kthread, IRQs enabled, no lock held —
            // exactly the context work items are promised.
            unsafe { drain(my_cpu); }
            // cond_resched(): draining a burst must stay preemptible.
            // SAFETY: running kthread, no lock held; schedule re-enqueues this
            // still-Runnable task.
            unsafe { super::schedule(); }
            continue;
        }
        // SAFETY: running kthread on this CPU, no lock held across the park;
        // schedule() yields immediately per the WaitList contract.
        unsafe {
            WAIT[my_cpu].park_with_deadline(now_ns() + BACKSTOP_NS);
            super::schedule();
        }
    }
}

/// Spawn one pinned `kworker` per online CPU. Boot, once, after AP bring-up
/// and per-CPU runqueue install — same site as `spawn_ksoftirqd`. A CPU with no
/// installed runqueue is skipped; work queued to it simply waits.
/// # C: O(N_cpus)
#[cfg(target_os = "oxide-kernel")]
pub fn spawn_kworkers() -> Result<(), super::SpawnError> {
    let online = (cpu::smp::online_count() as usize).min(MAX_CPUS);
    for n in 0..online {
        // SAFETY: global_for is sound for any index; None unless CPU n is online + scheduling.
        if unsafe { super::runqueue::global_for(n as u32) }.is_none() { continue; }
        let tid = super::next_tid();
        // SAFETY: boot path after install_default_runqueue + AP bring-up; entry
        // is a 'static extern "C" fn ptr; arg = the CPU to pin to.
        let arc = unsafe { super::spawn_kernel_thread(tid, "kworker", kworker, n) }?;
        if n < 64 {
            arc.cpus_allowed.store(1u64 << n, Ordering::Release);
            // Linux `kthread_bind` -> PF_NO_SETAFFINITY (see ksoftirqd).
            arc.no_setaffinity.store(true, Ordering::Release);
        }
        drop(arc);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicUsize;

    // Cargo runs tests in parallel threads, and the rings + counters here are
    // `static`. Each test therefore owns BOTH a distinct CPU slot and its own
    // counters — sharing either makes results depend on scheduling order, which
    // showed up immediately as two intermittent failures.
    static HITS_FIFO: AtomicUsize = AtomicUsize::new(0);
    static SUM_FIFO: AtomicUsize = AtomicUsize::new(0);
    static HITS_WRAP: AtomicUsize = AtomicUsize::new(0);
    static HITS_REQUEUE: AtomicUsize = AtomicUsize::new(0);

    fn fifo(arg: usize) {
        HITS_FIFO.fetch_add(1, Ordering::AcqRel);
        SUM_FIFO.fetch_add(arg, Ordering::AcqRel);
    }
    fn wrap(_arg: usize) { HITS_WRAP.fetch_add(1, Ordering::AcqRel); }
    fn noop(_arg: usize) {}

    /// Empty a slot's ring so a test starts from a known state.
    fn reset(cpu: usize) {
        let mut g = QUEUE[cpu].lock_irqsave::<WqIrq>();
        while g.pop().is_some() {}
        g.dropped = 0;
        drop(g);
        DONE[cpu].store(0, Ordering::Release);
    }

    #[test]
    fn queued_work_runs_in_fifo_order_and_counts() {
        const C: usize = 1;
        reset(C);
        assert!(queue_work_on(C, fifo, 10));
        assert!(queue_work_on(C, fifo, 20));
        assert_eq!(pending_on(C), 2);
        // SAFETY: host test, single-threaded within this test's own CPU slot.
        unsafe { drain(C); }
        assert_eq!(HITS_FIFO.load(Ordering::Acquire), 2);
        assert_eq!(SUM_FIFO.load(Ordering::Acquire), 30);
        assert_eq!(pending_on(C), 0);
        assert_eq!(completed_on(C), 2);
    }

    #[test]
    fn a_full_ring_refuses_rather_than_dropping_silently() {
        const C: usize = 2;
        reset(C);
        for i in 0..WORK_CAPACITY {
            assert!(queue_work_on(C, noop, i), "ring must accept up to capacity");
        }
        assert!(!queue_work_on(C, noop, 999), "past capacity must return false");
        assert_eq!(dropped_on(C), 1, "a refusal must be counted, not hidden");
        assert_eq!(pending_on(C), WORK_CAPACITY);
        reset(C);
    }

    #[test]
    fn ring_wraps_without_losing_items() {
        const C: usize = 3;
        reset(C);
        // Fill, drain, refill: exercises head/tail wrap past the array end.
        for i in 0..WORK_CAPACITY { assert!(queue_work_on(C, wrap, i)); }
        // SAFETY: host test, single-threaded within this test's own CPU slot.
        unsafe { drain(C); }
        assert_eq!(completed_on(C), WORK_CAPACITY as u64);
        for i in 0..WORK_CAPACITY { assert!(queue_work_on(C, wrap, i), "slot {i} after wrap"); }
        assert_eq!(pending_on(C), WORK_CAPACITY);
        // SAFETY: host test, single-threaded within this test's own CPU slot.
        unsafe { drain(C); }
        assert_eq!(completed_on(C), 2 * WORK_CAPACITY as u64);
        assert_eq!(HITS_WRAP.load(Ordering::Acquire), 2 * WORK_CAPACITY);
    }

    /// The drain must pop BEFORE running and release the ring lock across the
    /// call. Written as `while let Some(w) = lock().pop()` the temporary guard
    /// lives for the whole loop body, and this test deadlocks — which is how
    /// that bug was found.
    #[test]
    fn work_may_queue_more_work() {
        const C: usize = 4;
        reset(C);
        fn requeue(arg: usize) {
            HITS_REQUEUE.fetch_add(1, Ordering::AcqRel);
            if arg > 0 { queue_work_on(4, requeue, arg - 1); }
        }
        assert!(queue_work_on(C, requeue, 3));
        // SAFETY: host test, single-threaded within this test's own CPU slot.
        unsafe { drain(C); }
        assert_eq!(HITS_REQUEUE.load(Ordering::Acquire), 4, "3 re-queues plus the original");
        assert_eq!(pending_on(C), 0);
    }

    #[test]
    fn out_of_range_cpu_is_refused() {
        assert!(!queue_work_on(MAX_CPUS, noop, 0));
        assert_eq!(pending_on(MAX_CPUS), 0);
        assert_eq!(completed_on(MAX_CPUS), 0);
        assert_eq!(dropped_on(MAX_CPUS), 0);
    }
}
