use super::*;
use std::sync::{Arc, Barrier};
use std::vec::Vec;

/// Hosted workers must not borrow an interrupt context from another OS thread.
#[test]
fn hosted_threads_do_not_alias_preempt_context_after_cpu_capacity() {
    const WORKERS: usize = cpu::MAX_CPUS * 2;
    let entered = Arc::new(Barrier::new(WORKERS + 1));
    let release = Arc::new(Barrier::new(WORKERS + 1));
    let mut workers = Vec::with_capacity(WORKERS);
    for _ in 0..WORKERS {
        let entered = entered.clone();
        let release = release.clone();
        workers.push(std::thread::spawn(move || {
            preempt_count_add(SOFTIRQ_OFFSET);
            entered.wait();
            release.wait();
            preempt_count_sub(SOFTIRQ_OFFSET);
        }));
    }
    entered.wait();
    let observer = std::thread::spawn(in_interrupt).join().unwrap();
    assert!(!observer, "a fresh hosted worker must start in process context");
    release.wait();
    for worker in workers { worker.join().unwrap(); }
}

/// `preemptible()` gates every reschedule this file can take. Both terms are
/// load-bearing: a zero count with interrupts MASKED is not a schedule point.
///
/// Switching there strands the outgoing task off-CPU while it still owns the
/// IRQ-off spinlocks it took, because a spinlock is released by its guard on
/// the owning stack and that stack is no longer running. A second CPU hides it
/// by running the owner; a uniprocessor cannot, and the next acquirer spins
/// forever with interrupts masked — no tick, no wakeup, no progress.
#[test]
fn preemptible_requires_zero_count_and_unmasked_interrupts() {
    assert!(preemptible(0, false), "count 0, IRQs on = the one schedule point");
    assert!(!preemptible(0, true), "IRQs masked is never preemptible");
    assert!(!preemptible(1, false), "a held preempt count is never preemptible");
    assert!(!preemptible(1, true));
    assert!(!preemptible(u32::MAX, false));
}

/// The reschedule REQUEST must outlive a refused check. `preempt_enable` and
/// `preempt_check_resched` consume `need_resched` with `take_need_resched`, so
/// evaluating that before the gate would swallow the request at an
/// unpreemptible point and lose the wakeup entirely. Short-circuit order is
/// the contract; this pins it.
#[test]
fn a_refused_preempt_check_leaves_need_resched_pending() {
    set_need_resched();
    // The gate says no; the flag must still be there for the next legal point.
    assert!(!preemptible(0, true));
    assert!(need_resched(), "a masked-interrupt check must not consume the request");
    assert!(take_need_resched(), "the next legal point still sees it");
    assert!(!need_resched());
}
