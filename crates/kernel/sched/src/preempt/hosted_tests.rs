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

/// THE uniprocessor wedge, as a check that can fail.
///
/// A `Spinlock` owner that reaches a voluntary reschedule point inside its
/// critical section gives up the CPU still holding the lock; with one CPU
/// nothing can run it again, and the next acquirer spins forever. `open_by_dev`
/// is the live shape — a plain table lock held across a nested bottom-half
/// section whose release runs `local_bh_enable`, which ends in
/// `preempt_check_resched`.
///
/// So: while a spinlock is held, `preemptible()` — the single gate every
/// reschedule in this file consults — must say no.
#[test]
fn a_reschedule_cannot_be_taken_while_a_spinlock_is_held() {
    crate::preempt::install_spinlock_gate();
    let base = preempt_count();
    assert!(preemptible(base, false), "test must start at a schedule point");

    let lk: sync::Spinlock<u32, sync::Buddy> = sync::Spinlock::new(0);
    let g = lk.lock();
    assert!(preempt_count() > base, "spin_lock must disable preemption");
    assert!(!preemptible(preempt_count(), false),
        "a reschedule here deschedules the lock OWNER and wedges every later acquirer");
    drop(g);

    assert_eq!(preempt_count(), base, "spin_unlock must restore the count exactly");
    assert!(preemptible(preempt_count(), false));
}

/// Same contract for the IRQ-saving and reader-writer forms: masking
/// interrupts covers the tick, but the count is what covers a VOLUNTARY
/// reschedule reached from inside the section.
#[test]
fn irqsave_and_rwlock_sections_are_equally_unpreemptible() {
    crate::preempt::install_spinlock_gate();
    let base = preempt_count();

    let lk: sync::Spinlock<u32, sync::Buddy> = sync::Spinlock::new(0);
    let g = lk.lock_irqsave::<sync::NoopIrq>();
    assert!(!preemptible(preempt_count(), false), "spin_lock_irqsave section");
    drop(g);
    assert_eq!(preempt_count(), base);

    let rw: sync::RwLock<u32, sync::AddressSpace> = sync::RwLock::new(0);
    let r = rw.read();
    assert!(!preemptible(preempt_count(), false), "read_lock section");
    drop(r);
    let w = rw.write();
    assert!(!preemptible(preempt_count(), false), "write_lock section");
    drop(w);
    assert_eq!(preempt_count(), base);
}

/// Nesting must count, not latch: the outer lock still holds when the inner
/// one releases, so the section is unpreemptible until the LAST release.
#[test]
fn nested_spinlock_sections_stay_unpreemptible_until_the_outermost_release() {
    crate::preempt::install_spinlock_gate();
    let base = preempt_count();
    let outer: sync::Spinlock<u32, sync::Buddy> = sync::Spinlock::new(0);
    let inner: sync::Spinlock<u32, sync::Slab> = sync::Spinlock::new(0);
    let a = outer.lock();
    let b = inner.lock();
    assert_eq!(preempt_count(), base + 2);
    drop(b);
    assert!(!preemptible(preempt_count(), false),
        "the outer lock is still held; this is not a schedule point");
    drop(a);
    assert_eq!(preempt_count(), base);
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

/// The context-switch count invariant (Linux: `preempt_count() ==
/// 2*PREEMPT_DISABLE_OFFSET` in `finish_task_switch`, and `FORK_PREEMPT_COUNT`
/// so a first-run task satisfies it too).
///
/// A switching task is inside `schedule()`'s own `preempt_disable` AND the
/// runqueue spinlock it forgot, so it carries exactly two levels; the incoming
/// task pays both back — one at the forgotten guard's `raw_unlock`, one at the
/// switcher's enable. A never-run task reaches the same tail having taken
/// neither, so it must ARRIVE with both or its first switch underflows the
/// count and pins that CPU unpreemptible for good.
#[test]
fn a_never_run_task_starts_owing_exactly_what_the_switch_tail_pays_back() {
    assert_eq!(crate::preempt::FORK_PREEMPT_COUNT, 2 * PREEMPT_DISABLED);
    let fresh = crate::Task::new(4242, "fresh", crate::SchedClass::Normal { weight: 1024 });
    assert_eq!(fresh.preempt_count.load(Ordering::Acquire), crate::preempt::FORK_PREEMPT_COUNT,
        "a first-run task must arrive owing the switch tail's two decrements");

    // The two the tail pays: the rq lock's release, then the switcher's enable.
    let paid = crate::preempt::FORK_PREEMPT_COUNT - 1 - 1;
    assert_eq!(paid, 0, "the tail must land the incoming task at a schedule point");
}
