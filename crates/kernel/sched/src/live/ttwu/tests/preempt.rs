use super::*;
use alloc::sync::Arc;
use crate::SchedClass;

const START: u64 = 1_000_000;
const NOW: u64 = 5_000_000;
const CURRENT_VRUNTIME: u64 = 10_000_000;
const WAKE_VRUNTIME: u64 = 12_000_000;

fn fixture() -> (Runqueue, Arc<Task>, Arc<Task>) {
    let rq = Runqueue::new(0, Arc::new(Task::new(9001, "idle", SchedClass::Idle)));
    let current = Arc::new(Task::new(9002, "running", SchedClass::Normal { weight: 1024 }));
    current.sched.se.exec_start.store(START, Ordering::Release);
    current.sched.se.vruntime.store(CURRENT_VRUNTIME, Ordering::Release);
    // SAFETY: test exclusively owns this runqueue and its current-task reference.
    let _ = unsafe { rq.swap_current(Arc::clone(&current)) };
    let wakee = Arc::new(Task::new(9003, "io-waiter", SchedClass::Normal { weight: 1024 }));
    wakee.sched.se.vruntime.store(WAKE_VRUNTIME, Ordering::Release);
    (rq, current, wakee)
}

fn decide(rq: &Runqueue, inner: &mut RunqueueInner, wakee: &Arc<Task>, now: u64) -> bool {
    prepare_wake(rq, inner, wakee, now);
    assert!(inner.enqueue(Arc::clone(wakee)));
    let result = wake_preempts(rq, inner, wakee);
    let _ = inner.remove(wakee.tid);
    result
}

#[test]
fn elapsed_execution_changes_wake_preemption() {
    let (rq, current, wakee) = fixture();
    assert!(!wakeup_preempt(cand_of(&wakee), cand_of(&current)), "stale comparison control");
    let mut inner = rq.inner.lock();
    assert!(decide(&rq, &mut inner, &wakee, NOW), "wake ignored current's elapsed execution");
    assert_eq!(current.sched.se.sum_exec_runtime.load(Ordering::Acquire), NOW - START);
}

#[test]
fn same_instant_wakes_do_not_charge_execution_twice() {
    let (rq, current, wakee) = fixture();
    let mut inner = rq.inner.lock();
    assert!(decide(&rq, &mut inner, &wakee, NOW));
    let vruntime = current.sched.se.vruntime.load(Ordering::Acquire);
    assert!(decide(&rq, &mut inner, &wakee, NOW));
    assert_eq!(current.sched.se.vruntime.load(Ordering::Acquire), vruntime);
    assert_eq!(current.sched.se.sum_exec_runtime.load(Ordering::Acquire), NOW - START);
}

#[test]
fn insufficient_elapsed_execution_does_not_preempt() {
    let (rq, _, wakee) = fixture();
    assert!(!decide(&rq, &mut rq.inner.lock(), &wakee, START + 1));
}

#[test]
fn fair_wake_under_rq_lock_does_not_read_interrupted_deadline_publication() {
    let (rq, current, wakee) = fixture();
    let _pi = wakee.pi_lock.lock_irqsave::<crate::live::runqueue::RqIrq>();
    let mut inner = rq.inner.lock_irqsave::<crate::live::runqueue::RqIrq>();
    current.sched.dl.with_interrupted_publication(|| {
        assert!(decide(&rq, &mut inner, &wakee, NOW));
    });
}

#[test]
fn fair_wakee_does_not_read_its_inactive_deadline_state() {
    let (rq, _, wakee) = fixture();
    let _pi = wakee.pi_lock.lock_irqsave::<crate::live::runqueue::RqIrq>();
    let mut inner = rq.inner.lock_irqsave::<crate::live::runqueue::RqIrq>();
    wakee.sched.dl.with_interrupted_publication(|| {
        assert!(decide(&rq, &mut inner, &wakee, NOW));
    });
}
