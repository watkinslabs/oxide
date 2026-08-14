use super::*;

/// A peer may claim a current task after it published Sleeping but before its
/// `schedule()` removes it. The owner consumes the stale list entry without
/// waiting for its own switch-off.
#[test]
fn target_drain_completes_a_current_task_wake_without_waiting_on_itself() {
    const CPU: u32 = 62;
    let cpus = Cpus::new(&[CPU]);
    let rq = cpus.get(CPU).expect("test cpu installed");
    let t = parked_but_still_running(2011, CPU);
    assert!(t.claim_wake());
    wake_list_push(CPU, Arc::clone(&t));

    assert!(!sched_ttwu_pending(CPU, Arc::as_ptr(&t) as *mut Task, rq));
    assert_eq!(t.state(), TaskState::Runnable);
    assert!(!t.on_rq.load(Ordering::Acquire));
    assert!(!t.on_wake_list.load(Ordering::Acquire));
}
