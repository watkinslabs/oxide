use super::*;
use alloc::vec;

const SOURCE: u32 = 55;
const TARGET: u32 = 56;
// Deferred-wake storage is process-global and CPU-indexed. Keep tests which
// inspect it on slots not used by the wake-placement suite or by each other.
const FINAL_PROOF_CPU: u32 = 46;
const DEFERRED_WAKE_CPU: u32 = 45;

fn rq(cpu: u32) -> Runqueue {
    Runqueue::new(cpu as u16,
        Arc::new(Task::new(0xD000 + cpu, "idle", SchedClass::Idle)))
}

fn task(tid: u32) -> Arc<Task> {
    let task = Arc::new(Task::new(tid, "evacuate", SchedClass::Normal { weight: 1024 }));
    task.cpus_allowed.store(cpu::CpuMask::all(), Ordering::Release);
    task
}

fn enqueue(rq: &Runqueue, task: &Arc<Task>) {
    let mut inner = rq.inner.lock();
    assert!(inner.enqueue(Arc::clone(task)));
    rq.publish_nr_running(inner.nr_running());
}

#[test]
fn persistent_evacuation_moves_multiple_queued_and_targets_current() {
    let source = rq(SOURCE);
    let target = rq(TARGET);
    let first = task(8101);
    let second = task(8102);
    let current = task(8103);
    enqueue(&source, &first);
    enqueue(&source, &second);
    current.cpu.store(SOURCE as u16, Ordering::Release);
    current.on_rq.store(true, Ordering::Release);
    current.on_cpu.store(true, Ordering::Release);
    // SAFETY: hosted fixture exclusively owns this runqueue/current slot.
    let _idle = unsafe { source.swap_current(Arc::clone(&current)) };
    let get = |cpu| if cpu == SOURCE { Some(&source) }
        else if cpu == TARGET { Some(&target) } else { None };
    let result = evacuate_with(&get, SOURCE, &|cpu| cpu == TARGET);
    assert_eq!(result, Evacuation { moved: 2, current_target: Some(TARGET) });
    assert_eq!(source.inner.lock().nr_running(), 0);
    assert_eq!(target.inner.lock().nr_running(), 2);
    assert!(current.need_resched.load(Ordering::Acquire));
}

#[test]
fn final_empty_proof_owns_the_runqueue_lock() {
    let rq = rq(FINAL_PROOF_CPU);
    let mut probed = false;
    assert!(final_empty_with(&rq, FINAL_PROOF_CPU, &mut || {
        probed = true;
        assert!(rq.inner.try_lock().is_none(), "final proof ran without rq ownership");
    }));
    assert!(probed);
}

#[test]
fn positive_control_lockless_empty_sample_can_miss_a_late_enqueue() {
    let rq = rq(SOURCE);
    let task = task(8104);
    let stale_empty = rq.curr_is_idle() && rq.nr_running.load(Ordering::Acquire) == 0;
    enqueue(&rq, &task);
    assert!(stale_empty, "positive control needs the old lockless sample");
    assert!(!final_empty_with(&rq, SOURCE, &mut || {}),
        "rq-locked proof must observe the committed runnable task");
}

#[test]
fn final_empty_rejects_a_late_pre_grace_deferred_wake() {
    let rq = rq(DEFERRED_WAKE_CPU);
    let task = task(8105);
    task.cpu.store(DEFERRED_WAKE_CPU as u16, Ordering::Release);
    assert!(crate::live::ttwu::wake_list_push_selected_for_test(
        DEFERRED_WAKE_CPU, Arc::clone(&task)));
    assert!(!final_empty_with(&rq, DEFERRED_WAKE_CPU, &mut || {}),
        "a published deferred wake must prevent play-dead");
    assert_eq!(crate::live::ttwu::wake_list_drain(DEFERRED_WAKE_CPU).len(), 1);
    assert!(final_empty_with(&rq, DEFERRED_WAKE_CPU, &mut || {}));
}

#[test]
fn only_immutable_singleton_kernel_threads_are_hotplug_bound() {
    let bound = task(8106);
    bound.cpus_allowed.store(cpu::CpuMask::of(SOURCE as usize), Ordering::Release);
    bound.no_setaffinity.store(true, Ordering::Release);
    assert!(is_per_cpu_kthread(&bound, SOURCE));
    assert!(!is_per_cpu_kthread(&bound, TARGET));

    let unbound = task(8107);
    unbound.no_setaffinity.store(true, Ordering::Release);
    assert!(!is_per_cpu_kthread(&unbound, SOURCE));

    let user = task(8108);
    user.cpus_allowed.store(cpu::CpuMask::of(SOURCE as usize), Ordering::Release);
    user.no_setaffinity.store(true, Ordering::Release);
    user.kernel_thread.store(false, Ordering::Release);
    assert!(!is_per_cpu_kthread(&user, SOURCE));
}

fn bound_kthread(tid: u32) -> Arc<Task> {
    let task = task(tid);
    task.cpus_allowed.store(cpu::CpuMask::of(SOURCE as usize), Ordering::Release);
    task.no_setaffinity.store(true, Ordering::Release);
    task
}

#[test]
fn positive_control_one_snapshot_misses_a_worker_created_while_manager_parks() {
    let manager = bound_kthread(8109);
    let late_worker = bound_kthread(8110);
    let published = core::cell::Cell::new(false);
    let first = vec![Arc::clone(&manager)];
    for task in first {
        if is_per_cpu_kthread(&task, SOURCE) {
            task.kthread_parked.store(true, Ordering::Release);
            published.set(true);
        }
    }
    assert!(published.get());
    assert!(!super::super::kthread::is_parked(&late_worker),
        "one registry snapshot cannot see a worker its manager publishes during that pass");
}

#[test]
fn fixed_point_park_catches_a_worker_created_during_the_first_pass() {
    let manager = bound_kthread(8111);
    let late_worker = bound_kthread(8112);
    let published = core::cell::Cell::new(false);
    park_per_cpu_kthreads_with(SOURCE,
        || if published.get() {
            vec![Arc::clone(&manager), Arc::clone(&late_worker)]
        } else {
            vec![Arc::clone(&manager)]
        },
        |task| {
            task.kthread_parked.store(true, Ordering::Release);
            if task.tid == manager.tid { published.set(true); }
        });
    assert!(super::super::kthread::is_parked(&manager));
    assert!(super::super::kthread::is_parked(&late_worker),
        "the stable rescan must park a worker published by the first-pass manager");
}

#[test]
fn fixed_point_park_treats_an_exited_bound_thread_as_quiescent() {
    let exited = bound_kthread(8113);
    exited.kthread_exited.store(true, Ordering::Release);
    park_per_cpu_kthreads_with(SOURCE, || vec![Arc::clone(&exited)],
        |_| panic!("an exited kthread cannot acknowledge a new park request"));
}

#[test]
fn process_coordinator_closes_callfn_only_after_quiescence() {
    let passes = core::cell::Cell::new(0u32);
    let closed_after = core::cell::Cell::new(0u32);
    assert!(prepare_stop_with(4,
        &mut || passes.set(passes.get() + 1),
        &mut || passes.get() == 3,
        &mut || { closed_after.set(passes.get()); true }));
    assert_eq!(closed_after.get(), 3,
        "sleeping callfn grace must follow persistent process-context evacuation");
}
