use super::*;

const SRC: u32 = 50;
const DST: u32 = 51;
const FALLBACK: u32 = 52;

fn rq(cpu: u32) -> Runqueue {
    Runqueue::new(cpu as u16,
        Arc::new(Task::new(0xE000 + cpu, "idle", SchedClass::Idle)))
}

fn task(tid: u32, mask: cpu::CpuMask) -> Arc<Task> {
    let task = Arc::new(Task::new(tid, "move", SchedClass::Normal { weight: 1024 }));
    task.cpus_allowed.store(mask, Ordering::Release);
    task
}

fn mask(cpus: &[u32]) -> cpu::CpuMask {
    let mut mask = cpu::CpuMask::empty();
    for cpu in cpus { let _ = mask.insert(*cpu as usize); }
    mask
}

fn enqueue(rq: &Runqueue, task: &Arc<Task>) {
    let mut inner = rq.inner.lock();
    assert!(inner.enqueue(Arc::clone(task)));
    rq.publish_nr_running(inner.nr_running());
}

#[test]
fn cpu_and_migrating_publish_before_source_unlock() {
    let src = rq(SRC);
    let dst = rq(DST);
    let task = task(8001, mask(&[SRC, DST]));
    enqueue(&src, &task);
    let get = |cpu| if cpu == SRC { Some(&src) } else if cpu == DST { Some(&dst) } else { None };
    let mut saw = false;
    let result = move_queued_with(&get, &task, Some(DST), &|_| true,
        &mut |point, _, moving| if point == MovePoint::SourceDetached {
            saw = true;
            assert!(src.inner.try_lock().is_none());
            assert!(moving.on_rq.is_migrating(Ordering::Acquire));
            assert_eq!(moving.cpu.load(Ordering::Acquire), DST as u16);
        });
    assert!(matches!(result, MoveResult::Moved { from: SRC, to: DST }));
    assert!(saw);
}

#[test]
fn source_and_destination_deactivation_select_a_third_active_cpu() {
    let src = rq(SRC);
    let dst = rq(DST);
    let fallback = rq(FALLBACK);
    let task = task(8002, mask(&[SRC, DST, FALLBACK]));
    enqueue(&src, &task);
    let get = |cpu| match cpu { SRC => Some(&src), DST => Some(&dst),
        FALLBACK => Some(&fallback), _ => None };
    let open = core::cell::Cell::new(true);
    let result = move_queued_with(&get, &task, Some(DST),
        &|cpu| cpu != SRC && cpu != DST || (cpu == DST && open.get()),
        &mut |point, cpu, _| if point == MovePoint::DestinationLocked && cpu == DST {
            open.set(false);
        });
    assert!(matches!(result, MoveResult::Moved { from: SRC, to: FALLBACK }));
    assert_eq!(src.nr_running.load(Ordering::Acquire), 0);
    assert_eq!(dst.nr_running.load(Ordering::Acquire), 0);
    assert_eq!(fallback.nr_running.load(Ordering::Acquire), 1);
}

#[test]
fn fallback_forces_effective_affinity_before_placement() {
    let src = rq(SRC);
    let fallback = rq(FALLBACK);
    let task = task(8003, cpu::CpuMask::of(SRC as usize));
    enqueue(&src, &task);
    let get = |cpu| if cpu == SRC { Some(&src) } else if cpu == FALLBACK { Some(&fallback) } else { None };
    let result = move_queued_with(&get, &task, None, &|cpu| cpu == FALLBACK,
                                  &mut |_, _, _| {});
    assert!(matches!(result, MoveResult::Moved { from: SRC, to: FALLBACK }));
    assert_eq!(task.cpu.load(Ordering::Acquire), FALLBACK as u16);
    assert!(task.cpus_allowed.load(Ordering::Acquire).contains(FALLBACK as usize));
    assert_eq!(task.user_cpus_allowed.load(Ordering::Acquire), cpu::CpuMask::empty(),
        "fallback must not erase the parked user request");
    assert!(task.on_rq.is_queued(Ordering::Acquire));
}

#[test]
fn fallback_relaxes_to_a_live_cpuset_member_before_possible_mask() {
    let src = rq(SRC);
    let fallback = rq(FALLBACK);
    let task = task(8007, cpu::CpuMask::of(SRC as usize));
    task.cpuset_cpus_allowed.store(mask(&[SRC, FALLBACK]), Ordering::Release);
    task.user_cpus_allowed.store(cpu::CpuMask::of(SRC as usize), Ordering::Release);
    enqueue(&src, &task);
    let get = |cpu| if cpu == SRC { Some(&src) } else if cpu == FALLBACK { Some(&fallback) } else { None };
    let result = move_queued_with(&get, &task, None, &|cpu| cpu == FALLBACK,
                                  &mut |_, _, _| {});
    assert!(matches!(result, MoveResult::Moved { from: SRC, to: FALLBACK }));
    assert_eq!(task.cpus_allowed.load(Ordering::Acquire),
        cpu::CpuMask::of(FALLBACK as usize));
    assert_eq!(task.user_cpus_allowed.load(Ordering::Acquire),
        cpu::CpuMask::of(SRC as usize), "fallback erased configured affinity");
}

#[test]
fn positive_control_stale_destination_check_commits_to_closed_cpu() {
    let src = rq(SRC);
    let dst = rq(DST);
    let task = task(8004, mask(&[SRC, DST]));
    enqueue(&src, &task);
    let get = |cpu| if cpu == SRC { Some(&src) } else if cpu == DST { Some(&dst) } else { None };
    let closed = core::cell::Cell::new(false);
    let result = move_queued_with(&get, &task, Some(DST), &|_| true,
        &mut |point, cpu, _| if point == MovePoint::DestinationLocked && cpu == DST {
            closed.set(true);
        });
    assert!(matches!(result, MoveResult::Moved { to: DST, .. }));
    assert!(closed.get());
    assert_eq!(dst.nr_running.load(Ordering::Acquire), 1,
        "positive control: stale acceptance permits a closed destination commit");
}


#[test]
fn frozen_migration_rejection_is_a_loud_invariant_not_false_success() {
    let dst = rq(DST);
    let task = task(8005, mask(&[SRC, DST]));
    task.on_rq.begin_migration();
    task.frozen.store(true, Ordering::Release);
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        dst.inner.lock().enqueue_migrated(Arc::clone(&task));
    }));
    assert!(failed.is_err(), "positive control: frozen migration must fail loudly");
    assert_eq!(dst.nr_running.load(Ordering::Acquire), 0);
}

#[test]
fn same_tid_different_task_is_fatal_corruption_not_restored() {
    let src = rq(SRC);
    let dst = rq(DST);
    let queued = task(8006, mask(&[SRC, DST]));
    let impostor = task(8006, mask(&[SRC, DST]));
    enqueue(&src, &queued);
    impostor.cpu.store(SRC as u16, Ordering::Release);
    impostor.on_rq.store(true, Ordering::Release);
    impostor.on_class_rq.store(true, Ordering::Release);
    let get = |cpu| if cpu == SRC { Some(&src) } else if cpu == DST { Some(&dst) } else { None };
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = move_queued_with(&get, &impostor, Some(DST), &|_| true,
                                 &mut |_, _, _| {});
    }));
    assert!(failed.is_err(),
        "positive control: same tid must not authorize mutation of another Arc");
}
