// `can_migrate_task` — Linux's two unconditional migration refusals.
// The `on_cpu` one is memory safety, not policy: pulling a
// task that is still executing on its source CPU lets the destination pick and
// run it while the source is still saving its registers.

use super::*;
use alloc::sync::Arc;
use crate::task::SchedClass;

const SRC: u32 = 40;
const DST: u32 = 41;

fn m(bits: u64) -> cpu::CpuMask { cpu::CpuMask::from_words(&[bits]) }

fn cfs_task(tid: u32) -> Arc<Task> {
    Arc::new(Task::new(tid, "t", SchedClass::Normal { weight: 1024 }))
}

#[test]
fn an_idle_unpinned_task_is_migratable() {
    let t = cfs_task(3001);
    assert!(can_migrate_task(&t, DST));
}

/// Linux `nr_failed_migrations_running`: a task executing on the source CPU is
/// never pulled.
#[test]
fn a_running_task_is_never_migratable() {
    let t = cfs_task(3002);
    t.cpu.store(SRC as u16, Ordering::Release);
    t.on_cpu.store(true, Ordering::Release);
    assert!(!can_migrate_task(&t, DST),
        "a task still executing on its source CPU was offered for migration");
}

/// Clearing `on_cpu` (the `finish_task_switch` handoff) makes it migratable
/// again — the refusal is about the switch being in flight, not about the task.
#[test]
fn the_running_refusal_lifts_once_the_switch_completes() {
    let t = cfs_task(3003);
    t.on_cpu.store(true, Ordering::Release);
    assert!(!can_migrate_task(&t, DST));
    t.on_cpu.store(false, Ordering::Release);
    assert!(can_migrate_task(&t, DST));
}

/// Linux `nr_failed_migrations_affine`: the destination must be in the mask.
#[test]
fn a_task_pinned_away_from_the_destination_is_not_migratable() {
    let t = cfs_task(3004);
    t.cpus_allowed.store(cpu::CpuMask::of(SRC as usize), Ordering::Release);
    assert!(!can_migrate_task(&t, DST));
    assert!(can_migrate_task(&t, SRC));
}

/// `on_cpu` outranks affinity: a running task pinned TO the destination is
/// still refused.
#[test]
fn running_outranks_a_permissive_affinity_mask() {
    let t = cfs_task(3005);
    t.cpus_allowed.store(cpu::CpuMask::all(), Ordering::Release);
    t.on_cpu.store(true, Ordering::Release);
    assert!(!can_migrate_task(&t, DST));
}

/// A CPU id outside the kernel CPU-mask capacity is never admitted by an
/// affinity mask.
#[test]
fn affinity_refuses_cpu_ids_outside_the_mask() {
    let t = cfs_task(3006);
    t.cpus_allowed.store(m(0), Ordering::Release);
    assert!(!can_migrate_task(&t, 64));
}

fn rq(cpu: u32) -> Runqueue {
    Runqueue::new(cpu as u16, Arc::new(Task::new(0xF000 + cpu, "idle", SchedClass::Idle)))
}

fn queue(rq: &Runqueue, task: &Arc<Task>) {
    let mut inner = rq.inner.lock();
    assert!(inner.enqueue(Arc::clone(task)));
    rq.publish_nr_running(inner.nr_running());
}

fn queued_tids(rq: &Runqueue, tids: &[u32]) -> alloc::vec::Vec<u32> {
    let inner = rq.inner.lock();
    tids.iter().copied().filter(|tid| inner.cfs.find_tid(*tid).is_some()).collect()
}

#[test]
fn balance_skips_pinned_first_candidate_for_movable_second() {
    let src = rq(SRC);
    let dst = rq(DST);
    let pinned = cfs_task(3007);
    let movable = cfs_task(3008);
    pinned.cpus_allowed.store(m(1u64 << SRC), Ordering::Release);
    movable.cpus_allowed.store(m((1u64 << SRC) | (1u64 << DST)), Ordering::Release);
    queue(&src, &pinned);
    queue(&src, &movable);
    assert_eq!(src.inner.lock().cfs.peek_leftmost().map(|task| task.tid), Some(pinned.tid),
        "positive control: pinned task must be the first candidate");
    assert!(!can_migrate_task(&pinned, DST),
        "positive control: first candidate must fail destination affinity");

    let get = |cpu| if cpu == SRC { Some(&src) } else if cpu == DST { Some(&dst) } else { None };
    assert_eq!(migrate_one_cfs_with(&src, &dst, &get, true, |_, _| {}, |_| true), Some(DST));
    assert_eq!(queued_tids(&src, &[pinned.tid, movable.tid]), [pinned.tid]);
    assert_eq!(queued_tids(&dst, &[pinned.tid, movable.tid]), [movable.tid]);
    assert_eq!(src.inner.lock().cfs.peek_leftmost().map(|task| task.tid), Some(pinned.tid));
}

#[test]
fn balance_skips_hot_first_candidate_for_cold_second() {
    let src = rq(SRC);
    let dst = rq(DST);
    let hot = cfs_task(3009);
    let cold = cfs_task(3010);
    hot.cpus_allowed.store(m((1u64 << SRC) | (1u64 << DST)), Ordering::Release);
    cold.cpus_allowed.store(m((1u64 << SRC) | (1u64 << DST)), Ordering::Release);
    hot.sched.se.exec_start.store(1, Ordering::Release);
    queue(&src, &hot);
    queue(&src, &cold);
    assert_eq!(src.inner.lock().cfs.peek_leftmost().map(|task| task.tid), Some(hot.tid),
        "positive control: cache-hot task must be the first candidate");
    assert!(cache_hot(&hot, now_ns()), "positive control: first candidate must be cache-hot");
    assert!(!cache_hot(&cold, now_ns()), "positive control: second candidate must be cold");

    let get = |cpu| if cpu == SRC { Some(&src) } else if cpu == DST { Some(&dst) } else { None };
    assert_eq!(migrate_one_cfs_with(&src, &dst, &get, false, |_, _| {}, |_| true), Some(DST));
    assert_eq!(queued_tids(&src, &[hot.tid, cold.tid]), [hot.tid]);
    assert_eq!(queued_tids(&dst, &[hot.tid, cold.tid]), [cold.tid]);
    assert_eq!(src.inner.lock().cfs.peek_leftmost().map(|task| task.tid), Some(hot.tid));
}

#[test]
fn migration_bridge_publishes_cpu_before_source_unlock() {
    let src = rq(SRC);
    let dst = rq(DST);
    let task = cfs_task(3010);
    task.cpus_allowed.store(m((1u64 << SRC) | (1u64 << DST)), Ordering::Release);
    queue(&src, &task);
    assert!(src.inner.try_lock().is_some(), "positive control: source lock starts free");
    assert!(task.pi_lock.try_lock().is_some(), "positive control: TaskPi starts free");

    let mut points = alloc::vec::Vec::new();
    let get = |cpu| if cpu == SRC { Some(&src) } else if cpu == DST { Some(&dst) } else { None };
    assert_eq!(migrate_one_cfs_with(&src, &dst, &get, true, |point, moving| {
        points.push(point);
        if point == MigrationPoint::AfterDestinationEnqueue {
            assert!(moving.on_rq.is_queued(Ordering::Acquire));
        } else {
            assert!(moving.on_rq.is_migrating(Ordering::Acquire));
        }
        assert!(moving.pi_lock.try_lock().is_none(), "TaskPi spans the migration bridge");
        match point {
            MigrationPoint::BeforeDequeue => {
                assert!(src.inner.try_lock().is_none(), "source probe runs while source rq is locked");
                assert!(moving.on_class_rq.load(Ordering::Acquire), "MIGRATING precedes dequeue");
                assert_eq!(moving.cpu.load(Ordering::Acquire), SRC as u16);
            }
            MigrationPoint::BeforeSourceUnlock => {
                assert!(src.inner.try_lock().is_none(), "source probe runs while source rq is locked");
                assert!(!moving.on_class_rq.load(Ordering::Acquire), "dequeue completed");
                assert_eq!(moving.cpu.load(Ordering::Acquire), DST as u16,
                    "destination CPU must publish before source unlock");
            }
            MigrationPoint::BeforeDestinationCommit => {
                assert!(dst.inner.try_lock().is_none(), "commit probe runs while destination rq is locked");
                assert!(!moving.on_class_rq.load(Ordering::Acquire));
            }
            MigrationPoint::AfterDestinationEnqueue => {
                assert!(dst.inner.try_lock().is_none(), "enqueue probe runs while destination rq is locked");
                assert!(moving.on_class_rq.load(Ordering::Acquire));
            }
        }
    }, |_| true), Some(DST));
    assert_eq!(points, [MigrationPoint::BeforeDequeue, MigrationPoint::BeforeSourceUnlock,
        MigrationPoint::BeforeDestinationCommit, MigrationPoint::AfterDestinationEnqueue]);
    assert_eq!(src.nr_running.load(Ordering::Acquire), 0);
    assert_eq!(dst.nr_running.load(Ordering::Acquire), 1);
    assert!(task.on_rq.is_queued(Ordering::Acquire), "destination insertion clears MIGRATING");
    assert!(task.on_class_rq.load(Ordering::Acquire));
}

#[test]
fn affinity_update_after_active_migration_cannot_be_missed() {
    let src = rq(SRC);
    let dst = rq(DST);
    let task = cfs_task(3011);
    task.cpus_allowed.store(m((1u64 << SRC) | (1u64 << DST)), Ordering::Release);
    queue(&src, &task);
    let mut writer_entered = false;
    let get = |cpu| if cpu == SRC { Some(&src) } else if cpu == DST { Some(&dst) } else { None };
    assert_eq!(migrate_one_cfs_with(&src, &dst, &get, true, |point, moving| {
        if point == MigrationPoint::BeforeSourceUnlock {
            if let Some(_writer) = moving.pi_lock.try_lock() {
                writer_entered = true;
                moving.cpus_allowed.store(m(1u64 << SRC), Ordering::Release);
            }
        }
    }, |_| true), Some(DST));
    assert!(!writer_entered, "a mask writer entered between detach and attach");

    let get = |cpu| if cpu == SRC { Some(&src) } else if cpu == DST { Some(&dst) } else { None };
    task.cpus_allowed.store(m(1u64 << SRC), Ordering::Release);
    crate::live::ttwu::relocate_for_affinity_with(&get, &task, m(1u64 << SRC));
    assert_eq!(task.cpu.load(Ordering::Acquire), SRC as u16);
    assert_eq!(src.nr_running.load(Ordering::Acquire), 1);
    assert_eq!(dst.nr_running.load(Ordering::Acquire), 0);
    assert!(task.on_rq.is_queued(Ordering::Acquire));
}

#[test]
fn destination_offline_race_rolls_migration_back_to_source() {
    use core::sync::atomic::AtomicBool;

    let src = rq(SRC);
    let dst = rq(DST);
    let task = cfs_task(3012);
    task.cpus_allowed.store(m((1u64 << SRC) | (1u64 << DST)), Ordering::Release);
    queue(&src, &task);
    let accepting = AtomicBool::new(true);

    let get = |cpu| if cpu == SRC { Some(&src) } else if cpu == DST { Some(&dst) } else { None };
    assert_eq!(migrate_one_cfs_with(&src, &dst, &get, true, |point, _| {
        if point == MigrationPoint::BeforeDestinationCommit {
            accepting.store(false, Ordering::Release);
        }
    }, |cpu| cpu == SRC || accepting.load(Ordering::Acquire)), None);
    assert_eq!(task.cpu.load(Ordering::Acquire), SRC as u16);
    assert_eq!(src.nr_running.load(Ordering::Acquire), 1);
    assert_eq!(dst.nr_running.load(Ordering::Acquire), 0);
    assert!(task.on_rq.is_queued(Ordering::Acquire));
    assert!(task.on_class_rq.load(Ordering::Acquire));
}

#[test]
fn source_and_preferred_deactivation_fall_back_to_third_cpu() {
    use core::sync::atomic::AtomicBool;

    const THIRD: u32 = 42;
    let src = rq(SRC);
    let dst = rq(DST);
    let third = rq(THIRD);
    let task = cfs_task(3014);
    task.cpus_allowed.store(m((1u64 << SRC) | (1u64 << DST) | (1u64 << THIRD)),
                            Ordering::Release);
    queue(&src, &task);
    let dst_active = AtomicBool::new(true);
    let get = |cpu| match cpu {
        SRC => Some(&src), DST => Some(&dst), THIRD => Some(&third), _ => None,
    };

    assert_eq!(migrate_one_cfs_with(&src, &dst, &get, true, |point, _| {
        if point == MigrationPoint::BeforeDestinationCommit {
            dst_active.store(false, Ordering::Release);
        }
    }, |cpu| cpu == THIRD || (cpu == DST && dst_active.load(Ordering::Acquire))), Some(THIRD));
    assert_eq!(src.nr_running.load(Ordering::Acquire), 0);
    assert_eq!(dst.nr_running.load(Ordering::Acquire), 0);
    assert_eq!(third.nr_running.load(Ordering::Acquire), 1);
    assert_eq!(task.cpu.load(Ordering::Acquire), THIRD as u16);
}

#[test]
fn positive_control_stale_destination_acceptance_enqueues_on_closed_cpu() {
    use core::sync::atomic::AtomicBool;

    let src = rq(SRC);
    let dst = rq(DST);
    let task = cfs_task(3013);
    task.cpus_allowed.store(m((1u64 << SRC) | (1u64 << DST)), Ordering::Release);
    queue(&src, &task);
    let accepting = AtomicBool::new(true);

    let get = |cpu| if cpu == SRC { Some(&src) } else if cpu == DST { Some(&dst) } else { None };
    assert_eq!(migrate_one_cfs_with(&src, &dst, &get, true, |point, _| {
        if point == MigrationPoint::AfterDestinationEnqueue {
            accepting.store(false, Ordering::Release);
        }
    }, |_| true), Some(DST),
        "positive control: omitting commit revalidation reproduces offline enqueue");
    assert!(!accepting.load(Ordering::Acquire));
    assert_eq!(src.nr_running.load(Ordering::Acquire), 0);
    assert_eq!(dst.nr_running.load(Ordering::Acquire), 1,
        "stale acceptance leaves the task queued on the closed destination");
}
