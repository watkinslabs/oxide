// `can_migrate_task` — Linux `kernel/sched/fair.c`'s two unconditional
// migration refusals. The `on_cpu` one is memory safety, not policy: pulling a
// task that is still executing on its source CPU lets the destination pick and
// run it while the source is still saving its registers.

use super::*;
use crate::task::SchedClass;

const SRC: u32 = 40;
const DST: u32 = 41;

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
    t.cpus_allowed.store(1u64 << SRC, Ordering::Release);
    assert!(!can_migrate_task(&t, DST));
    assert!(can_migrate_task(&t, SRC));
}

/// `on_cpu` outranks affinity: a running task pinned TO the destination is
/// still refused.
#[test]
fn running_outranks_a_permissive_affinity_mask() {
    let t = cfs_task(3005);
    t.cpus_allowed.store(u64::MAX, Ordering::Release);
    t.on_cpu.store(true, Ordering::Release);
    assert!(!can_migrate_task(&t, DST));
}

/// A CPU id past the 64-bit mask width cannot be expressed in `cpus_allowed`,
/// so affinity does not constrain it (matching the guarded call sites).
#[test]
fn affinity_does_not_constrain_cpu_ids_past_the_mask_width() {
    let t = cfs_task(3006);
    t.cpus_allowed.store(0, Ordering::Release);
    assert!(can_migrate_task(&t, 64));
}
