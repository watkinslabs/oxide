// Cross-CPU load balancer per `13§11`.
//
// v1: simplest correct shape. `balance_once()` scans the per-CPU
// runqueue array, identifies the busiest + idlest CPUs by total
// `nr_running`, and migrates a single CFS task from busiest →
// idlest if the delta is ≥ 2. Sends a resched IPI to the
// destination so its idle loop wakes and picks up the new task.
//
// Periodic + idle-pull + push-on-overload variants land alongside
// per-CPU `clock` ticks in P4-23+. Today's call site is a one-shot
// boot-time smoke that exercises the migration path; the structure
// is what the periodic balancer will reuse verbatim.


use core::sync::atomic::Ordering;

use crate::Task;

use super::runqueue::{global_for, RqIrq, Runqueue};

/// Cache-hot window (Linux `sysctl_sched_migration_cost`, 0.5 ms): a task
/// that last ran within this of now is likely still warm in its CPU's cache,
/// so the periodic balancer leaves it put unless the imbalance is large.
const MIGRATION_COST_NS: u64 = 500_000;

/// This CPU's index. Host build → 0.
#[inline]
fn this_cpu() -> u32 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; hal_x86_64::X86CpuOps::current_cpu() }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; hal_aarch64::ArmCpuOps::current_cpu() }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

#[inline]
fn now_ns() -> u64 {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// Snapshot of one CPU's load. Captured under the runqueue's
/// inner lock, then released before the migration decision.
#[derive(Copy, Clone)]
struct CpuLoad {
    cpu:        u32,
    nr_running: u32,
}

/// Move one CFS task through the single-rq migration bridge. Candidate lookup
/// is speculative; after taking TaskPi -> source rq, CPU, state, affinity, and
/// class-tree membership are revalidated before any state changes.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum MigrationPoint {
    BeforeDequeue,
    BeforeSourceUnlock,
    BeforeDestinationCommit,
    AfterDestinationEnqueue,
}

fn migration_destination_accepts(cpu: u32) -> bool {
    cpu::smp::is_active(cpu)
}

fn cache_hot(task: &Task, now: u64) -> bool {
    let last = task.sched.se.exec_start.load(Ordering::Acquire);
    last != 0 && now.saturating_sub(last) < MIGRATION_COST_NS
}

fn migrate_one_cfs_with<'a, F, A, G>(src: &'a Runqueue, dst: &'a Runqueue,
                                     get_rq: &G, ignore_hot: bool,
                                     mut probe: F, accepts: A) -> Option<u32>
where F: FnMut(MigrationPoint, &Task), A: Fn(u32) -> bool,
      G: Fn(u32) -> Option<&'a Runqueue> {
    // `lock_irqsave`, not `lock`: the balancer runs from the IDLE LOOP
    // (`halt_forever` -> `newidle_balance`), outside `schedule()`'s IRQ-off
    // window, while softirq context takes this same runqueue lock. A plain
    // acquisition lets a softirq land on this CPU mid-hold and spin on it
    // forever (`06§3.1`, `skizm.md` Step 3e-bh).
    //
    // NOT `lock_bh`, which drains softirqs on release; those callbacks also
    // take rq locks. Masking interrupts excludes them without a release-time
    // drain, matching the rq lock's irqsave contract.
    let task = {
        let inner = src.inner.lock_irqsave::<RqIrq>();
        let now = now_ns();
        inner.cfs.find(|task| can_migrate_task(task, dst.cpu as u32)
            && (ignore_hot || !cache_hot(task, now)))?
    };
    let _placement = sync::rcu_read_lock();
    let mut bridge = |point, _, moving: &Task| probe(match point {
        super::migration::MovePoint::SourceLocked => MigrationPoint::BeforeDequeue,
        super::migration::MovePoint::SourceDetached => MigrationPoint::BeforeSourceUnlock,
        super::migration::MovePoint::DestinationLocked => MigrationPoint::BeforeDestinationCommit,
        super::migration::MovePoint::DestinationCommitted => MigrationPoint::AfterDestinationEnqueue,
    }, moving);
    match super::migration::move_queued_with(get_rq, &task, Some(dst.cpu as u32),
                                              &accepts, &mut bridge) {
        super::migration::MoveResult::Moved { from, to } if from != to => Some(to),
        super::migration::MoveResult::Unplaced { from, task } =>
            match super::migration::finish_unplaced_with(
                get_rq, task, from, Some(dst.cpu as u32), &accepts, &mut bridge) {
                super::migration::MoveResult::Moved { from, to } if from != to => Some(to),
                _ => None,
            },
        _ => None,
    }
}

/// Linux `can_migrate_task`, the two unconditional
/// refusals. Both are correctness, not policy:
///
///   * `task_on_cpu(env->src_rq, p)` — a task still executing on its source CPU
///     may NOT be pulled. Its registers are being saved; moving it lets the
///     destination pick it and run it on two CPUs at once, which is what
///     `schedule()`'s `on_cpu` CAS ("selected task already owned by another
///     CPU") catches. Linux counts these as `nr_failed_migrations_running`.
///   * `!cpumask_test_cpu(env->dst_cpu, p->cpus_ptr)` — the destination must be
///     in `cpus_allowed` (`sched_setaffinity` / cgroup `cpuset.cpus`). Linux
///     counts these as `nr_failed_migrations_affine`.
///
/// A CPU id at or above the 64-bit mask width cannot be expressed in
/// `cpus_allowed`, so affinity does not constrain it.
/// The cache-hot heuristic (`sysctl_sched_migration_cost`) is a separate,
/// imbalance-scaled decision and stays at the call site.
/// # C: O(1)
pub fn can_migrate_task(task: &Task, dst_cpu: u32) -> bool {
    if task.on_cpu.load(Ordering::Acquire) { return false; }
    if !task.cpus_allowed.load(Ordering::Acquire).contains(dst_cpu as usize) {
        return false;
    }
    true
}

/// One pass of the load balancer. Returns the number of tasks
/// migrated (0 or 1 in v1).
///
/// # SAFETY: caller is the boot CPU or a kthread context;
/// `global_for` returns stable references for online CPUs;
/// migration takes per-CPU runqueue inner locks in CPU-id order
/// to avoid the trivial deadlock between a pair.
/// # C: O(N_cpus + N_tasks + log N_tasks)
pub unsafe fn balance_once() -> u32 {
    let online = cpu::smp::online_count();
    if online < 2 { return 0; }
    let online_mask = cpu::smp::online_cpumask();

    // Snapshot loads.
    let mut loads: alloc::vec::Vec<CpuLoad> = alloc::vec::Vec::new();
    for id in 0..cpu::count() {
        if !online_mask.contains(id as usize) || !cpu::smp::accepts_work(id) { continue; }
        if cpu::get(id as usize).is_some() {
            // SAFETY: per fn contract; topology slots are dense logical IDs bounded by MAX_CPUS.
            let rq_opt = unsafe { global_for(id) };
            if let Some(rq) = rq_opt {
                loads.push(CpuLoad {
                    cpu:        id,
                    nr_running: rq.nr_running.load(Ordering::Acquire),
                });
            }
        }
    }
    if loads.is_empty() { return 0; }

    // Pick busiest + lightest.
    let (mut busy_idx, mut idle_idx) = (0usize, 0usize);
    for (i, l) in loads.iter().enumerate() {
        if l.nr_running > loads[busy_idx].nr_running { busy_idx = i; }
        if l.nr_running < loads[idle_idx].nr_running { idle_idx = i; }
    }
    if busy_idx == idle_idx { return 0; }
    let delta = loads[busy_idx].nr_running.saturating_sub(loads[idle_idx].nr_running);
    if delta < 2 { return 0; }

    let busy_cpu = loads[busy_idx].cpu;
    let idle_cpu = loads[idle_idx].cpu;

    // SAFETY: busy_cpu was just enumerated above and has a runqueue.
    let busy_rq = match unsafe { global_for(busy_cpu) } {
        Some(rq) => rq,
        None     => return 0,
    };
    // SAFETY: same — idle_cpu's runqueue is live.
    let idle_rq = match unsafe { global_for(idle_cpu) } {
        Some(rq) => rq,
        None     => return 0,
    };

    // A large imbalance overrides cache warmth. All admission checks and CPU
    // publication occur under TaskPi -> source rq; source and destination rq
    // locks are never nested.
    let get_rq = |cpu| unsafe { global_for(cpu) };
    let Some(target) = migrate_one_cfs_with(busy_rq, idle_rq, &get_rq, delta >= 4, |_, _| {},
                                             migration_destination_accepts) else { return 0; };

    // Wake the destination so its idle loop picks up the new task. The
    // hook is arch-agnostic (x86 LAPIC ICR / arm GIC SGI), installed at
    // boot; no-op (false) when unset.
    // SAFETY: send_resched_ipi is a non-blocking IPI/SGI to an online CPU.
    unsafe { let _ = super::send_resched_ipi(target); }

    1
}

/// Periodic load-balance pass for the timer driver: migrate up to one task
/// busiest→idlest per CPU, bounded by online count so a burst converges in
/// one tick. No-op with <2 CPUs. Process context (takes per-CPU rq locks).
/// # C: O(online_cpus · migrate)
pub fn balance_tick(_now_ns: u64) {
    for _ in 0..cpu::smp::online_count() {
        // SAFETY: timer-driver kthread (process ctx), not under any runqueue lock; balance_once takes the per-CPU inner locks in cpu-id order so no pair deadlocks.
        if unsafe { balance_once() } == 0 { break; }
    }
}

/// Newidle balance (Linux `sched_balance_newidle`): a CPU whose runqueue just
/// went empty pulls ONE runnable CFS task from the busiest remote CPU rather
/// than idling while another CPU is overloaded. Called from the idle loop
/// (`halt_forever`) before parking. Honors affinity; ignores cache-hot (an
/// idle CPU pulling overloaded work is a net win — it has no warm cache for
/// the task anyway). Returns 1 if it pulled a task, else 0.
/// # SAFETY: idle context, not holding any runqueue lock; takes one per-CPU
/// inner lock at a time (no nesting).
/// # C: O(N_cpus + N_tasks + log N_tasks)
pub unsafe fn newidle_balance() -> u32 {
    if cpu::smp::online_count() < 2 { return 0; }
    let me = this_cpu();
    // SAFETY: this CPU's runqueue is installed (we're in its idle loop).
    let my_rq = match unsafe { global_for(me) } { Some(r) => r, None => return 0 };
    // Only pull if WE have nothing runnable.
    if my_rq.nr_running.load(Ordering::Acquire) > 0 { return 0; }
    // Find the busiest remote CPU (>1 runnable so pulling actually unloads it).
    let mut busy_cpu: Option<u32> = None;
    let mut busy_load = 1u32;
    let online = cpu::smp::online_cpumask();
    let n = cpu::count();
    for id in 0..n {
        if !online.contains(id as usize) || !cpu::smp::accepts_work(id) { continue; }
        if cpu::get(id as usize).is_some() {
            if id == me { continue; }
            // SAFETY: enumerated CPU; global_for None unless it's scheduling.
            if let Some(rq) = unsafe { global_for(id) } {
                let l = rq.nr_running.load(Ordering::Acquire);
                if l > busy_load { busy_load = l; busy_cpu = Some(id); }
            }
        }
    }
    let busy_cpu = match busy_cpu { Some(c) => c, None => return 0 };
    // SAFETY: busy_cpu was just enumerated with a live runqueue.
    let busy_rq = match unsafe { global_for(busy_cpu) } { Some(r) => r, None => return 0 };
    let get_rq = |cpu| unsafe { global_for(cpu) };
    migrate_one_cfs_with(busy_rq, my_rq, &get_rq, true, |_, _| {},
                         migration_destination_accepts).is_some() as u32
}

#[cfg(test)]
mod tests;
