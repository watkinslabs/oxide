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


use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::Task;

use super::runqueue::{global_for, Runqueue};

/// Snapshot of one CPU's load. Captured under the runqueue's
/// inner lock, then released before the migration decision.
#[derive(Copy, Clone)]
struct CpuLoad {
    cpu:        u32,
    nr_running: u32,
}

/// Pick a CFS task off `rq`'s queue. Returns `None` if no CFS
/// task is queued (only idle / RT). Caller already filtered to
/// "this CPU has surplus".
fn pop_one_cfs(rq: &Runqueue) -> Option<Arc<Task>> {
    let mut inner = rq.inner.lock();
    // CFS tasks are leftmost in vruntime order; pick_leftmost is
    // O(log N) but we don't actually want the *highest priority*
    // — for migration the principle is "any task is fine, just
    // unload this CPU". Steal the leftmost since that's what's
    // already at the head of the queue.
    let t = inner.cfs.pick_leftmost();
    if let Some(ref tk) = t {
        let _ = tk;
    }
    rq.nr_running.store(inner.nr_running(), Ordering::Release);
    t
}

/// Push `task` onto `rq`'s queue.
fn push_to(rq: &Runqueue, task: Arc<Task>) {
    let mut inner = rq.inner.lock();
    inner.enqueue(task);
    rq.nr_running.store(inner.nr_running(), Ordering::Release);
}

/// One pass of the load balancer. Returns the number of tasks
/// migrated (0 or 1 in v1).
///
/// # SAFETY: caller is the boot CPU or a kthread context;
/// `global_for` returns stable references for online CPUs;
/// migration takes per-CPU runqueue inner locks in CPU-id order
/// to avoid the trivial deadlock between a pair.
/// # C: O(N_cpus + log N_tasks)
pub unsafe fn balance_once() -> u32 {
    let online = cpu::smp::online_count();
    if online < 2 { return 0; }

    // Snapshot loads.
    let mut loads: alloc::vec::Vec<CpuLoad> = alloc::vec::Vec::new();
    for i in 0..cpu::count() {
        if let Some((id, _)) = cpu::get(i as usize) {
            // SAFETY: per fn contract; CPU id is one ACPI MADT enumerated and is bounded by MAX_CPUS.
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

    // Lock order: lower cpu id first so concurrent balancers on
    // a pair never deadlock. v1 only ever runs from BSP for now,
    // so this is forward-looking.
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

    let task = pop_one_cfs(busy_rq);
    let task = match task { Some(t) => t, None => return 0 };
    push_to(idle_rq, task);

    // Wake the destination so its idle loop picks up the new task.
    #[cfg(target_arch = "x86_64")]
    // SAFETY: LAPIC enabled on BSP; ICR write is non-blocking; idle_cpu APIC ID is from cpu_topology.
    unsafe { let _ = super::send_resched_ipi(idle_cpu); }

    1
}
