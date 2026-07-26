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
/// Arch IRQ gate for the runqueue lock on the balancer path.
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
type RqIrq = hal_x86_64::X86IrqGate;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
type RqIrq = hal_aarch64::ArmIrqGate;
#[cfg(not(target_os = "oxide-kernel"))]
type RqIrq = sync::NoopIrq;

#[derive(Copy, Clone)]
struct CpuLoad {
    cpu:        u32,
    nr_running: u32,
}

/// Pick a CFS task off `rq`'s queue. Returns `None` if no CFS
/// task is queued (only idle / RT). Caller already filtered to
/// "this CPU has surplus".
fn pop_one_cfs(rq: &Runqueue) -> Option<Arc<Task>> {
    // `lock_irqsave`, not `lock`: the balancer runs from the IDLE LOOP
    // (`halt_forever` -> `newidle_balance`), outside `schedule()`'s IRQ-off
    // window, while softirq context takes this same runqueue lock. A plain
    // acquisition lets a softirq land on this CPU mid-hold and spin on it
    // forever (`06§3.1`, `skizm.md` Step 3e-bh).
    //
    // NOT `lock_bh`, which is the usual answer for a softirq-shared lock:
    // `balance_once` holds TWO runqueue locks at once, and `local_bh_enable`
    // on the inner guard's release DRAINS SOFTIRQS while the outer lock is
    // still held — and those softirqs take a runqueue lock. That deadlocks,
    // and did: it hung the boot with an NMI backtrace. Masking interrupts
    // excludes softirqs on this CPU with no drain on release, which is exactly
    // why Linux's rq lock is `raw_spin_lock_irqsave`.
    let mut inner = rq.inner.lock_irqsave::<RqIrq>();
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
    // Same reasoning as `pop_one_cfs`: reached from the idle-loop balancer.
    let mut inner = rq.inner.lock_irqsave::<RqIrq>();
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
    // Affinity: only migrate to a CPU in the task's cpus_allowed mask
    // (`sched_setaffinity` / cgroup cpuset.cpus). If the chosen task is
    // pinned away from idle_cpu, put it back and skip this round rather
    // than violate the mask (a later round may move a different task).
    if idle_cpu < 64 && task.cpus_allowed.load(Ordering::Acquire) & (1u64 << idle_cpu) == 0 {
        push_to(busy_rq, task);
        return 0;
    }
    // can_migrate_task cache-hot guard (Linux): a task that ran within
    // MIGRATION_COST_NS is likely cache-warm on `busy_cpu`; leave it unless
    // the imbalance is large (delta >= 4) where spreading wins over locality.
    if delta < 4 {
        let last = task.exec_start_ns.load(Ordering::Acquire);
        let now = now_ns();
        if last != 0 && now.saturating_sub(last) < MIGRATION_COST_NS {
            push_to(busy_rq, task);
            return 0;
        }
    }
    task.cpu.store(idle_cpu as u16, Ordering::Release);
    push_to(idle_rq, task);

    // Wake the destination so its idle loop picks up the new task. The
    // hook is arch-agnostic (x86 LAPIC ICR / arm GIC SGI), installed at
    // boot; no-op (false) when unset.
    // SAFETY: send_resched_ipi is a non-blocking IPI/SGI to an online CPU.
    unsafe { let _ = super::send_resched_ipi(idle_cpu); }

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
/// # C: O(N_cpus + log N)
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
    let n = cpu::count();
    for i in 0..n {
        if let Some((id, _)) = cpu::get(i as usize) {
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
    let task = pop_one_cfs(busy_rq);
    let task = match task { Some(t) => t, None => return 0 };
    // Affinity: if pinned away from us, put it back and skip.
    if me < 64 && task.cpus_allowed.load(Ordering::Acquire) & (1u64 << me) == 0 {
        push_to(busy_rq, task);
        return 0;
    }
    task.cpu.store(me as u16, Ordering::Release);
    push_to(my_rq, task);
    1
}
