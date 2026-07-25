// try_to_wake_up + wake-time CPU placement per `13§11` (Linux ttwu /
// select_task_rq). A blocking wait wakes a task by transitioning it
// Sleeping→Runnable and enqueuing it on a chosen CPU's runqueue; this module
// is the "which CPU" + "make that CPU reschedule" half. The periodic load
// balancer (`balance.rs`) redistributes afterwards; ttwu places work near
// idle CPUs at wake time so the idle AP picks it up without waiting a tick.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::task::PendingWake;
use crate::live::runqueue::Runqueue;
use crate::{Task, TaskState};
use super::runqueue::global_for;
use sync::{Spinlock, Runqueue as RunqueueClass};

/// Per-CPU deferred-wake list (Linux `ttwu_queue` / `wake_list` +
/// `sched_ttwu_pending`). A waker that must NOT place a task directly on a
/// runqueue pushes it here and IPIs the target; the target enqueues it on its
/// next `schedule()` drain. Used when:
///   - the task is still finishing its switch-OFF on another CPU (`on_cpu`) —
///     a direct enqueue could run it on two CPUs at once; or
///   - the target is a REMOTE CPU — a waker must not take a peer's rq lock; or
///   - the waker is the timer ISR (IF=0) — it must never block on a contended
///     rq lock (the BSP-tick freeze).
/// Leaf lock: pushed/drained briefly, NEVER held across the rq inner lock or a
/// context switch. Reuses the `Runqueue` class but is never nested with `inner`
/// (drain pulls the Vec out, releases, then `schedule()` takes `inner`).
struct WakeCell(Spinlock<Vec<Arc<Task>>, RunqueueClass>);
const WAKE_EMPTY: WakeCell = WakeCell(Spinlock::new(Vec::new()));
static WAKE_LISTS: [WakeCell; cpu::MAX_CPUS] = [WAKE_EMPTY; cpu::MAX_CPUS];

/// Push `task` onto CPU `cpu`'s deferred-wake list. Caller IPIs `cpu` after.
/// # C: O(1) amortized
pub fn wake_list_push(cpu: u32, task: Arc<Task>) {
    let i = cpu as usize;
    if i >= cpu::MAX_CPUS { return; }
    WAKE_LISTS[i].0.lock().push(task);
}

/// Drain CPU `cpu`'s deferred-wake list (Linux `sched_ttwu_pending`). Called
/// from `schedule()` on that CPU. Returns the claimed tasks (empty fast path
/// allocates nothing).
/// # C: O(deferred)
pub fn wake_list_drain(cpu: u32) -> Vec<Arc<Task>> {
    let i = cpu as usize;
    if i >= cpu::MAX_CPUS { return Vec::new(); }
    let mut g = WAKE_LISTS[i].0.lock();
    if g.is_empty() { return Vec::new(); }
    core::mem::take(&mut *g)
}

/// Drain this CPU's claimed wakes and return tasks now safe to enqueue. Tasks
/// still completing a switch-off are returned to their installed owner CPU;
/// that CPU's next scheduler edge retries after `finish_task_switch` clears
/// `on_cpu`. # C: O(deferred)
fn wake_list_ready(cpu: u32, current: *mut Task) -> Vec<Arc<Task>> {
    let mut ready = Vec::new();
    for task in wake_list_drain(cpu) {
        match task.pending_wake(current) {
            PendingWake::Drop => {}
            PendingWake::Ready => ready.push(task),
            PendingWake::Defer => {
                let owner = task.cpu.load(Ordering::Acquire) as u32;
                // SAFETY: bounded lookup; an absent old owner cannot drain a list.
                let target = if owner < cpu::MAX_CPUS as u32
                    && unsafe { global_for(owner) }.is_some() { owner } else { cpu };
                wake_list_push(target, task);
                resched_curr(target);
            }
        }
    }
    ready
}

/// Linux `sched_ttwu_pending`: consume this CPU's wake-list after switch
/// ownership is settled and enqueue each task exactly once. Called both before
/// a pick and from `finish_task_switch`; the latter closes a wake arriving
/// after the pre-pick drain but before the outgoing task clears `on_cpu`.
/// # C: O(deferred * log N)
pub fn sched_ttwu_pending(cpu: u32, current: *mut Task, rq: &Runqueue) -> bool {
    let ready = wake_list_ready(cpu, current);
    if ready.is_empty() { return false; }
    let mut inner = rq.inner.lock();
    for task in ready {
        task.set_vruntime_to_floor(inner.cfs.min_vruntime());
        inner.enqueue(task);
    }
    rq.nr_running.store(inner.nr_running(), Ordering::Release);
    drop(inner);
    resched_curr(cpu);
    true
}

/// This CPU's index (gs:0 / TPIDR). Host build → 0.
#[inline]
fn this_cpu() -> u32 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_x86_64::X86CpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1) as u32 }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_aarch64::ArmCpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1) as u32 }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// Choose the CPU to wake `task` on (Linux `select_task_rq`): the idlest
/// online runqueue (fewest `nr_running`) among the task's allowed CPUs,
/// biased to the caller's local CPU on ties (wake-affine: a not-busier
/// local stays cache-warm). Honors `cpus_allowed` (sched_setaffinity /
/// cpuset). UP / single online CPU → that CPU.
/// # C: O(N_cpus)
pub fn select_task_rq(task: &Task) -> u32 {
    let allowed = task.cpus_allowed.load(Ordering::Acquire);
    let local = this_cpu();
    let prev = task.cpu.load(Ordering::Acquire);
    if prev != u16::MAX {
        let cpu = prev as u32;
        if cpu < 64 && (allowed & (1u64 << cpu)) != 0 {
            // SAFETY: global_for returns None unless this prior owner still
            // has an installed runqueue.
            if let Some(rq) = unsafe { global_for(cpu) } {
                // Keep prev ONLY if it is idle (cache-warm + runs the wakee
                // immediately). If prev is busy, fall through to the idlest-CPU
                // scan so the wakee lands on an idle CPU and runs now instead of
                // queueing behind prev's current task — Linux
                // `select_idle_sibling`. An unconditional prev-return made a
                // woken sync-I/O waiter wait multi-ms with idle CPUs free.
                if rq.nr_running.load(Ordering::Acquire) == 0 { return cpu; }
            }
        }
    }
    let mut best: Option<u32> = None;
    let mut best_load = u32::MAX;
    // Visit local first so equal-load ties resolve to it (wake-affine).
    let order = core::iter::once(local)
        .chain((0..cpu::MAX_CPUS as u32).filter(move |&c| c != local));
    for cpu in order {
        // Affinity: only CPUs in the task's mask (bit per CPU, <64).
        if cpu < 64 && (allowed & (1u64 << cpu)) == 0 { continue; }
        // SAFETY: global_for is sound for any index; returns None unless that
        // CPU has installed its runqueue (online + scheduling).
        if let Some(rq) = unsafe { global_for(cpu) } {
            let load = rq.nr_running.load(Ordering::Acquire);
            if load < best_load { best_load = load; best = Some(cpu); }
        }
    }
    best.unwrap_or(local)
}

/// Make `cpu` reschedule (Linux `resched_curr`): set its per-CPU
/// `need_resched`; if it's a REMOTE CPU, send a reschedule IPI so it
/// re-enters `schedule()` promptly — waking its idle `hlt`/`wfi`, or
/// preempting its current user task at the next IRQ-exit. Local: the next
/// return-to-user / idle-loop schedule consumes the flag.
/// # C: O(1)
pub fn resched_curr(cpu: u32) {
    crate::preempt::set_need_resched_on(cpu as usize);
    if cpu != this_cpu() {
        // Hook installed at boot (set_send_resched_ipi_hook). Arch glue
        // translates this dense scheduler CPU id to APIC/GIC routing state.
        // SAFETY: non-blocking IPI/SGI to an online CPU; no-op if the hook is unset.
        unsafe { let _ = super::send_resched_ipi(cpu); }
    }
}

/// Honor a changed `cpus_allowed` (sched_setaffinity / cpuset): move `task`
/// off any disallowed CPU. A task QUEUED (on_rq, not currently running) on a
/// now-disallowed CPU is safely dequeued and re-placed via `select_task_rq`
/// (it isn't executing, so no cross-CPU race). A task RUNNING (rq.current) on
/// a disallowed CPU is nudged with need_resched + a reschedule IPI; fully
/// evicting a running task needs the `on_cpu` migration handshake (the target
/// must wait until it stops running on the source) — that lands with the
/// Phase C cross-CPU hardening. UP / single CPU: no-op (allowed == local).
/// # C: O(N_cpus · log N)
pub fn relocate_for_affinity(task: &Arc<Task>, allowed: u64) {
    let tid = task.tid;
    for cpu in 0..cpu::MAX_CPUS as u32 {
        // Skip CPUs the task is allowed on.
        if cpu < 64 && (allowed & (1u64 << cpu)) != 0 { continue; }
        // SAFETY: global_for is sound for any index; None unless that CPU is scheduling.
        let rq = match unsafe { global_for(cpu) } { Some(r) => r, None => continue };
        // Try to dequeue it from this disallowed CPU's runqueue (queued, not
        // running). One rq lock at a time — no nesting, no ordering hazard.
        let removed = {
            let mut inner = rq.inner.lock();
            let r = inner.remove(tid);
            if r.is_some() { rq.nr_running.store(inner.nr_running(), Ordering::Release); }
            r
        };
        if let Some(moved) = removed {
            moved.on_rq.store(false, Ordering::Release);
            // Re-place on an allowed CPU (select_task_rq filters by the mask).
            let target = select_task_rq(&moved);
            // SAFETY: target came from select_task_rq over installed runqueues.
            if let Some(trq) = unsafe { global_for(target) } {
                let mut ti = trq.inner.lock();
                ti.enqueue(moved);
                trq.nr_running.store(ti.nr_running(), Ordering::Release);
            }
            resched_curr(target);
        } else {
            // Not queued here — is it the RUNNING task on this disallowed CPU?
            // Nudge it to reschedule (it re-enqueues elsewhere on its next
            // sleep/yield). Synchronous eviction = Phase C on_cpu handshake.
            let cur = rq.current.load(Ordering::Acquire);
            // SAFETY: rq.current is non-null after install; the pointee is kept
            // alive by the rq's strong ref; reading the tid field is sound.
            if !cur.is_null() && unsafe { (*cur).tid } == tid {
                resched_curr(cpu);
            }
        }
    }
}

/// Shared `try_to_wake_up` body. `force_defer` routes placement through the
/// target's wake_list even when local+settled (the timer-ISR contract: never
/// take an rq lock from IF=0). See [`try_to_wake_up`] / [`ttwu_deferred`].
///
/// Claim-then-place (Linux ttwu): an atomic `Sleeping → Runnable` CAS claims
/// the wake (exactly one waker wins; losers / already-runnable / exiting tasks
/// return false), THEN the task is placed. This replaces the old "spin IF=0 on
/// `on_cpu`, then re-check state under the target rq lock" — that unbounded
/// cross-CPU spin AB-BA'd against a waker-held subsystem lock (the -smp hang).
/// # SAFETY: caller is a wake site (process/IRQ ctx); the Arc keeps `task`
/// alive; preempt discipline per the wake path.
/// # C: O(N_cpus + log N)
unsafe fn ttwu_inner(task: Arc<Task>, force_defer: bool) -> bool {
    if !task.claim_wake() {
        // The Sleeping -> Runnable transition is the exclusive placement
        // claim. A winner may not have reached `on_rq` yet, so treating
        // Runnable && !on_cpu && !on_rq as repairable lets a second waker put
        // the same task on another CPU's wake-list. Once the first copy is
        // picked (and clears on_rq), that delayed copy can enqueue a task that
        // is already executing, corrupting its saved context. Linux ttwu loses
        // this race at the state claim and performs no second placement.
        return false;
    }
    // Explicit wake clears any SO_*TIMEO deadline so the scanner doesn't re-rouse it.
    task.wakeup_deadline_ns.store(0, Ordering::Release);
    // debug-wakelat: stamp the make-Runnable instant + wake source so a
    // later switch-in can report the wake→run latency (H2) and whether the
    // wake came from the arrival edge or the deferred/scanner path (H1).
    #[cfg(feature = "debug-wakelat")]
    {
        let now = {
            #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
            { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 }
            #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
            { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 }
            #[cfg(not(target_os = "oxide-kernel"))]
            { 0u64 }
        };
        let src = if force_defer { super::wakelat::SRC_DEFER } else { super::wakelat::SRC_EDGE };
        super::wakelat::note_runnable(task.tid, now, src);
    }
    // SAFETY: ttwu_inner owns an Arc for this wake placement and has just
    // established the task is Runnable but not already executing or queued.
    unsafe { place_runnable(task, force_defer); }
    true
}

/// Place a Runnable task on an eligible runqueue, repairing the same invariant
/// as a normal wake: Runnable tasks must be executing or queued.
/// # SAFETY: caller is a wake site and owns an `Arc<Task>` for placement.
/// # C: O(N_cpus + log N)
unsafe fn place_runnable(task: Arc<Task>, force_defer: bool) {
    let me = this_cpu();
    let owner = task.cpu.load(Ordering::Acquire) as u32;
    let on_cpu = task.on_cpu.load(Ordering::Acquire);
    // SAFETY: owner is range-checked and global_for returns None unless that
    // CPU has an installed runqueue.
    let owner_online = owner < cpu::MAX_CPUS as u32
        && unsafe { global_for(owner) }.is_some();
    let target = if on_cpu && owner_online {
        owner
    } else {
        select_task_rq(&task)
    };
    // Defer to the target's wake_list (Linux `ttwu_queue_wakelist`) when we must
    // not place directly: the task is still switching OFF elsewhere (`on_cpu`),
    // the target is remote, or the caller forced it (timer ISR). The target
    // drains + enqueues it once its own switch has settled (`schedule()` →
    // `wake_list_drain`), so a task is never run on two CPUs and a waker never
    // blocks IF=0 on a peer's rq lock.
    if force_defer || target != me || task.on_cpu.load(Ordering::Acquire) {
        // Pick a real, installed CPU to own the deferred task; fall back to local.
        // SAFETY: global_for reads installed per-CPU runqueue slots; None unless online.
        let tcpu = if unsafe { global_for(target) }.is_some() { target }
                   else if unsafe { global_for(me) }.is_some() { me }
                   else { wake_list_push(target, task); return; };
        wake_list_push(tcpu, task);
        resched_curr(tcpu);
        return;
    }
    // Local, settled (`on_cpu == false`, target == this CPU): direct enqueue —
    // the UP fast path, behaviourally identical to the pre-SMP code. The task
    // is not on any rq (just claimed Runnable) so nobody can pick it / set its
    // `on_cpu` until we enqueue; the `on_cpu == false` check above therefore
    // can't race a fresh switch-on.
    // SAFETY: global_for(me) reads this CPU's own installed runqueue slot.
    if let Some(rq) = unsafe { global_for(me) } {
        {
            let mut inner = rq.inner.lock();
            // Sleeper credit on wake (F211).
            task.set_vruntime_to_floor(inner.cfs.min_vruntime());
            inner.enqueue(task);
            rq.nr_running.store(inner.nr_running(), Ordering::Release);
        }
        resched_curr(me);
    }
}

/// Linux `try_to_wake_up`: place a Sleeping `task` Runnable on its selected
/// CPU's runqueue and make that CPU reschedule. Returns true on a genuine
/// Sleeping→Runnable transition; false if the task was already runnable /
/// exiting (a racing waker won, or it's a stale wait-list entry). Remote /
/// still-`on_cpu` placements defer through the per-CPU wake_list.
/// # SAFETY: caller is a wake site (process/IRQ ctx); the Arc keeps `task`
/// alive; preempt discipline per the wake path.
/// # C: O(N_cpus + log N)
pub unsafe fn try_to_wake_up(task: Arc<Task>) -> bool {
    // SAFETY: wake-site context; the Arc keeps `task` alive across placement.
    unsafe { ttwu_inner(task, false) }
}

/// Timer-ISR / IRQ-context wake (Linux ttwu via `wake_list`, always deferred):
/// claims the Sleeping→Runnable transition, then hands placement to the
/// target's wake_list + a resched, NEVER taking an rq inner lock from the
/// caller. This is the wake form for the timer tick scanner (`tick_deadline`)
/// so a tick never blocks IF=0 on a contended rq lock (the BSP-tick freeze) and
/// never enqueues a task still finishing its switch-off elsewhere (run-on-2-CPUs
/// corruption).
/// # SAFETY: wake-site (timer ISR) context; the Arc keeps `task` alive.
/// # C: O(N_cpus)
pub unsafe fn ttwu_deferred(task: Arc<Task>) -> bool {
    // SAFETY: see try_to_wake_up; force_defer avoids any rq-lock acquire here.
    unsafe { ttwu_inner(task, true) }
}
