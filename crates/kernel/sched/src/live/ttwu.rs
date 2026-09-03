// try_to_wake_up + wake-time CPU placement per `13§11` (Linux ttwu /
// select_task_rq). A blocking wait wakes a task by transitioning it
// Sleeping→Runnable and enqueuing it on a chosen CPU's runqueue; this module
// is the "which CPU" + "make that CPU reschedule" half. The periodic load
// balancer (`balance.rs`) redistributes afterwards; ttwu places work near
// idle CPUs at wake time so the idle AP picks it up without waiting a tick.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::sched_enc::wakeup::{cand_of, wakeup_preempt};
use crate::task::PendingWake;
use crate::live::runqueue::{RqIrq, Runqueue};
use crate::Task;
#[cfg(feature = "debug-watchdog")]
use crate::task::WakeDiagPhase;
use super::runqueue::global_for;

mod wake_list;
mod cpu_target;
mod affinity;
pub use wake_list::{wake_list_debug, wake_list_push};

use wake_list::{wake_list_finish, wake_list_take};
pub use cpu_target::{resched_curr, service_current_cpu};
pub use affinity::{relocate_for_affinity, relocate_for_affinity_with, select_task_rq,
    select_task_rq_with, update_affinity};
use cpu_target::this_cpu;
#[cfg(test)]
use cpu_target::service_pending_on;
#[cfg(any(test, feature = "hosted"))]
pub use wake_list::wake_list_drain;

#[cfg(feature = "debug-watchdog")]
use cpu_target::wake_diag_now_ns;


/// The per-task decision is made INSIDE the rq lock, immediately before the
/// enqueue it authorises — Linux's structure exactly:
///
/// ```c
/// rq_lock_irqsave(rq, &rf);
/// llist_for_each_entry_safe(p, t, llist, wake_entry.llist) {
///         if (WARN_ON_ONCE(p->on_cpu))
///                 smp_cond_load_acquire(&p->on_cpu, !VAL);
///         ...
///         ttwu_do_activate(rq, p, ..., &rf);
/// }
/// ```
///
/// Classifying first and taking the lock afterwards (the pre-fix shape) is a
/// check-then-act across an unbounded wait: this rq's lock is held across whole
/// context switches, so a task cleared as "not executing" could be executing by
/// the time the enqueue landed. That is precisely the `WARN_ON_ONCE(p->on_cpu)`
/// Linux places at the activation point, and here it was fatal — `schedule()`
/// then picks a task another CPU owns. The target waits for switch-off under
/// its rq lock before activating the claimed task.
///
/// The producer-side `pi_lock` ends at the list publication.  Taking
/// it again after `llist_del_all` would turn the claimed list into a detached
/// local `Vec` while the target spins behind a waker: the task is no longer
/// linked, but it has not reached activation.  Linux's pending callback does
/// not reacquire `p->pi_lock`; its claimed llist is consumed under the target
/// rq lock.  Affinity writers already serialize their mask update and
/// relocation at the producer side, so the target consumes the published
/// target snapshot without reopening that handoff.
/// # C: O(deferred * log N)
pub fn sched_ttwu_pending(cpu: u32, current: *mut Task, rq: &Runqueue) -> bool {
    let mut node = wake_list_take(cpu);
    if node.is_null() { return false; }
    let mut requeue = [false; cpu::MAX_CPUS];
    let mut placed = false;
    let mut preempt = false;
    // Linux acquires the target rq once and walks the claimed llist under it.
    // In particular, do not reacquire the producer's task-side wake lock here:
    // it protects claim/CPU selection before publication, not target-side
    // activation after the list transfer.
    let mut inner = rq.inner.lock_irqsave::<RqIrq>();
    while !node.is_null() {
        // SAFETY: wake_list_take claimed this chain exclusively; read the next
        // raw link before Arc::from_raw retakes this node's strong reference.
        let next = unsafe { (&(*node)).wake_next.load(Ordering::Relaxed) };
        // SAFETY: wake_list_push transferred exactly one strong reference into
        // each node, and this detached-chain walk consumes it exactly once.
        let task = unsafe { Arc::from_raw(node as *const Task) };
        task.on_wake_list.store(false, Ordering::Release);
        #[cfg(feature = "debug-watchdog")]
        task.wake_diag_mark(WakeDiagPhase::Drained, wake_diag_now_ns());
        // A task can sit on the remote wake list while an affinity writer
        // narrows its mask. Its producer/affinity-side critical section
        // publishes the selected target before list insertion; a later change
        // is repaired by the affinity relocation path after this activation.
        let allowed = task.cpus_allowed.load(Ordering::Acquire);
        if !allowed.contains(cpu as usize) {
            let target = select_task_rq(&task) as usize;
            requeue[target] |= wake_list_push(target as u32, task);
            node = next;
            continue;
        }
        if core::ptr::eq(Arc::as_ptr(&task), current as *const Task) {
            rq.account_wake(&task);
            task.complete_wake();
            node = next;
            continue;
        }
        match task.pending_wake(current) {
            PendingWake::Drop  => {}
            PendingWake::Defer => {
                // A callback can observe the outgoing task before its switch
                // tail clears `on_cpu`. Never spin in IRQ context: the
                // interrupted task may hold a lock needed by the CPU that must
                // finish that handoff. Keep the wake on its canonical owner;
                // IRQ return completes the switch, and a later drain activates
                // it. Linux's queued wake callback runs after that same
                // finish-task handoff rather than waiting in the interrupt.
                let owner = task.cpu.load(Ordering::Acquire) as usize;
                let target = if owner < cpu::MAX_CPUS
                    && cpu::smp::online_cpumask().contains(owner)
                    && cpu::smp::accepts_work(owner as u32) { owner } else { cpu as usize };
                requeue[target] |= wake_list_push(target as u32, task);
                node = next;
                continue;
            }
            PendingWake::Ready => {
                // SAFETY: `current` is this CPU's running task, kept alive by
                // the runqueue's strong reference for this locked decision.
                let raw = rq.current.load(Ordering::Acquire);
                // SAFETY: `raw` is the runqueue's current-task pointer read under the held rq
                // lock, and the runqueue holds a strong reference to whatever it names, so the
                // borrow cannot outlive the task or race a swap of `rq.current`.
                let curr = if raw.is_null() { None } else { Some(cand_of(unsafe { &*raw })) };
                #[cfg(feature = "debug-watchdog")]
                task.wake_diag_mark(WakeDiagPhase::Activating, wake_diag_now_ns());
                task.lift_vruntime(inner.cfs.min_vruntime());
                preempt |= curr.is_none_or(|c| wakeup_preempt(cand_of(&task), c));
                rq.account_wake(&task);
                #[cfg(target_os = "oxide-kernel")]
                let wake_util = task.update_util(crate::deadline::clock::now_ns(), false);
                #[cfg(target_os = "oxide-kernel")]
                let wake_iowait = task.take_iowait();
                inner.enqueue(Arc::clone(&task));
                #[cfg(target_os = "oxide-kernel")]
                crate::cpufreq_hook::update_from_scheduler(
                    cpu as usize, wake_util, wake_iowait, crate::deadline::clock::now_ns());
                placed = true;
            }
        }
        node = next;
    }
    rq.publish_nr_running(inner.nr_running());
    let more = wake_list_finish(cpu);
    drop(inner);
    // Requeue wake-list work only after dropping the target rq lock. Linux's
    // pending callback likewise never sends a reschedule IPI under rq lock.
    for (target, queued) in requeue.into_iter().enumerate() {
        if queued { resched_curr(target as u32); }
    }
    if more || (placed && preempt) { resched_curr(cpu); }
    placed
}


/// Shared `try_to_wake_up` body. `force_defer` routes placement through the
/// target's wake_list even when local+settled (the interrupt-context contract:
/// never take an rq lock from a hardirq/softirq that may have interrupted its
/// owner). See [`try_to_wake_up`] / [`ttwu_deferred`].
///
/// Claim-then-place: an atomic `Sleeping → Waking` CAS claims the wake
/// (exactly one waker wins; losers / already-runnable / exiting tasks return
/// false), THEN the task is activated and published Runnable. This replaces the old "spin IF=0 on
/// `on_cpu`, then re-check state under the target rq lock" — that unbounded
/// cross-CPU spin AB-BA'd against a waker-held subsystem lock (the -smp hang).
/// # SAFETY: caller is a wake site (process/IRQ ctx); the Arc keeps `task`
/// alive; preempt discipline per the wake path.
/// # C: O(N_cpus + log N)
unsafe fn ttwu_inner(task: Arc<Task>, force_defer: bool) -> bool {
    // Serialize wake state, affinity, and CPU selection with the task-side
    // lock. An affinity writer cannot land between this claim and the enqueue
    // selected from the mask. IRQ-save prevents a same-task hardirq wake from
    // spinning on interrupted process context holding this lock.
    let _wake = task.pi_lock.lock_irqsave::<RqIrq>();
    if !task.claim_wake() {
        // The Sleeping -> Waking transition is the exclusive placement
        // claim. A winner may not have reached `on_rq` yet, so treating
        // Runnable && !on_cpu && !on_rq as repairable lets a second waker put
        // the same task on another CPU's wake-list. Once the first copy is
        // picked (and clears on_rq), that delayed copy can enqueue a task that
        // is already executing, corrupting its saved context. Linux ttwu loses
        // this race at the state claim and performs no second placement.
        return false;
    }
    #[cfg(feature = "debug-watchdog")]
    task.wake_diag_mark(WakeDiagPhase::Claimed, wake_diag_now_ns());
    // Explicit wake clears any SO_*TIMEO deadline so the scanner doesn't re-rouse it.
    task.wakeup_deadline_ns.store(0, Ordering::Release);
    // debug-wakelat: stamp the exclusive wake claim + source so a later
    // switch-in can report wake-to-run latency (H2) and whether the wake came
    // from the arrival edge or the deferred/scanner path (H1).
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
    unsafe { place_runnable(Arc::clone(&task), force_defer); }
    true
}

/// Place a Runnable task on an eligible runqueue, repairing the same invariant
/// as a normal wake: Runnable tasks must be executing or queued. Every caller
/// routes through here so CPU choice happens in ONE place — `select_task_rq`,
/// which is the only code that consults `cpus_allowed`. A site that enqueues
/// straight onto `runqueue::global()` instead silently ignores the affinity
/// mask (Linux `wake_up_new_task` has the same `select_task_rq` step).
/// # SAFETY: caller is a wake site and owns an `Arc<Task>` for placement.
/// # C: O(N_cpus + log N)
pub(crate) unsafe fn place_runnable(task: Arc<Task>, force_defer: bool) {
    // SAFETY: `global_for` is sound for any index; it yields `None` for a CPU
    // that has not completed `install_global`, which the walk skips.
    place_runnable_with(&|c| unsafe { global_for(c) }, this_cpu(), task, force_defer);
}

/// [`place_runnable`] over an injected CPU->runqueue accessor and local CPU id.
/// Every wake in the tree funnels through here, so the `on_cpu` handshake is
/// stated once and is hosted-testable on a real two-CPU model — see
/// [`select_task_rq_with`] for why the accessor is injected.
/// # C: O(N_cpus + log N)
pub(crate) fn place_runnable_with<'a, F>(get_rq: &F, me: u32, task: Arc<Task>, force_defer: bool)
where F: Fn(u32) -> Option<&'a Runqueue> {
    let owner = task.cpu.load(Ordering::Acquire) as u32;
    // Linux ttwu's `smp_load_acquire(&p->on_cpu)` (in
    // `try_to_wake_up`), pairing with `finish_task`'s
    // `smp_store_release(&prev->on_cpu, 0)`.
    let on_cpu = task.on_cpu.load(Ordering::Acquire);
    let owner_online = owner < cpu::MAX_CPUS as u32 && get_rq(owner).is_some();
    let target = if on_cpu && owner_online {
        owner
    } else {
        select_task_rq_with(get_rq, me, &task)
    };
    // Defer to the target's wake_list (Linux `ttwu_queue_wakelist`) when we must
    // not place directly: the task is still switching OFF elsewhere (`on_cpu`),
    // the target is remote, or the caller forced it (timer ISR). The target
    // drains + enqueues it once its own switch has settled (`schedule()` →
    // `wake_list_drain`), so a task is never run on two CPUs and a waker never
    // blocks IF=0 on a peer's rq lock.
    let target_idle = get_rq(target).is_some_and(|rq|
        rq.nr_running.load(Ordering::Acquire) == 0);
    let softirq_idle_wake = crate::preempt::in_serving_softirq() && target_idle;
    if force_defer || target != me || task.on_cpu.load(Ordering::Acquire) || softirq_idle_wake {
        // Pick a real, installed CPU to own the deferred task; fall back to local.
        let tcpu = if get_rq(target).is_some() { target }
                   else if get_rq(me).is_some() { me }
                   else { let _ = wake_list_push(target, task); return; };
        let kick = wake_list_push(tcpu, task);
        // Unconditional, and NOT a preemption decision: the target drains its
        // wake list from `schedule()`, so without this the task would never
        // reach a runqueue at all. The preemption decision is made on the
        // drain side, once the task is enqueued and `curr` is known there
        // (`sched_ttwu_pending`).
        if kick { resched_curr(tcpu); }
        return;
    }
    // Local, settled (`on_cpu == false`, target == this CPU): direct enqueue —
    // the UP fast path, behaviourally identical to the pre-SMP code. The task
    // is not on any rq (just claimed Runnable) so nobody can pick it / set its
    // `on_cpu` until we enqueue; the `on_cpu == false` check above therefore
    // can't race a fresh switch-on.
    if let Some(rq) = get_rq(me) {
        let curr = rq.current.load(Ordering::Acquire);
        // SAFETY: `current` is non-null after `Runqueue::new`; the runqueue holds
        // the strong reference, so this snapshot read is sound.
        let curr = if curr.is_null() { None } else { Some(cand_of(unsafe { &*curr })) };
        let preempt;
        {
            let mut inner = rq.inner.lock_irqsave::<RqIrq>();
            // Sleeper credit on wake (F211).
            task.lift_vruntime(inner.cfs.min_vruntime());
            // Linux `ttwu_do_activate` -> `wakeup_preempt`: the wake only takes
            // the CPU away from the running task when the class/policy/priority
            // comparison says it should. Resching unconditionally here made
            // SCHED_FIFO lose the CPU to an equal-priority peer and let a
            // SCHED_BATCH / SCHED_IDLE wakee preempt a SCHED_NORMAL task.
            preempt = curr.is_none_or(|c| wakeup_preempt(cand_of(&task), c));
            #[cfg(feature = "debug-watchdog")]
            task.wake_diag_mark(WakeDiagPhase::Activating, wake_diag_now_ns());
            rq.account_wake(&task);
            #[cfg(target_os = "oxide-kernel")]
            let wake_util = task.update_util(crate::deadline::clock::now_ns(), false);
            #[cfg(target_os = "oxide-kernel")]
            let wake_iowait = task.take_iowait();
            inner.enqueue(task);
            #[cfg(target_os = "oxide-kernel")]
            crate::cpufreq_hook::update_from_scheduler(
                me as usize, wake_util, wake_iowait, crate::deadline::clock::now_ns());
            rq.publish_nr_running(inner.nr_running());
        }
        if preempt { resched_curr(me); }
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
    // Linux takes the target rq lock with IRQs saved. Oxide's IRQ and softirq
    // tails instead use the existing `ttwu_queue_wakelist` analogue: an IRQ
    // can interrupt process context while it owns this CPU's rq lock, so a
    // direct local enqueue would self-deadlock in `Spinlock::lock`. This is
    // broader than the timer scanner: block-completion softirq wakes use the
    // ordinary WaitList path and need the same deferral.
    let irq_context = wake_context_requires_defer();
    // SAFETY: wake-site context; the Arc keeps `task` alive across placement.
    unsafe { ttwu_inner(task, irq_context) }
}

#[inline]
fn wake_context_requires_defer() -> bool {
    // Hard IRQs cannot take a runqueue lock that they may have interrupted.
    // Softirq completion runs after the hard-IRQ field is dropped and follows
    // Linux's target-specific `ttwu_queue_cond` decision in placement.
    crate::preempt::hardirq_count() != 0
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

#[cfg(test)]
mod tests;
