// try_to_wake_up + wake-time CPU placement per `13§11` (Linux ttwu /
// select_task_rq). A blocking wait wakes a task by transitioning it
// Sleeping→Runnable and enqueuing it on a chosen CPU's runqueue; this module
// is the "which CPU" + "make that CPU reschedule" half. The periodic load
// balancer (`balance.rs`) redistributes afterwards; ttwu places work near
// idle CPUs at wake time so the idle AP picks it up without waiting a tick.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::sched_enc::wakeup::{cand_of, wakeup_preempt};
use crate::task::PendingWake;
use crate::live::runqueue::Runqueue;
use crate::Task;
use super::runqueue::global_for;

/// Per-CPU deferred-wake list (Linux `ttwu_queue` / `wake_list` +
/// `sched_ttwu_pending`). A waker that must NOT place a task directly on a
/// runqueue pushes it here and IPIs the target; the target enqueues it on its
/// next `schedule()` drain. Used when:
///   - the task is still finishing its switch-OFF on another CPU (`on_cpu`) —
///     a direct enqueue could run it on two CPUs at once; or
///   - the target is a REMOTE CPU — a waker must not take a peer's rq lock; or
///   - the waker is the timer ISR (IF=0) — it must never block on a contended
///     rq lock (the BSP-tick freeze).
/// Never held across the rq inner lock or a context switch: the drain claims
/// the whole chain in one atomic swap and is done, then `schedule()` takes
/// `inner`.
///
/// Head of each CPU's lock-free wake list (Linux `llist_head`). A bare
/// `AtomicPtr` chained through `Task::wake_next`; each linked node owns one
/// strong reference, transferred in by `Arc::into_raw` and back out by
/// `Arc::from_raw`.
///
/// This was a `Spinlock<Vec<Arc<Task>>>`, and both halves of that were wrong
/// for the contexts involved. The timer ISR pushes here (`tick_poll_ktimers`
/// waking `ktimers`), while `place_runnable` pushes and `schedule()` drains
/// from process context — all taking the lock PLAINLY. A tick landing on a CPU
/// whose process-context push already held the lock spins forever with IRQs
/// masked, and it held that lock across `Vec::push`, i.e. across a possible
/// allocation, which widened the window and took the allocator lock from hard
/// IRQ as well (`06§3.1`; lockdep's `Runqueue` and `KMalloc` classes,
/// `skizm.md` 3.1 #4 and 3.0).
///
/// Linux uses an `llist` here for exactly this reason: push is one cmpxchg and
/// drain is one xchg, so neither side can block the other and no allocation is
/// involved.
static WAKE_LISTS: [AtomicPtr<Task>; cpu::MAX_CPUS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; cpu::MAX_CPUS];

/// Push `task` onto CPU `cpu`'s deferred-wake list (Linux `llist_add` +
/// `ttwu_queue_wakelist`). Caller IPIs `cpu` after. Lock-free and
/// allocation-free, so it is safe from the timer ISR.
///
/// A task already linked is NOT pushed again: the pending drain will enqueue
/// it, and the second waker set it Runnable before attempting this, so the
/// drain that follows delivers that wake too — coalescing, not losing it. This
/// is Linux's `llist_add` returning false, and it is what stops a double push
/// from overwriting `wake_next` and cycling the list.
/// # C: O(1)
/// # Ctx: any, including hard IRQ
pub fn wake_list_push(cpu: u32, task: Arc<Task>) {
    let i = cpu as usize;
    if i >= cpu::MAX_CPUS { return; }
    if task
        .on_wake_list
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return; // already linked — its pending drain covers this wake
    }
    // Ownership of one strong ref moves into the list here; the drain takes it
    // back out. Nothing else may drop it in between.
    let raw = Arc::into_raw(task) as *mut Task;
    loop {
        let head = WAKE_LISTS[i].load(Ordering::Acquire);
        // SAFETY: `raw` came from `Arc::into_raw` above and is not yet visible to any drain, so this CPU has exclusive access to its `wake_next`.
        unsafe { (*raw).wake_next.store(head, Ordering::Relaxed); }
        if WAKE_LISTS[i]
            .compare_exchange_weak(head, raw, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return;
        }
    }
}

/// Drain CPU `cpu`'s deferred-wake list (Linux `llist_del_all` /
/// `sched_ttwu_pending`). Called from `schedule()` on that CPU. Returns the
/// claimed tasks; the empty fast path allocates nothing.
///
/// Order is LIFO, as Linux's `llist_del_all` also yields — the wake list is a
/// staging area whose members are all made runnable together, so relative order
/// carries no scheduling meaning (the CFS tree re-orders by vruntime anyway).
/// # C: O(deferred)
pub fn wake_list_drain(cpu: u32) -> Vec<Arc<Task>> {
    let i = cpu as usize;
    if i >= cpu::MAX_CPUS { return Vec::new(); }
    let mut node = WAKE_LISTS[i].swap(core::ptr::null_mut(), Ordering::AcqRel);
    if node.is_null() { return Vec::new(); }
    let mut out = Vec::new();
    while !node.is_null() {
        // SAFETY: the swap above claimed the whole chain exclusively, so no other CPU can observe or free these nodes; `next` is read before the Arc is reconstituted.
        let next = unsafe { (*node).wake_next.load(Ordering::Relaxed) };
        // SAFETY: each linked node holds exactly one strong ref put there by `Arc::into_raw` in `wake_list_push`; this takes it back out, once.
        let task = unsafe { Arc::from_raw(node as *const Task) };
        // Released only now that the task is out of the list, so a waker racing
        // here either lost the claim (and the enqueue below carries its wake)
        // or wins it after this and pushes normally.
        task.on_wake_list.store(false, Ordering::Release);
        out.push(task);
        node = next;
    }
    out
}

/// Linux `sched_ttwu_pending`: consume this CPU's wake-list after switch
/// ownership is settled and enqueue each task exactly once. Called both before
/// a pick and from `finish_task_switch`; the latter closes a wake arriving
/// after the pre-pick drain but before the outgoing task clears `on_cpu`.
///
/// The per-task decision is made INSIDE the rq lock, immediately before the
/// enqueue it authorises — Linux's structure exactly (`kernel/sched/core.c`):
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
/// then picks a task another CPU owns. Where Linux waits the switch out with
/// `smp_cond_load_acquire`, this defers to the owner's wake-list instead: an
/// unbounded cross-CPU spin under a held rq lock AB-BA's against a peer
/// balancer wanting this same lock (the `-smp` hang this module's wake-list
/// exists to avoid). Deferral loses no wake — the owner drains it once its own
/// switch settles.
/// # C: O(deferred * log N)
pub fn sched_ttwu_pending(cpu: u32, current: *mut Task, rq: &Runqueue) -> bool {
    let drained = wake_list_drain(cpu);
    if drained.is_empty() { return false; }
    let mut deferred: Vec<Arc<Task>> = Vec::new();
    let mut placed = false;
    let mut preempt = false;
    // SAFETY: `current` is this CPU's running task, kept alive by the runqueue's
    // strong reference for the duration of this drain.
    let curr = if current.is_null() { None } else { Some(cand_of(unsafe { &*current })) };
    {
        let mut inner = rq.inner.lock();
        for task in drained {
            match task.pending_wake(current) {
                PendingWake::Drop  => {}
                PendingWake::Defer => deferred.push(task),
                PendingWake::Ready => {
                    // Sleeper credit on wake (F211).
                    task.set_vruntime_to_floor(inner.cfs.min_vruntime());
                    // Decided AFTER the vruntime lift and BEFORE the enqueue
                    // hands the Arc away, so the fair comparison sees the
                    // position the task was actually queued at.
                    preempt |= curr.is_none_or(|c| wakeup_preempt(cand_of(&task), c));
                    inner.enqueue(task);
                    placed = true;
                }
            }
        }
        rq.publish_nr_running(inner.nr_running());
    }
    // Re-queue still-executing tasks to their owner CPU, outside the rq lock so
    // no reschedule IPI is ever sent from under it.
    for task in deferred {
        let owner = task.cpu.load(Ordering::Acquire) as u32;
        // SAFETY: bounded lookup; an absent old owner cannot drain a list.
        let target = if owner < cpu::MAX_CPUS as u32
            && unsafe { global_for(owner) }.is_some() { owner } else { cpu };
        wake_list_push(target, task);
        resched_curr(target);
    }
    if placed && preempt { resched_curr(cpu); }
    placed
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
    // SAFETY: `global_for` is sound for any index; it yields `None` for a CPU
    // that has not completed `install_global`, which the walk skips.
    select_task_rq_with(&|c| unsafe { global_for(c) }, this_cpu(), task)
}

/// [`select_task_rq`] over an injected CPU->runqueue accessor, so the placement
/// decision is exercised by hosted tests against real `Runqueue` instances on
/// more than one CPU (`GLOBALS` only accepts writes for `this_cpu()`, which is
/// unconditionally 0 off-target). Same split `rq_locate` uses.
/// # C: O(N_cpus)
pub fn select_task_rq_with<'a, F>(get_rq: &F, local: u32, task: &Task) -> u32
where F: Fn(u32) -> Option<&'a Runqueue> {
    let allowed = task.cpus_allowed.load(Ordering::Acquire);
    let prev = task.cpu.load(Ordering::Acquire);
    if prev != u16::MAX {
        let cpu = prev as u32;
        if cpu < 64 && (allowed & (1u64 << cpu)) != 0 {
            if let Some(rq) = get_rq(cpu) {
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
        if let Some(rq) = get_rq(cpu) {
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
/// off any disallowed CPU.
///
/// A task QUEUED (on_rq, not currently running) on a now-disallowed CPU is
/// dequeued here and re-placed by `select_task_rq` — it is not executing, so
/// there is no cross-CPU race. A task RUNNING on a disallowed CPU is only
/// nudged with need_resched plus a reschedule IPI: it cannot be moved while it
/// still owns a CPU's register context. The eviction itself happens when that
/// nudge lands in `schedule()`, which parks the task and lets the incoming
/// task's `finish_task_switch` place it once `on_cpu` has cleared
/// (`live::schedule::migrate`). UP / single CPU: no-op (allowed == local).
/// # C: O(N_cpus · log N)
pub fn relocate_for_affinity(task: &Arc<Task>, allowed: u64) {
    // SAFETY: `global_for` is sound for any index and yields `None` for a CPU
    // that has not completed `install_global`, which the walk skips.
    relocate_for_affinity_with(&|c| unsafe { global_for(c) }, task, allowed)
}

/// Place `task` on `target`, falling back to `fallback` when `target` has no
/// installed runqueue. Returns whether `target` took it.
/// # C: O(log N)
fn enqueue_on_with_fallback<'a, F>(get_rq: &F, target: u32, fallback: u32, task: Arc<Task>) -> bool
where F: Fn(u32) -> Option<&'a Runqueue> {
    if get_rq(target).is_some() {
        return super::rq_locate::enqueue_on_with(get_rq, target, task);
    }
    let _ = super::rq_locate::enqueue_on_with(get_rq, fallback, task);
    false
}

/// [`relocate_for_affinity`] over an injected CPU->runqueue accessor, so the
/// relocation is exercised by hosted tests against real `Runqueue` instances
/// on more than one CPU. Same split [`select_task_rq_with`] uses, and for the
/// same reason: the un-split version reaches only the live per-CPU globals,
/// which off-target exist for CPU 0 alone — that is how the running-task half
/// of this function shipped untested.
/// # C: O(N_cpus · log N)
pub fn relocate_for_affinity_with<'a, F>(get_rq: &F, task: &Arc<Task>, allowed: u64)
where F: Fn(u32) -> Option<&'a Runqueue> {

    let tid = task.tid;
    for cpu in 0..cpu::MAX_CPUS as u32 {
        // Skip CPUs the task is allowed on.
        if cpu < 64 && (allowed & (1u64 << cpu)) != 0 { continue; }
        let rq = match get_rq(cpu) { Some(r) => r, None => continue };
        // Try to dequeue it from this disallowed CPU's runqueue (queued, not
        // running). One rq lock at a time — no nesting, no ordering hazard.
        let removed = {
            let mut inner = rq.inner.lock();
            let r = inner.remove(tid);
            if r.is_some() { rq.publish_nr_running(inner.nr_running()); }
            r
        };
        if let Some(moved) = removed {
            moved.on_rq.store(false, Ordering::Release);
            // Re-place on an allowed CPU (select_task_rq filters by the mask).
            // When the mask names no CPU with an installed runqueue the
            // placement fails, and the task must go back where it came from:
            // affinity is broken before a runnable task is stranded, which is
            // what dropping it here would do — silently and permanently.
            let target = select_task_rq_with(get_rq, this_cpu(), &moved);
            let dest = if enqueue_on_with_fallback(get_rq, target, cpu, moved) { target } else { cpu };
            resched_curr(dest);
        } else {
            // Not queued here — is it the RUNNING task on this disallowed CPU?
            // It cannot be moved while it owns this CPU's register context, so
            // it is nudged instead; `schedule()` parks it and the incoming
            // task's `finish_task_switch` places it on an allowed CPU.
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
    // Linux ttwu's `smp_load_acquire(&p->on_cpu)` (`kernel/sched/core.c`
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
    if force_defer || target != me || task.on_cpu.load(Ordering::Acquire) {
        // Pick a real, installed CPU to own the deferred task; fall back to local.
        let tcpu = if get_rq(target).is_some() { target }
                   else if get_rq(me).is_some() { me }
                   else { wake_list_push(target, task); return; };
        wake_list_push(tcpu, task);
        // Unconditional, and NOT a preemption decision: the target drains its
        // wake list from `schedule()`, so without this the task would never
        // reach a runqueue at all. The preemption decision is made on the
        // drain side, once the task is enqueued and `curr` is known there
        // (`sched_ttwu_pending`).
        resched_curr(tcpu);
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
            let mut inner = rq.inner.lock();
            // Sleeper credit on wake (F211).
            task.set_vruntime_to_floor(inner.cfs.min_vruntime());
            // Linux `ttwu_do_activate` -> `wakeup_preempt`: the wake only takes
            // the CPU away from the running task when the class/policy/priority
            // comparison says it should. Resching unconditionally here made
            // SCHED_FIFO lose the CPU to an equal-priority peer and let a
            // SCHED_BATCH / SCHED_IDLE wakee preempt a SCHED_NORMAL task.
            preempt = curr.is_none_or(|c| wakeup_preempt(cand_of(&task), c));
            inner.enqueue(task);
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

#[cfg(test)]
mod tests;
