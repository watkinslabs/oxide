// `schedule()` per `13§8` + IRQ-exit preempt path per `14§R07`.
//
// Two switch entry points:
//
//   `schedule()`           — voluntary (`yield_to_scheduler`,
//                            `tick_yield`, kthread exit). Picks
//                            next, performs `Context::switch`
//                            in-place. Equivalent to Linux
//                            `schedule()` from process context.
//
//   `schedule_from_irq()`  — IRQ-exit picker. Picks next + stages
//                            `(prev, next)` in
//                            `oxide_preempt_{cur,next}_ctx` for
//                            the asm tail to perform via
//                            `oxide_context_switch` before iretq /
//                            eret. `13§9` "preempt-on-IRQ-exit".
//
// Both paths share the same `pick_next_task` algorithm and the
// same `if next.mm != prev.mm: switch_address_space(...)` AS-swap
// hook (`13§8`). With v1's single global user AS + kthreads
// having `mm=None`, the AS-swap branch is currently exercised
// only when a kthread→user-task pair shares the runqueue. The
// hook itself is wired via `MmuOps::activate(next.mm.root_pa)`
// landed in P2-19.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use hal::{Context, MmuOps};
use sched::{RunqueueInner, SchedClass, Task, TaskState};

use super::runqueue::{global, install_global, uninstall_global, Runqueue};

#[cfg(target_arch = "x86_64")]
type ArchCtx = hal_x86_64::ContextX86_64;
#[cfg(target_arch = "aarch64")]
type ArchCtx = hal_aarch64::ContextAArch64;

#[cfg(target_arch = "x86_64")]
type ActiveMmu = hal_x86_64::mmu_ops::X86Mmu;
#[cfg(target_arch = "aarch64")]
type ActiveMmu = hal_aarch64::mmu_ops::ArmMmu;

/// Aggregate metrics returned by `uninstall_global_with_stats`,
/// for smoke-driver bookkeeping.
#[derive(Copy, Clone, Debug, Default)]
pub struct RunStats {
    pub yields_total:       u32,
    pub voluntary_switches: u32,
    pub irq_switches:       u32,
}

/// Per docs/13§8 `update_vruntime(prev)`: advance the prev task's
/// vruntime past the current `min_vruntime` so the next CFS pick
/// rotates among the runnable peers per invariant 5. v1 uses a
/// fixed delta of 1 (no real time accounting yet); a future
/// `timer_tick` integration will scale by `wall_dt / weight` per
/// `13§3`. The bump runs before pick + before re-enqueue so the
/// re-keyed insert lands at the correct sorted position.
fn update_vruntime_prev(prev: &Task, inner: &RunqueueInner) {
    if !matches!(prev.class, SchedClass::Normal { .. }) { return; }
    let cur = prev.vruntime.load(Ordering::Acquire);
    let floor = inner.cfs.min_vruntime();
    let new = core::cmp::max(cur, floor).saturating_add(1);
    prev.vruntime.store(new, Ordering::Release);
}

/// Build the per-CPU idle Task per `13§2` invariant 7. v1 idle
/// doubles as the **boot anchor**: its `arch_ctx` is left zeroed,
/// so the first `Context::switch(prev=idle, next=kthreadN)` from
/// the boot path saves boot's live registers into idle's
/// `arch_ctx`. When every other kthread is `done` and the picker
/// falls through to idle, the matching switch loads those saved
/// regs and resumes in boot — the smoke harness exits cleanly.
///
/// A future "real production idle" (hlt-loop kthread) lives behind
/// the same slot once full process scheduling lands; the boot-
/// anchor flavor is sufficient for v1's smoke-driven runqueue.
fn build_idle_task(cpu: u16) -> Arc<Task> {
    Arc::new(Task::new(cpu as u32 * 0x1_0000, "idle", SchedClass::Idle))
}

/// Install the per-CPU runqueue and its idle task. Must run before
/// any `spawn_kernel_thread` / `schedule()`.
/// # SAFETY: caller is the boot path; allocator up; single-CPU
/// pre-init; no kthread or IRQ has yet observed `GLOBAL`.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn install_default_runqueue() {
    let idle = build_idle_task(0);
    let rq = Runqueue::new(0, idle);
    // SAFETY: per fn contract; first writer wins.
    unsafe { install_global(rq); }
}

/// True iff the global runqueue is installed.
/// # C: O(1)
pub fn runqueue_active() -> bool { global().is_some() }

/// Borrow `current` task. Returns `None` if no runqueue is up
/// (boot phase before `install_default_runqueue`).
/// # C: O(1)
pub fn current() -> Option<&'static Task> {
    let rq = global()?;
    // SAFETY: borrow is short-lived; current is non-null after
    // install; the underlying Arc strong ref keeps the task alive
    // until the next swap_current.
    Some(unsafe { rq.current_ref() })
}

/// Counters incremented by the schedule paths. Hosted-test access
/// via the `RunStats` snapshot returned from teardown.
static VOLUNTARY: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static IRQ_SW:    core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Voluntary `schedule()` per `13§8`. Saves the current task's
/// context, picks next, performs the AS-swap if `next.mm !=
/// prev.mm`, runs `Context::switch`. Returns to the caller (via
/// the saved RIP/LR) when something else schedules us back.
///
/// Lock-held-across-switch (`13§8`): we acquire the inner spinlock
/// to do the pick + class-list fixup, drop it before `Context::
/// switch` (UP v1 — no concurrent CPU could observe a stale
/// runqueue state). SMP wraps this in the lock-cross-switch
/// primitive per `13§12` later.
///
/// # SAFETY: caller is in process / kthread context (NOT IRQ);
/// preempt-off discipline (`13§9`); single-CPU.
/// # C: O(log N) CFS pick + O(1) ctx switch
/// # Ctx: process|kthread; preempt-off
pub unsafe fn schedule() {
    let rq = match global() { Some(r) => r, None => return };

    // Pick next under the lock.
    let next_arc = {
        let mut inner = rq.inner.lock();
        // SAFETY: rq.current is non-null after install_global.
        let prev_ref = unsafe { rq.current_ref() };
        // Re-enqueue the current runnable task (unless it's idle
        // or marked done) so the picker can return to it later.
        if !matches!(prev_ref.class, SchedClass::Idle)
            && prev_ref.state() == TaskState::Runnable
        {
            // The current task isn't on the class list while it's
            // running. Re-insert before pick so RR/CFS rotates
            // among all runnable peers.
            // SAFETY: prev_ref's Arc is owned by rq.current; we
            // synthesise a fresh strong ref by cloning the raw ptr
            // through Arc::increment_strong_count for the enqueue.
            let raw = rq.current.load(Ordering::Acquire);
            // SAFETY: raw came from Arc::into_raw; bumping the strong count is sound.
            unsafe { Arc::increment_strong_count(raw); }
            // SAFETY: same raw → matching Arc::from_raw reclaims that bumped strong ref into a fresh Arc.
            let cloned = unsafe { Arc::from_raw(raw) };
            inner.enqueue(cloned);
        }
        let n = inner.pick_next_task();
        rq.nr_running.store(inner.nr_running(), Ordering::Release);
        n
    };

    // No-op if we picked the same task back.
    let next_raw = Arc::as_ptr(&next_arc) as *mut Task;
    let prev_raw = rq.current.load(Ordering::Acquire);
    if next_raw == prev_raw {
        return;
    }

    // AS-swap hook per `13§8`. Compare Arc pointers — equal Arc
    // means identical AS (kthreads share `mm = None`; user tasks
    // in v1 share the single global Arc<AddressSpace>).
    // SAFETY: prev_raw is non-null after install_global.
    let prev_ref = unsafe { &*prev_raw };
    let prev_root = prev_ref.mm.as_ref().map(|a| a.root_pa()).unwrap_or(0);
    let next_root = next_arc.mm.as_ref().map(|a| a.root_pa()).unwrap_or(0);
    if next_root != 0 && next_root != prev_root {
        // SAFETY: root_pa is the AS-private root populated with kernel-half mappings per P2-19; activate writes CR3/TTBR0 + flushes user TLB; preempt-off + single-CPU.
        unsafe { ActiveMmu::activate(next_root); }
    }

    // Pointers for the asm switch BEFORE we mutate `current`.
    // SAFETY: prev_ref aliases the prev Task's arch_ctx buffer storage; per-active-CPU single-mutator invariant from `13§5` keeps this sound.
    let prev_ctx_ptr: *mut ArchCtx = unsafe { prev_ref.arch_ctx_ptr::<ArchCtx>() };
    // SAFETY: next_arc aliases the next Task's arch_ctx; will be active on this CPU after swap_current; size fits per compile-time assert.
    let next_ctx_ptr: *const ArchCtx = unsafe { next_arc.arch_ctx_ptr::<ArchCtx>() };

    // Commit the swap. swap_current returns the old Arc; drop
    // happens after the switch returns into us next time so the
    // current Task's stack remains live across the asm.
    // SAFETY: caller asserts preempt-off; we are about to context-switch off this Task. Until that completes the prev Arc must remain alive — store it in a function-local where its destructor runs only on the eventual return.
    let prev_arc = unsafe { rq.swap_current(next_arc) };
    VOLUNTARY.fetch_add(1, Ordering::Relaxed);

    // Update the per-CPU TSS so future ring-3→ring-0 transitions
    // for the next kthread/user task land on its kernel stack.
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: rq.current was just updated to the new Arc<Task> by swap_current; its strong ref is held in the AtomicPtr.
        let now = unsafe { rq.current_ref() };
        let top = now.kernel_stack.load(Ordering::Acquire);
        if !top.is_null() {
            // SAFETY: top is the next task's top-of-stack; set_rsp0 writes the RSP0 field of the live TSS, used by ring-3→ring-0 transitions per `14§3`.
            unsafe { hal_x86_64::set_rsp0(top as u64); }
        }
    }

    // Perform the actual register dance.
    // SAFETY: prev_ctx_ptr aliases prev's arch_ctx buffer (kept alive by `prev_arc` until after switch returns); next_ctx_ptr aliases next's arch_ctx (kept alive by the new `current` Arc); both buffers were init'd via `new_kernel_with_irq_frame`. switch saves prev's regs, loads next's, returns on prev's stack when control comes back.
    unsafe { ArchCtx::switch(prev_ctx_ptr, next_ctx_ptr); }

    // Control resumes here when something switches back to prev.
    // Drop prev_arc: by now it's already been re-enqueued (above)
    // OR is the idle task (boot frame's idle), so dropping our
    // local strong ref is safe.
    drop(prev_arc);
}

/// IRQ-exit preempt picker per `14§R07`. Called from the per-arch
/// IRQ dispatcher (`lapic` / `gic`) after EOI. If a switch is
/// warranted, stages the `(prev_ctx, next_ctx)` pointer pair in
/// `oxide_preempt_{cur,next}_ctx` so the asm tail performs
/// `oxide_context_switch` before `iretq` / `eret`.
///
/// # SAFETY: caller is the IRQ dispatcher running with IRQs masked;
/// single-CPU pre-init; runqueue may or may not be installed.
/// # C: O(log N) CFS pick when active; O(1) early-exit otherwise
/// # Ctx: IRQ
pub unsafe fn schedule_from_irq() {
    let rq = match global() { Some(r) => r, None => return };

    let next_arc = {
        let mut inner = rq.inner.lock();
        // SAFETY: holding the inner lock serialises against any other writer; current ptr is stable for this critical section per `13§2` invariant 2.
        let prev_ref = unsafe { rq.current_ref() };
        // `update_vruntime(prev)` per `13§8` so the next CFS pick
        // rotates rather than re-selecting `prev`.
        update_vruntime_prev(prev_ref, &inner);
        if !matches!(prev_ref.class, SchedClass::Idle)
            && prev_ref.state() == TaskState::Runnable
        {
            let raw = rq.current.load(Ordering::Acquire);
            // SAFETY: raw came from Arc::into_raw via swap_current / install_global; bumping the strong count is sound.
            unsafe { Arc::increment_strong_count(raw); }
            // SAFETY: matching from_raw reclaims the bumped count.
            let cloned = unsafe { Arc::from_raw(raw) };
            inner.enqueue(cloned);
        }
        let n = inner.pick_next_task();
        rq.nr_running.store(inner.nr_running(), Ordering::Release);
        n
    };

    let next_raw = Arc::as_ptr(&next_arc) as *mut Task;
    let prev_raw = rq.current.load(Ordering::Acquire);
    if next_raw == prev_raw {
        return;
    }

    // AS-swap hook per `13§8`. Same logic as voluntary path; the
    // CR3/TTBR write happens before the asm tail's
    // `oxide_context_switch`.
    // SAFETY: prev_raw came from rq.current AtomicPtr (non-null after install_global); strong ref held by current AtomicPtr keeps the pointee alive for this critical section.
    let prev_ref = unsafe { &*prev_raw };
    let prev_root = prev_ref.mm.as_ref().map(|a| a.root_pa()).unwrap_or(0);
    let next_root = next_arc.mm.as_ref().map(|a| a.root_pa()).unwrap_or(0);
    if next_root != 0 && next_root != prev_root {
        // SAFETY: root_pa is the AS-private root populated with kernel-half mappings per P2-19; activate writes CR3/TTBR0 + flushes user TLB; IRQs masked + single-CPU.
        unsafe { ActiveMmu::activate(next_root); }
    }

    // SAFETY: prev_ref aliases prev Task's arch_ctx; per `13§5` single-mutator-per-active-CPU invariant; we are mid-IRQ-exit so no other reader exists.
    let prev_ctx_ptr: *mut u8 = unsafe { prev_ref.arch_ctx_ptr::<ArchCtx>() } as *mut u8;
    // SAFETY: next_arc aliases next Task's arch_ctx; once installed via swap_current it becomes the active-CPU's mutator.
    let next_ctx_ptr: *mut u8 = unsafe { next_arc.arch_ctx_ptr::<ArchCtx>() } as *mut u8;

    // Commit `current` swap; drop returned Arc on the next
    // `schedule_from_irq` callback (held by re-enqueue).
    // SAFETY: per fn contract; runqueue serial under IRQs-masked single-CPU.
    let prev_arc = unsafe { rq.swap_current(next_arc) };
    drop(prev_arc);
    IRQ_SW.fetch_add(1, Ordering::Relaxed);

    // Update TSS RSP0 for the new task so future ring-3 traps
    // land on its kernel stack.
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: rq.current was updated to the new Arc<Task> by swap_current; strong ref held in AtomicPtr.
        let now = unsafe { rq.current_ref() };
        let top = now.kernel_stack.load(Ordering::Acquire);
        if !top.is_null() {
            // SAFETY: top is the next task's top-of-stack; set_rsp0 writes RSP0 of the live TSS used by ring-3→ring-0 transitions per `14§3`.
            unsafe { hal_x86_64::set_rsp0(top as u64); }
        }
    }

    // Stage the pointer pair for the asm IRQ epilogue.
    crate::preempt::oxide_preempt_cur_ctx.store(prev_ctx_ptr, Ordering::Release);
    crate::preempt::oxide_preempt_next_ctx.store(next_ctx_ptr, Ordering::Release);
}

/// Cooperative voluntary yield. Bumps a counter, calls
/// `schedule()`. Equivalent to Linux `schedule()` from
/// process context. Used by kthread "I'm done, give boot back"
/// paths and by smoke harnesses.
/// # SAFETY: per `schedule()`.
/// # C: O(log N) + O(1) ctxsw
/// # Ctx: process|kthread; preempt-off
pub unsafe fn tick_yield() {
    // SAFETY: caller satisfies `schedule()`'s contract (process / kthread context, preempt-off, single-CPU); delegated wholesale.
    unsafe { schedule(); }
}

/// Mark a task `done` (Zombie state). Subsequent `schedule()` /
/// `schedule_from_irq()` won't return to it because the
/// re-enqueue gate (`state() == Runnable`) becomes false.
/// # C: O(1)
pub fn mark_done(task: &Task) {
    task.set_state(TaskState::Zombie);
}

/// Tear down the global runqueue and return run stats. Used by
/// smoke harnesses that install a transient runqueue.
/// # SAFETY: caller is the boot path post-run; no kthread is
/// current; IRQs masked.
/// # C: O(N_tasks) drop
pub unsafe fn uninstall_global_with_stats() -> Option<RunStats> {
    // SAFETY: caller is boot path post-run; no kthread is current; IRQs masked; uninstall_global delegates the same invariants.
    let _ = unsafe { uninstall_global() }?;
    let stats = RunStats {
        yields_total:       VOLUNTARY.swap(0, Ordering::AcqRel),
        voluntary_switches: 0, // populated below
        irq_switches:       IRQ_SW.swap(0, Ordering::AcqRel),
    };
    let mut s = stats;
    s.voluntary_switches = s.yields_total;
    Some(s)
}
