use super::*;

/// Live monotonic clock in ns. Host builds (unit tests) return 0 - the
/// pure accounting math is tested directly in `cputime`.
/// # C: O(1)
#[inline]
pub fn now_ns() -> u64 {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// `update_curr(prev)` per `13§3`/`13§8`: charge the CPU time the prev
/// task just consumed (the complete positive `now - exec_start`) to its
/// `sum_exec_runtime`, advance its vruntime by that delta scaled by
/// load weight (heavier/lower-nice -> slower vruntime -> more CPU), and
/// re-stamp exec_start. The vruntime advance is floored at
/// `min_vruntime + 1` so the CFS re-key always moves forward - without
/// that, two schedules within one clock tick (delta 0) would re-insert
/// prev at its old key and the BTreeMap tiebreak (lower tid) would
/// re-select it, starving higher-tid peers (the F144 rotation bug).
/// Runs before pick + re-enqueue so the re-keyed insert sorts correctly.
pub fn update_curr(prev: &Task, inner: &RunqueueInner, now: u64) {
    prev.update_util(now, true);
    // The deadline class charges wall time against a budget, not vruntime
    // against a weight, so it has its own accounting (`deadline::live`). Doing
    // it HERE — on every schedule-out, not only on the periodic tick — is what
    // stops a task that blocks between ticks from running unaccounted.
    if matches!(prev.sched_class(), SchedClass::Deadline) {
        let _ = crate::deadline::live::update_curr_dl(prev, now);
        return;
    }
    // The scheduler-runtime charge is CLASS-INDEPENDENT: fair, RT and deadline
    // all fold the elapsed slice into the same per-task total, because
    // `CLOCK_THREAD_CPUTIME_ID` and its process-wide sibling sample THAT
    // total. Only the idle class runs unaccounted. Restricting the charge to
    // the fair class left every SCHED_FIFO/SCHED_RR thread's CPU clock frozen
    // at zero. The vruntime advance below is fair-only, so the two parts are
    // gated separately.
    let start = prev.sched.se.exec_start.load(Ordering::Acquire);
    if start == 0 {
        prev.sched.se.exec_start.store(now, Ordering::Release);
        return;
    }
    if now < start { return; }
    let delta = crate::cputime::runtime_delta(now, start);
    if !crate::cputime::accounts_exec_runtime(prev.sched_class()) { return; }
    if delta != 0 {
        crate::cputime::charge_exec_runtime(prev, delta);
        // Same ns, charged to the CPU that burned it, for CPU-context
        // `PERF_COUNT_SW_TASK_CLOCK` (Linux `task_clock_event_update`).
        crate::perf_sw::charge(crate::perf_sw::CpuSw::ExecNs,
            prev.cpu.load(Ordering::Acquire) as usize, delta);
    }
    if !matches!(prev.sched_class(), SchedClass::Normal { .. }) {
        prev.sched.se.exec_start.store(now, Ordering::Release);
        return;
    }
    let load = prev.sched.se.load.snapshot().weight;
    let vdelta = crate::cputime::vruntime_delta(delta, load).max(1);
    let cur = prev.sched.se.vruntime.load(Ordering::Acquire);
    let floor = inner.cfs.min_vruntime_for(prev);
    let base = if crate::cfs::vruntime_before(cur, floor) { floor } else { cur };
    let new = base.wrapping_add(vdelta);
    prev.sched.se.vruntime.store(new, Ordering::Release);
    prev.sched.se.exec_start.store(now, Ordering::Release);
}

/// Clear the previous switch's outgoing-task `on_cpu` handoff before the slot
/// is reused. This mirrors Linux `finish_task_switch(prev)`: a later wake must
/// be able to see that the old task is no longer executing.
/// # SAFETY: caller runs on this runqueue's CPU in scheduler context.
/// # C: O(1)
unsafe fn finish_switched_from(rq: &Runqueue) -> bool {
    let from = rq.switched_from.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !from.is_null() {
        // SAFETY: `from` is the scheduler handoff pointer stored by schedule(); this debug read only validates the Task sentinel before the handoff write.
        unsafe { (*from).debug_check_canary("finish_switched_from"); }
        // SAFETY: `from` was stored by schedule() before a context switch; the
        // outgoing task is kept alive by the switcher's frame or task registry.
        unsafe { (&(*from)).on_cpu.store(false, Ordering::Release); }
        // SAFETY: the same live outgoing Task remains owned through unlock.
        return unsafe { (&*from).kthread_parked.load(Ordering::Acquire) };
    }
    false
}

/// Complete the lock/ownership half of a switch handoff exactly once.
///
/// Normally the incoming task reaches this through its first-run trampoline
/// or immediately after `Context::switch` returns.  A task can, however,
/// reach another blocking `schedule()` before that tail hook (the live ext4
/// fault reproduction does exactly this).  `switched_from` is the pending
/// token: clearing only `on_cpu` while leaving the forgotten rq guard locked
/// makes that next schedule spin forever on its own CPU.
///
/// # SAFETY: caller runs on `rq`'s CPU; a non-null handoff token denotes the
/// one forgotten `rq.inner` guard installed by the preceding switch.
/// # C: O(1)
pub unsafe fn finish_lock_switch_pending(rq: &Runqueue) -> bool {
    if rq.switched_from.load(Ordering::Acquire).is_null() { return false; }
    // SAFETY: the non-null token proves a preceding switch still owns both
    // the outgoing-task handoff and its forgotten rq guard.
    let notify_park = unsafe { finish_switched_from(rq) };
    // SAFETY: paired 1:1 with that switch's lock()+mem::forget guard.
    unsafe { rq.inner.raw_unlock(); }
    // Wake park controllers only after rq unlock; waking one can enqueue it
    // and therefore must not recurse into this runqueue's raw lock.
    if notify_park { crate::live::kthread::note_schedule_out(); }
    true
}

/// Linux `finish_task_switch` / `schedule_tail`: the INCOMING task runs this
/// after the switch. It (1) releases the rq-lock the switcher held across the
/// switch, (2) drops the `preempt_count` the switcher bumped before any
/// deferred destructor can sleep, and (3) drains deferred mm/reap work.
/// # C: O(1) excluding deferred destruction
#[no_mangle]
pub unsafe extern "C" fn oxide_finish_task_switch() {
    sync::note_qs();
    let Some(rq) = global() else { return };
    if rq.switched_from.load(Ordering::Acquire).is_null() { return; }
    // A duplicate/delayed tail has no handoff debt. In particular, if
    // schedule() repaired the pending switch before blocking again, a later
    // stale tail must not unlock a new owner's rq guard or decrement its
    // preempt count a second time.
    // SAFETY: finish_task_switch runs on this runqueue's incoming task.
    crate::live::schedule::provenance::finish(b"before-rq-release", 2);
    crate::live::schedule::provenance::normalize_finish();
    // SAFETY: `switched_from` proves this incoming task owns the forgotten
    // runqueue guard published by the immediately preceding context switch.
    if !unsafe { finish_lock_switch_pending(rq) } { return; }
    #[cfg(feature = "debug-preempt")]
    crate::live::schedule::provenance::finish(b"after-rq-release", 1);
    // rq.inner is no longer held, so consume the scheduler's preempt debt
    // before any deferred destructor can block. This kernel's lazy-mm release
    // can synchronously write back file-backed VMAs; leaving the debt live
    // made its valid block look atomic and corrupted the nested switch count.
    crate::preempt::preempt_enable_no_check();
    #[cfg(feature = "debug-preempt")]
    crate::live::schedule::provenance::finish(b"after-sched-release", 0);
    // The deferred mm can run file-backed VMA destruction and synchronous
    // writeback. The helper above has released rq.inner, matching the required
    // finish-switch ordering before a potentially sleeping final mmdrop, and
    // the preempt debt above is also settled before it can call schedule.
    active_mm_finish_drop(rq);
    {
        // Linux `finish_task_switch()` order: `finish_task(prev)` — the
        // `smp_store_release(&prev->on_cpu, 0)` — runs BEFORE
        // `finish_lock_switch(rq)` releases the rq lock. Linux
        // states the rule outright: "p->on_cpu ... is set by prepare_task() and
        // cleared by finish_task() such that it will be set before p is
        // scheduled-in and cleared after p is scheduled-out, BOTH UNDER
        // rq->lock". Releasing first opened a window in which this rq's class
        // tree held the outgoing task (re-enqueued by `schedule()` while still
        // Runnable) with `on_cpu` still set: a peer CPU parked in
        // `newidle_balance` spinning on this very lock takes it the instant it
        // drops, steals that task, and picks it — tripping the ownership claim
        // in `schedule()` ("selected task already owned by another CPU").
        //
        // Also write `switched_from->on_cpu = false` BEFORE draining
        // reap_pending, while the outgoing task is still alive. For a
        // self-reaping non-leader thread exit the outgoing task
        // (switched_from) IS the reap_pending task; draining reap_pending below
        // drops its last Arc and frees it, so doing the on_cpu write AFTER the
        // drain would store `false` (0) through a raw pointer into freed — then
        // reused — memory (a use-after-free that scribbles whatever object the
        // allocator later placed in that Task's slot: BTree node, Vec buffer,
        // dcache Weak, VMA, etc. — the ~55s live-gnome heap-corruption
        // blocker). reap_pending still holds the Arc here, so the task is
        // guaranteed live.
        // Place any task the switch we just completed evicted for affinity.
        // Here — not in `schedule()` — because here the outgoing task's
        // `on_cpu` is clear (so no other CPU can pick a task this one is still
        // executing) and this CPU holds no runqueue lock (so taking the
        // destination's lock nests nothing).
        crate::live::schedule::migrate::place_parked(sched_current_cpu() as u32);
        let raw = rq.reap_pending.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !raw.is_null() {
            // SAFETY: `raw` came from `Arc::into_raw` in schedule()'s zombie path; reclaim it and hand ownership to ZOMBIES.
            let dying = unsafe { Arc::from_raw(raw) };
            // A kernel thread's joiner may free the thread's stack the instant
            // it observes the exit, so the exit is published HERE — on the
            // incoming task, after the switch — and never by the dying thread,
            // which is still executing on that stack until this point.
            crate::live::kthread::note_kthread_exited(&dying);
            // Linux `put_task_stack()` in `finish_task_switch`: the task is off
            // this CPU for the last time, so its stack is dead storage from
            // here. Released now rather than when the last `Arc<Task>` drops,
            // so an unreaped zombie does not pin 16 KiB and so reaping can
            // never free a stack a task is still running on.
            dying.release_kernel_stack();
            // The exit notification is NOT here. Linux runs `exit_notify` in
            // `do_exit`, on the dying task's own stack, before its final
            // schedule — `live::mark_done` does the same. Running it here made
            // every path in the kernel that can block carry the depth of the
            // notification and of the teardown its registry snapshot opens.
            // What is left is the hand-off: the reference goes to the drainer
            // (Linux `put_task_struct_rcu_user`), never dropped under whichever
            // task the scheduler just switched to.
            crate::live::zombies::reclaim::defer_release(dying);
        }
    }
    // Linux `schedule_tail`'s trailing `put_user(task_pid_vnr(current),
    // current->set_child_tid)`: the ONE point at which a freshly forked child
    // is running on its OWN page tables and can service the copy-on-write fault
    // its C library's thread-control-block store takes. Deliberately after the
    // preempt-enable above, since the store may sleep on that fault. Costs one
    // relaxed load per switch for every task that is not a fork return.
    publish_forked_child_tid();
    membarrier_sync_core_before_usermode();
}

/// The half of `MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE` the barrier IPI
/// cannot deliver.
///
/// That round only reaches CPUs that were RUNNING a thread of the mm. A thread
/// descheduled at the time takes no IPI, so it would otherwise resume user mode
/// with instructions it fetched before the code was rewritten still in flight.
/// Here the switch has completed, the incoming mm is known, and no user
/// instruction of it has executed yet.
///
/// Costs one relaxed load per switch for a mm that never registered. No-op on
/// aarch64, whose `eret` is already a context synchronization event.
/// # C: O(1)
fn membarrier_sync_core_before_usermode() {
    let Some(cur) = crate::live::current() else { return };
    // SAFETY: membarrier_sync_core_before_usermode reads the running task's
    // own mm slot from the task executing this switch tail; only execve/exit
    // on THIS task replace it, and neither runs concurrently with this return.
    let Some(mm) = (unsafe { cur.mm_ref() }) else { return };
    crate::membarrier::sync_core_before_usermode(mm.membarrier_sync_core_before_usermode());
}

/// Perform the parked `CLONE_CHILD_SETTID` store, if this task owes one.
/// # C: O(1)
fn publish_forked_child_tid() {
    let Some(cur) = crate::live::current() else { return };
    let Some((addr, tid)) = cur.take_set_child_tid() else { return };
    // This CPU runs on the child's own page tables here, so the store lands in
    // the address space that owns the mapping and a copy-on-write fault
    // resolves normally in process context. The address is caller-supplied and
    // never validated, so it goes through the faulting path and an unwritable
    // destination is dropped rather than turned into a fault.
    let _ = uaccess::copy_to_user(addr, &(tid as i32).to_le_bytes());
}
