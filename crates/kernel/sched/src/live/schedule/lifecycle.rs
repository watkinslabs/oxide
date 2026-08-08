use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::{SchedClass, Task};

use super::hooks::RunStats;
use super::switch::schedule;
use crate::live::runqueue::{global, install_global, uninstall_global, Runqueue};

/// Counters incremented by the schedule paths. Hosted-test access
/// via the `RunStats` snapshot returned from teardown.
pub(super) static VOLUNTARY: AtomicU32 = AtomicU32::new(0);

/// Build the per-CPU idle Task per `13§2` invariant 7. v1 idle
/// doubles as the boot anchor: its `arch_ctx` is left zeroed,
/// so the first `Context::switch(prev=idle, next=kthreadN)` from
/// the boot path saves boot's live registers into idle's
/// `arch_ctx`. When every other kthread is `done` and the picker
/// falls through to idle, the matching switch loads those saved
/// regs and resumes in boot - the smoke harness exits cleanly.
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
    if global().is_some() { return; }
    let cpu = {
        use hal::CpuOps;
        #[cfg(target_arch = "x86_64")]
        { hal_x86_64::X86CpuOps::current_cpu() as u16 }
        #[cfg(target_arch = "aarch64")]
        { hal_aarch64::ArmCpuOps::current_cpu() as u16 }
    };
    let idle = build_idle_task(cpu);
    let rq = Runqueue::new(cpu, idle);
    // SAFETY: per fn contract; first writer wins; we just confirmed `global().is_none()`.
    unsafe { install_global(rq); }
    // SAFETY: install_default_runqueue is the per-CPU bring-up path; preempt_enable hook is read at every decrement-to-zero with appropriate barriers via the count atomic.
    unsafe { crate::preempt::set_schedule_hook(schedule_hook_trampoline); }
    #[cfg(feature = "debug-smp")]
    sync::set_spin_warn_hook(smp_spin_warn);
    // `register_timers`'s body wires kernel-only tick owners (cgroup bandwidth,
    // orphan reap, RCU drain, mount expiry), so it exists only on the kernel
    // target; a hosted runqueue install has no timer subsystem to register with.
    #[cfg(target_os = "oxide-kernel")]
    crate::register_timers();
}

/// `debug-smp` spin-stall reporter installed into `sync`: emit a [SMP-STALL]
/// banner naming the contended lock CLASS rank, the spin count, and this CPU -
/// so a -smp boot that still wedges names the vertex the conservative wake-path
/// fix missed. # C: O(1)
#[cfg(feature = "debug-smp")]
fn smp_spin_warn(rank: u16, iters: u64) {
    klog::write_raw(b"[SMP-STALL] lock_class_rank=");
    klog::write_dec_u64(rank as u64);
    klog::write_raw(b" spin_iters=");
    klog::write_dec_u64(iters);
    klog::write_raw(b" cpu=");
    klog::write_dec_u64(super::active_mm::sched_current_cpu() as u64);
    klog::write_raw(b"\n");
}

/// Trampoline matching the `unsafe fn()` shape `crate::preempt`
/// expects. Forwards to `schedule()` proper.
///
/// # SAFETY: caller (`preempt_enable`) asserts a safe schedule
/// point per `13§9`: process / kthread context, no spinlocks held.
/// # C: O(log N) CFS pick + O(1) ctx switch
unsafe fn schedule_hook_trampoline() {
    // SAFETY: per fn contract; schedule() preconditions match preempt_enable's "safe schedule point" guarantee.
    unsafe { schedule(); }
}

/// True iff the global runqueue is installed.
/// # C: O(1)
pub fn runqueue_active() -> bool { global().is_some() }

/// Borrow `current` task. Returns `None` if no runqueue is up
/// (boot phase before `install_default_runqueue`).
/// # C: O(1)
pub fn current() -> Option<&'static Task> {
    let rq = global()?;
    // SAFETY: borrow is short-lived; current is non-null after install; the underlying Arc strong ref keeps the task alive until the next swap_current.
    Some(unsafe { rq.current_ref() })
}

/// Current task's mount-namespace id (0 if no current task).
/// # C: O(1)
pub fn current_mount_ns() -> u64 {
    current().and_then(Task::mount_namespace_id).unwrap_or(0)
}

/// Current task's chroot root path, or None when it is "/" or no current.
/// # C: O(1) + clone
pub fn current_chroot_root() -> Option<String> {
    let c = current()?;
    let r = c.fs_context_snapshot().root();
    if r == "/" { None } else { Some(r) }
}

/// Retire the running task: notify, then publish Zombie state.
///
/// Linux `do_exit`'s tail — `exit_notify(tsk, group_dead)` and then
/// `do_task_dead()`. Both happen on the dying task's OWN stack, before its
/// final schedule, and both of this kernel's retirement sites (`sys_exit` and
/// fatal-signal termination) already run there.
///
/// The notification used to run on the context-switch tail instead, which put
/// it — and the whole task teardown its registry snapshot can open — on the
/// stack of every path in the kernel that can block: 3.3 KiB of a 13 KiB
/// aarch64 budget, charged to callers with nothing to do with task exit. The
/// hazard that forced it there is gone: the kernel stack is now released by the
/// switch tail rather than by the reaper (`Task::release_kernel_stack`), so a
/// parent that reaps the instant the zombie is published cannot free a stack
/// this task is still running on. The task itself stays alive across the
/// notification because the runqueue holds a reference to the running task,
/// exactly as `rq->curr` does.
///
/// Ordering: notify BEFORE `Task::mark_done`, which releases the namespaces the
/// reaper lookup and the orphaned-process-group walk read. The reference has
/// the same order — `exit_notify` runs while the namespaces are still live.
/// # C: O(threads in group) + notification
/// # Ctx: the dying task, on its own stack
pub fn mark_done(task: &Task) {
    exit_notify(task);
    task.mark_done();
}

/// Linux `exit_notify`: publish the group exit so `wait4` can see it, and hand
/// the orphaned process group its POSIX hangup.
///
/// Takes its own reference through the task registry rather than reconstructing
/// one from a raw pointer: this kernel has already paid once for hand-rolled
/// `Arc` refcount machinery in the scheduler, and the registry is how every
/// other subsystem obtains a task reference. A task with no registry entry has
/// nothing to notify — it was never published.
/// # C: O(threads in group)
fn exit_notify(task: &Task) {
    let Some(task) = crate::registry::lookup(task.tid) else { return };
    let group = alloc::sync::Arc::clone(&task.thread_group);
    match group.finish_exit(task) {
        crate::thread_group::ExitDisposition::WaitableLeader(leader) => {
            super::super::zombies::enqueue_zombie(leader);
        }
        crate::thread_group::ExitDisposition::AlreadyRetired
        | crate::thread_group::ExitDisposition::ReleasedThread
        | crate::thread_group::ExitDisposition::DeferredLeader => {}
    }
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
        voluntary_switches: 0,
        irq_switches:       0,
    };
    let mut s = stats;
    s.voluntary_switches = s.yields_total;
    Some(s)
}
