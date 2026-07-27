//! Per-CPU `ksoftirqd` kthreads, per Linux `kernel/softirq.c`
//! (`run_ksoftirqd` / `wakeup_softirqd`, registered per-CPU via smpboot). One
//! thread per online CPU, each PINNED to its CPU (`cpus_allowed`), draining
//! ONLY that CPU's softirq pending mask in PROCESS context when the IRQ-tail
//! restart gate (`softirq::run_pending`) defers under load — e.g. a virtio-net
//! RX flood re-arming `Slot::NetRx` on that CPU. The per-CPU IRQ-tail drain
//! (lapic/gic) still runs on every CPU each tick; ksoftirqd is the
//! schedulable, preemptible drainer the gate hands the remainder to, so a
//! flood can't monopolise a CPU.
use super::WaitList;
use core::sync::atomic::Ordering;
use cpu::MAX_CPUS;

/// Per-CPU park lists — `WAIT[n]` holds CPU n's ksoftirqd while idle. `wake()`
/// (the softirq `wakeup_softirqd` hook) rouses the CURRENT CPU's thread, so a
/// deferral on CPU n wakes ksoftirqd/n, which (pinned to n) drains n's mask.
static WAIT: [WaitList; MAX_CPUS] = [const { WaitList::new() }; MAX_CPUS];
/// Missed-wakeup safety net. The wake site can fire in the window between a
/// thread's `pending()` check and `park()`, and `try_to_wake_up` can't
/// self-wake a still-running task (it spins on `on_cpu`). A deadline re-check
/// closes that race — same idiom as `ktimers`. The per-CPU IRQ-tail drainer
/// keeps each mask moving meanwhile, so this is a backstop, not the latency path.
const BACKSTOP_NS: u64 = 100_000_000;

#[cfg(target_arch = "x86_64")]
fn now_ns() -> u64 { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 }
#[cfg(target_arch = "aarch64")]
fn now_ns() -> u64 { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 }

/// This CPU's index (host build → 0).
#[inline]
fn this_cpu() -> usize {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; hal_x86_64::X86CpuOps::current_cpu() as usize }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; hal_aarch64::ArmCpuOps::current_cpu() as usize }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// Linux `run_ksoftirqd`: drain this CPU's softirqs while pending, yielding
/// between passes so a flood stays preemptible (`cond_resched`), then park on
/// THIS CPU's list until woken. `arg` is the CPU this thread is pinned to —
/// used only to select the park list; the drain itself reads the current CPU
/// (which equals `arg` because the thread is affinity-pinned).
/// # C: O(pending softirq work) per wake
extern "C" fn ksoftirqd(arg: usize) -> ! {
    let my_cpu = if arg < MAX_CPUS { arg } else { 0 };
    loop {
        // RCU callback drain (`06§3.5`) — process-context PRIMARY drainer.
        // Runs deferred frees (e.g. dentry __d_free) whose grace period has
        // elapsed. Process context, so callbacks that take sleeping-style
        // locks (iput → icache) are safe here.
        sync::rcu_process_callbacks();
        if softirq::pending() {
            // Linux run_ksoftirqd: drain in process context via the bh-accounted
            // entry (in_serving_softirq marked, in_interrupt re-entry guard).
            // SAFETY: process-context kthread, IRQs enabled, no lock held.
            unsafe { crate::bh::do_softirq_process(); }
            // cond_resched(): yield so draining a flood stays preemptible.
            // SAFETY: running kthread, preempt-off, no lock held; schedule
            // re-enqueues this still-Runnable task.
            unsafe { super::schedule(); }
            continue;
        }
        // Idle — park on this CPU's list until `wake()` (or the deadline) rouses us.
        // SAFETY: running kthread on this CPU; preempt-off; no lock held across
        // the park; schedule() yields immediately per the WaitList contract.
        unsafe { WAIT[my_cpu].park_with_deadline(now_ns() + BACKSTOP_NS); super::schedule(); }
    }
}

/// Linux `wakeup_softirqd` — installed as the softirq crate's deferral hook.
/// Rouse the CURRENT CPU's ksoftirqd to finish a deferred drain in process
/// context. A no-op self-wake when ksoftirqd itself is the caller (it isn't
/// parked, so its list is empty).
/// # C: O(1)
fn wake() {
    let c = this_cpu();
    if c < MAX_CPUS { WAIT[c].wake_one(); }
}

/// Lock-free publication kick: interrupt this CPU so IRQ tail transfers the
/// global process-only bit to ksoftirqd through the IRQ-save wait-list path.
fn kick() {
    let c = this_cpu() as u32;
    // SAFETY: boot installed the architecture's non-blocking reschedule IPI hook.
    unsafe { let _ = super::send_resched_ipi(c); }
}

/// Spawn one pinned ksoftirqd per online CPU and install the `wakeup_softirqd`
/// hook. Boot, once, after AP bring-up + per-CPU runqueue install (same site
/// as `spawn_timer_driver`). A CPU whose runqueue isn't installed is skipped;
/// its softirqs still drain from its IRQ-tail (the gate's backstop).
/// # C: O(N_cpus)
pub fn spawn_ksoftirqd() -> Result<(), super::SpawnError> {
    softirq::set_wakeup_hook(wake);
    softirq::set_process_kick_hook(kick);
    let online = (cpu::smp::online_count() as usize).min(MAX_CPUS);
    for n in 0..online {
        // Only CPUs with an installed runqueue can host a pinned thread.
        // SAFETY: global_for is sound for any index; None unless CPU n is online + scheduling.
        if unsafe { super::runqueue::global_for(n as u32) }.is_none() { continue; }
        let tid = super::next_tid();
        // SAFETY: boot path after install_default_runqueue + AP bring-up; entry is a 'static extern "C" fn ptr; arg = the CPU to pin to.
        let arc = unsafe { super::spawn_kernel_thread(tid, "ksoftirqd", ksoftirqd, n) }?;
        // Pin to CPU n (Linux per-CPU ksoftirqd is bound to its CPU): set the
        // affinity mask then relocate off the spawn CPU onto n's runqueue.
        if n < 64 {
            arc.cpus_allowed.store(1u64 << n, Ordering::Release);
            // Linux `kthread_bind` sets PF_NO_SETAFFINITY: a per-CPU kthread's
            // affinity is structural, so `sched_setaffinity(2)` on it is EINVAL.
            arc.no_setaffinity.store(true, Ordering::Release);
            super::relocate_for_affinity(&arc, 1u64 << n);
        }
    }
    Ok(())
}
