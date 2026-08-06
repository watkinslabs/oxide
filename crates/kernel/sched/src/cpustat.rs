//! CPU-time accounting. `/proc/stat` retains Linux tick accounting, while
//! per-task `utime`/`stime` use Linux generic virtual accounting: charge the
//! interval at every user↔kernel transition and context switch. Sampling the
//! whole inter-tick interval from one IRQ frame billed syscall-heavy workloads
//! almost entirely to user time.

use core::sync::atomic::{AtomicU64, Ordering};

const N: usize = cpu::MAX_CPUS;

static USER: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
static SYS:  [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
static IDLE: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];

pub const VTIME_SYSTEM: u8 = 0;
pub const VTIME_USER: u8 = 1;

/// What the timer tick interrupted.
pub enum TickKind { User, System, Idle }

/// Classify the interrupted context for Linux `kcpustat`: privilege level
/// distinguishes user from kernel, and runqueue identity distinguishes real
/// system work from the per-CPU idle task. # C: O(1)
pub fn tick_kind(from_user: bool) -> TickKind {
    if from_user { return TickKind::User; }
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    {
        if crate::live::runqueue::global().is_some_and(|rq| rq.curr_is_idle()) {
            return TickKind::Idle;
        }
    }
    TickKind::System
}

/// The CPU this code is running on (per-CPU base via gs/TPIDR). 0 off-target.
/// # C: O(1)
#[inline]
pub(crate) fn this_cpu() -> usize {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_x86_64::X86CpuOps::current_cpu() as usize).min(N - 1) }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_aarch64::ArmCpuOps::current_cpu() as usize).min(N - 1) }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// Charge one timer tick to the running context's bucket on the CPU the tick
/// fired on. Called from each CPU's timer-ISR tick hook.
/// # C: O(1)
pub fn account(kind: TickKind) {
    let c = this_cpu();
    match kind {
        TickKind::User   => USER[c].fetch_add(1, Ordering::Relaxed),
        TickKind::System => SYS[c].fetch_add(1, Ordering::Relaxed),
        TickKind::Idle   => IDLE[c].fetch_add(1, Ordering::Relaxed),
    };
}

/// Live monotonic clock in ns. Host builds (unit tests) return 0, so the
/// per-task charge below is a no-op off-target.
/// # C: O(1)
#[inline]
fn now_ns() -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

#[inline]
fn charge(task: &crate::Task, user: bool, delta: u64) {
    if delta == 0 { return; }
    if user { task.utime_ns.fetch_add(delta, Ordering::Relaxed); }
    else    { task.stime_ns.fetch_add(delta, Ordering::Relaxed); }
    task.thread_group.charge_cpu(user, delta);
    if crate::sched_enc::is_rt_class_policy(task.policy.load(Ordering::Relaxed)) {
        task.rt_timeout_ns.fetch_add(delta, Ordering::Relaxed);
    }
}

/// Close the running task's current virtual-time interval at `now`, optionally
/// changing its mode. `vtime_start_ns == 0` is the off-CPU sentinel, so a
/// switch-in establishes a baseline without charging the sleep interval.
/// # C: O(1)
#[inline]
fn flush(task: &crate::Task, now: u64, next_state: Option<u8>) -> u64 {
    let start = task.vtime_start_ns.swap(now, Ordering::AcqRel);
    let state = task.vtime_state.load(Ordering::Acquire);
    let delta = if start != 0 && now > start { now - start } else { 0 };
    charge(task, state == VTIME_USER, delta);
    if let Some(state) = next_state { task.vtime_state.store(state, Ordering::Release); }
    delta
}

/// Linux `vtime_user_exit`: close user time at kernel entry and begin system
/// time. Syscall and user-mode IRQ entry call this before doing kernel work.
/// # C: O(1)
#[inline]
pub fn user_exit() {
    #[cfg(target_os = "oxide-kernel")]
    if let Some(task) = crate::live::current() {
        let _ = flush(task, now_ns(), Some(VTIME_SYSTEM));
    }
}

/// Linux `vtime_user_enter`: close system time immediately before resuming
/// userspace and begin the next user interval. # C: O(1)
#[inline]
pub fn user_enter() {
    #[cfg(target_os = "oxide-kernel")]
    if let Some(task) = crate::live::current() {
        let _ = flush(task, now_ns(), Some(VTIME_USER));
    }
}

/// Flush the outgoing task and exclude the following off-CPU interval.
/// Called under the owning runqueue's switch invariant. # C: O(1)
pub(crate) fn switch_out(task: &crate::Task, now: u64) {
    let _ = flush(task, now, None);
    task.vtime_start_ns.store(0, Ordering::Release);
}

/// Start the incoming task's preserved user/system mode at this CPU's switch
/// timestamp. Called under the owning runqueue's switch invariant. # C: O(1)
pub(crate) fn switch_in(task: &crate::Task, now: u64) {
    task.vtime_start_ns.store(now, Ordering::Release);
}

/// Settle the final kernel interval before exit snapshots publish the task's
/// rusage. The later scheduler switch sees the off-CPU sentinel and cannot
/// charge it twice. # C: O(1)
pub fn exit_current(task: &crate::Task) {
    let _ = flush(task, now_ns(), None);
    task.vtime_start_ns.store(0, Ordering::Release);
}

/// Timer-tick checkpoint for CPU-clock timers. The user/system interval is
/// already owned by the transition state, so the interrupted-frame sample no
/// longer decides where the whole preceding tick belongs.
///
/// Hard-IRQ safe: atomics plus the POSIX timer backend's non-blocking try-lock.
/// # C: O(1)
/// # Ctx: IRQ
pub fn charge_current_tick(from_user: bool) {
    #[cfg(target_os = "oxide-kernel")]
    if let Some(t) = crate::live::current() {
        let now = now_ns();
        let start = t.vtime_start_ns.load(Ordering::Acquire);
        crate::cputime_trace::tick_entry(now, start, true);
        let user = t.vtime_state.load(Ordering::Acquire) == VTIME_USER;
        let delta = flush(t, now, None);
        crate::cputime_trace::tick(t, user, delta);
        crate::timers::account_cpu_tick(t);
    }
    let _ = from_user;
}

/// `(user, system, idle)` accumulated ticks for CPU `cpu` — `/proc/stat`'s
/// `cpuN` line. # C: O(1)
pub fn snapshot_cpu(cpu: usize) -> (u64, u64, u64) {
    if cpu >= N { return (0, 0, 0); }
    (USER[cpu].load(Ordering::Relaxed),
     SYS[cpu].load(Ordering::Relaxed),
     IDLE[cpu].load(Ordering::Relaxed))
}

/// Aggregate `(user, system, idle)` summed over all CPUs — `/proc/stat`'s
/// `cpu` (no-suffix) line. # C: O(MAX_CPUS)
pub fn snapshot() -> (u64, u64, u64) {
    let (mut u, mut s, mut i) = (0u64, 0u64, 0u64);
    for c in 0..N {
        u += USER[c].load(Ordering::Relaxed);
        s += SYS[c].load(Ordering::Relaxed);
        i += IDLE[c].load(Ordering::Relaxed);
    }
    (u, s, i)
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::sync::atomic::Ordering;
    use crate::{SchedClass, Task};
    use super::*;

    fn user_task() -> Arc<Task> {
        Arc::new(Task::new_user(1861, "vtime",
            SchedClass::Normal { weight: 1024 },
            vmm::AddressSpace::new(0).expect("test address space")))
    }

    #[test]
    fn transitions_charge_the_interval_that_preceded_them() {
        let task = user_task();
        switch_in(&task, 100);
        flush(&task, 160, Some(VTIME_SYSTEM));
        flush(&task, 225, Some(VTIME_USER));
        switch_out(&task, 250);

        assert_eq!(task.utime_ns.load(Ordering::Relaxed), 85);
        assert_eq!(task.stime_ns.load(Ordering::Relaxed), 65);
        assert_eq!(task.thread_group.cpu_sample(), (85, 65));
        assert_eq!(task.vtime_start_ns.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn context_switch_excludes_the_off_cpu_gap_and_preserves_mode() {
        let task = user_task();
        switch_in(&task, 100);
        switch_out(&task, 140);
        assert_eq!(task.vtime_start_ns.load(Ordering::Relaxed), 0,
            "an off-CPU task has no chargeable interval");
        switch_in(&task, 10_000);
        flush(&task, 10_025, Some(VTIME_SYSTEM));

        assert_eq!(task.utime_ns.load(Ordering::Relaxed), 65);
        assert_eq!(task.stime_ns.load(Ordering::Relaxed), 0);
    }
}
