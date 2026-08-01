// B20: coarse walker for alarm(2)/ITIMER_REAL and the CPU-time itimers.
// POSIX timers use the architecture one-shot path in `timers::runtime`.
//
// B1460 moved BLOCKING-WAIT deadlines out of here entirely. They used to be
// found by this same registry walk, which meant every kernel timeout inherited
// its ~100 ms cadence — the walk is a `timer::register_periodic` on the
// `ktimers` kthread, self-throttled to 100 ms, on a kthread that parks 100 ms
// per loop. Wait expiries now live in `sched::hrtimeout`, a deadline-ordered
// queue the timer IRQ sweeps and the one-shot programmer reads, so a 1 ms
// timeout costs 1 ms. Nothing here consumes `wakeup_deadline_ns` any more; a
// second consumer of the same deadline would be exactly the shadow state that
// lets a broken primary look healthy.
//
// What is left is genuinely coarse: `alarm(2)` has 1-second resolution, and
// ITIMER_VIRTUAL/ITIMER_PROF advance only on CPU time this walk also samples.
//
// Delivery goes through the ONE enqueue (`live::send`), which publishes the
// pending bit and wakes a thread that can take the signal. The roused task
// re-checks pending signals after schedule() returns and surfaces -EINTR
// (SIGALRM) from the caller's blocking loop.
//
// Cost: O(N_live_tasks) per scan, at the 100 ms ktimers cadence.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use super::sigpend::Signum;
use crate::sigsend::{SigSource, SigTarget};

/// Last `now_ns` the scan walked the registry. Throttles the O(N)
/// allocation-free registry walk to a ~100 ms
/// cadence so calling this from every timer tick stays cheap.
static LAST_SCAN_NS: AtomicU64 = AtomicU64::new(0);
const SCAN_PERIOD_NS: u64 = 100_000_000;

/// Service ONE task's expired `alarm(2)`/`ITIMER_REAL` deadline and its
/// CPU-time itimers, re-arming by interval (or clearing for a one-shot).
/// Returns the MASK of signals that came due — the caller owns the send, so
/// the deadline bookkeeping stays separate from the enqueue and a caller
/// holding only a `&Task` never pays for an `Arc` resolve it does not need.
///
/// ONE owner for the expiry policy: the registry walk below runs it for every
/// live task, and the return-to-user path runs it for the current task so a
/// timer that came due inside the last syscall is not held for up to a full
/// scan period. Before this the syscall tail carried its own open-coded copy.
/// # C: O(1)
pub fn service_task_timers(t: &crate::Task, now_ns: u64) -> u64 {
    let mut due = 0u64;
    let adl = t.alarm_ns.load(Ordering::Acquire);
    if adl != 0 && adl <= now_ns {
        let interval = t.alarm_interval_ns.load(Ordering::Acquire);
        t.alarm_ns.store(
            if interval != 0 { now_ns.saturating_add(interval) } else { 0 },
            Ordering::Release,
        );
        due |= Signum::Sigalrm.bit();
    }
    let u = t.utime_ns.load(Ordering::Acquire);
    let s = t.stime_ns.load(Ordering::Acquire);
    due |= fire_cpu_itimer(&t.itimer_virtual_ns, &t.itimer_virtual_interval_ns, u, Signum::Sigvtalrm);
    due |= fire_cpu_itimer(&t.itimer_prof_ns, &t.itimer_prof_interval_ns, u.saturating_add(s), Signum::Sigprof);
    // Linux checks `RLIMIT_CPU` and `RLIMIT_RTTIME` from the same periodic
    // sweep as the CPU-time itimers (`check_process_timers` /
    // `check_thread_timers`), and posts their SIGXCPU/SIGKILL through the same
    // process-directed enqueue the caller runs below.
    due |= super::cpu_rlimit::check_cpu_rlimits(t);
    // A `SCHED_DEADLINE` task that asked to be told about overruns
    // (`SCHED_FLAG_DL_OVERRUN`) has one latch per overrun; taking it here posts
    // the SIGXCPU through the same process-directed enqueue as the CPU-time
    // limits, and coalesces repeated overruns into one signal.
    if t.dl.take_overrun() { due |= Signum::Sigxcpu.bit(); }
    due
}

fn fire_cpu_itimer(deadline: &AtomicU64, interval: &AtomicU64, now_cpu: u64, sig: Signum) -> u64 {
    let dl = deadline.load(Ordering::Acquire);
    if dl == 0 || dl > now_cpu { return 0; }
    let intv = interval.load(Ordering::Acquire);
    deadline.store(if intv != 0 { now_cpu.saturating_add(intv) } else { 0 }, Ordering::Release);
    sig.bit()
}

/// Post the signals `service_task_timers` found due, through the ONE enqueue.
///
/// Linux runs all three from process context — `it_real_fn` is an hrtimer
/// callback calling `kill_pid_info(SIGALRM, SEND_SIG_PRIV, …)`, and
/// `check_cpu_itimer` calls `__group_send_sig_info(signo, SEND_SIG_PRIV, tsk)`
/// — so every one of them is PROCESS-directed and carries an `SI_KERNEL`
/// record. Both call sites here are process context too: the walk below runs
/// on the `ktimers` kthread (never the hard tick, which may not take the
/// registry or runqueue locks, `06§3.1`) and the other is the syscall-return
/// tail. Producers that set the bit directly lost the record and put a
/// process-directed signal into one thread's private set.
/// # C: O(N_threads) per due signal
pub fn post_expired_timer_signals(t: &Arc<crate::Task>, due: u64) {
    let mut rest = due;
    while rest != 0 {
        let sig = rest.trailing_zeros() + 1;
        rest &= rest - 1;
        let _ = super::send::send_signal(t, sig, SigSource::Kernel, SigTarget::Process);
    }
}

/// Service + post for the RUNNING task, at the syscall-return tail. The `Arc`
/// resolve happens only when something actually came due, so the common
/// "nothing expired" return costs one atomic load per timer.
/// # C: O(1) when nothing is due
pub fn service_current_timers(now_ns: u64) {
    let Some(cur) = super::current() else { return };
    let due = service_task_timers(cur, now_ns);
    if due == 0 { return; }
    let Some(arc) = crate::registry::lookup(cur.tid) else { return };
    post_expired_timer_signals(&arc, due);
}

/// Walk the live task registry and service expired `alarm_ns` (alarm(2) /
/// setitimer ITIMER_REAL) plus the CPU-time itimers. Idempotent.
///
/// B20: the syscall-return tail also checks alarm_ns,
/// but a task parked in a blocking syscall (e.g. read() on an empty
/// pipe) issues no further syscalls, so its tail never runs — only
/// this periodic walker can post SIGALRM and wake it. On expiry we
/// re-arm by interval (or clear for one-shot), set the SIGALRM
/// pending bit, and `wake_if_sleeping` so the blocking helper
/// re-checks deliverable signals and surfaces -EINTR.
/// # C: O(N_live_tasks)
pub fn tick_wake_expired(now_ns: u64) {
    if now_ns == 0 { return; }
    // Throttle to SCAN_PERIOD_NS. The load-then-store race under SMP
    // at worst double-scans one period — harmless (scan is idempotent).
    let last = LAST_SCAN_NS.load(Ordering::Relaxed);
    if now_ns.saturating_sub(last) < SCAN_PERIOD_NS { return; }
    LAST_SCAN_NS.store(now_ns, Ordering::Relaxed);
    // debug-wakelat: record the effective scan cadence; a gap far over the
    // 100 ms throttle means the driving tick stalled (H3).
    #[cfg(feature = "debug-wakelat")]
    super::wakelat::note_scan(now_ns);
    // Registered as a `ktimers` periodic (`sched::register_timers`), so this is
    // PROCESS context and the send below may take the registry and runqueue
    // locks. Still no Vec snapshot: advance one registry tid at a time with the
    // registry lock released before `lookup` / send work, so the walk never
    // holds REG across an enqueue.
    let mut after = 0;
    while let Some(tid) = crate::registry::next_live_tid_after(after) {
        after = tid;
        let t = match crate::registry::lookup(tid) { Some(t) => t, None => continue };
        let due = service_task_timers(&t, now_ns);
        if due != 0 { post_expired_timer_signals(&t, due); }
    }
}
