#[cfg(target_os = "oxide-kernel")]
use hal::{Nanos, TimerOps};

/// Translate an absolute `CLOCK_MONOTONIC` expiry into the architecture
/// counter's absolute domain.
///
/// Linux `clockevents_program_event()` performs this boundary explicitly:
/// `delta = expires - ktime_get()`, then the clockevent device receives that
/// relative delta.  TSC-deadline and CNTV_CVAL are absolute raw-counter
/// compares, while Oxide's scheduler deadlines are `CLOCK_MONOTONIC` and
/// therefore exclude suspended time.  Passing the scheduler value straight
/// to the compare register makes every post-resume deadline already expired
/// and produces a one-cycle interrupt storm.
/// # C: O(1)
fn raw_deadline(deadline_ns: u64, monotonic_now_ns: u64, raw_now_ns: u64) -> u64 {
    raw_now_ns.saturating_add(deadline_ns.saturating_sub(monotonic_now_ns))
}

fn program(deadline_ns: u64) {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let monotonic_now = timekeeper::monotonic_ns();
        let raw_now = hal_x86_64::X86TimerOps::monotonic_ns().0;
        let raw = raw_deadline(deadline_ns, monotonic_now, raw_now);
        // SAFETY: LAPIC timer vector is installed and this CPU owns its local timer/MSR.
        unsafe {
            if crate::lapic::timer_deadline_mode() {
                hal_x86_64::X86TimerOps::set_oneshot(Nanos(raw));
            }
        }
    }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let monotonic_now = timekeeper::monotonic_ns();
        let raw_now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
        let raw = raw_deadline(deadline_ns, monotonic_now, raw_now);
        // SAFETY: this CPU owns CNTV_CVAL/CTL and INTID 27 is enabled during timer bring-up.
        unsafe { hal_aarch64::ArmTimerOps::set_oneshot(Nanos(raw)); }
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    let _ = deadline_ns;
}

/// Connect scheduler deadline ownership to this CPU's timer hardware. # C: O(1)
pub fn install() {
    #[cfg(target_os = "oxide-kernel")]
    sched::timers::install_deadline_programmer(program);
}

// `rearm` used to do two unrelated jobs at once, and because they have
// different CPU scoping, every caller got one of them wrong:
//
//   * arming the next one-shot is PER-CPU — `program` writes THIS CPU's own
//     timer hardware (LAPIC TSC-deadline / CNTV_CVAL), so every CPU must do it
//     for its own running task;
//   * servicing due POSIX wall timers is GLOBAL — one shared queue behind one
//     try-lock, so exactly one CPU should do it.
//
// x86 called the combined `rearm` on every CPU (so the global half ran N
// times); aarch64 called it only on the BSP (so its APs never armed a deadline
// at all, and a task running on an AP got no one-shot). Splitting the two lets
// each dispatcher scope each half correctly, and makes the two dispatchers
// state the SAME policy — which is the duplicated-policy defect in
// `skizm.md` 3.2.

/// Arm THIS CPU's next accounting/deadline interrupt. Every CPU, every tick.
/// # C: O(1)
/// # Ctx: timer IRQ
pub fn rearm_local() {
    #[cfg(target_os = "oxide-kernel")]
    program(sched::timers::next_interrupt_deadline());
}

/// Service due POSIX wall timers. Global queue — the timekeeping CPU only.
/// # C: O(N) when due
/// # Ctx: timer IRQ
pub fn service_wall_timers() {
    #[cfg(target_os = "oxide-kernel")]
    sched::timers::wall_timer_interrupt();
}

/// Wake every blocking wait whose timeout has expired — Linux
/// `__hrtimer_run_queues`, driven from the same interrupt that armed it. Every
/// CPU, every tick: each expiry is taken under the queue lock, so a waiter is
/// woken exactly once however many CPUs reach here. This must run BEFORE
/// `rearm_local` so the deadline it programs is the next UNSERVICED one.
/// # C: O(due)
/// # Ctx: timer IRQ
pub fn service_wait_deadlines() {
    #[cfg(target_os = "oxide-kernel")]
    sched::hrtimeout::expire_now();
    // Same interrupt, same reason: a throttled deadline entity whose next
    // period has started is replenished and returned to the ready set here, so
    // its budget resumes at the instant the period begins.
    #[cfg(target_os = "oxide-kernel")]
    sched::deadline::live::expire_throttled_now();
    // rseq grants have a microsecond expiry, so they share the one-shot timer
    // instead of inheriting the coarse scheduler tick.
    #[cfg(target_os = "oxide-kernel")]
    sched::rseq::slice_timer_expired();
}

#[cfg(test)]
mod tests {
    use super::raw_deadline;

    #[test]
    fn clockevent_translation_preserves_relative_expiry_across_suspend_offset() {
        assert_eq!(raw_deadline(150, 100, 100), 150);
        assert_eq!(raw_deadline(150, 100, 600), 650,
            "500 ns excluded from CLOCK_MONOTONIC must remain in the raw compare domain");
    }

    #[test]
    fn expired_and_overflowing_deadlines_are_bounded() {
        assert_eq!(raw_deadline(99, 100, 600), 600);
        assert_eq!(raw_deadline(u64::MAX, 0, 10), u64::MAX);
    }
}
