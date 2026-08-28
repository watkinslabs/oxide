#[cfg(target_os = "oxide-kernel")]
use hal::{Nanos, TimerOps};

fn program(deadline_ns: u64) -> bool {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        if hal_x86_64::X86TimerOps::freq_khz() == 0 { return false; }
        // SAFETY: LAPIC timer vector is installed and this CPU owns its local timer/MSR.
        // Entering deadline mode and writing the compare are one hardware
        // transaction from the scheduler's point of view.  If either half
        // fails, the LVT may already have left periodic mode.  Restore a
        // periodic safety tick so the failed arm cannot strand an idle CPU
        // waiting for an interrupt that the LAPIC will never deliver; the
        // next tick retries the one-shot transition.
        let armed = unsafe {
            crate::lapic::timer_deadline_mode()
                && hal_x86_64::X86TimerOps::set_oneshot(Nanos(deadline_ns))
        };
        if !armed {
            // SAFETY: this CPU owns its local LAPIC timer.  The fallback is
            // deliberately periodic and therefore guarantees a retry path.
            unsafe { let _ = crate::lapic::timer_periodic(1_000_000); }
        }
        return armed;
    }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        if hal_aarch64::ArmTimerOps::freq_khz() == 0 { return false; }
        // SAFETY: this CPU owns CNTV_CVAL/CTL and INTID 27 is enabled during timer bring-up.
        let armed = unsafe { hal_aarch64::ArmTimerOps::set_oneshot(Nanos(deadline_ns)) };
        if !armed {
            // SAFETY: this PE owns its virtual timer.  Keep a periodic retry
            // source if the one-shot compare could not be enabled.
            unsafe { hal_aarch64::timer::timer_periodic(1_000_000); }
        }
        return armed;
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    { let _ = deadline_ns; return false; }
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
}
