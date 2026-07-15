use hal::{Nanos, TimerOps};

fn program(deadline_ns: u64) {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: LAPIC timer vector is installed and this CPU owns its local timer/MSR.
        unsafe {
            if crate::lapic::timer_deadline_mode() {
                hal_x86_64::X86TimerOps::set_oneshot(Nanos(deadline_ns));
            }
        }
    }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        // SAFETY: this CPU owns CNTV_CVAL/CTL and INTID 27 is enabled during timer bring-up.
        unsafe { hal_aarch64::ArmTimerOps::set_oneshot(Nanos(deadline_ns)); }
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    let _ = deadline_ns;
}

/// Connect scheduler deadline ownership to this CPU's timer hardware. # C: O(1)
pub fn install() {
    #[cfg(target_os = "oxide-kernel")]
    sched::timers::install_deadline_programmer(program);
}

/// Service due POSIX timers and arm the next accounting/deadline interrupt. # C: O(N) when due
/// # Ctx: timer IRQ
pub fn rearm() {
    #[cfg(target_os = "oxide-kernel")]
    {
        sched::timers::wall_timer_interrupt();
        program(sched::timers::next_interrupt_deadline());
    }
}
