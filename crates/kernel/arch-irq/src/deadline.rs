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
