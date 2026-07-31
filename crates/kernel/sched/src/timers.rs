// POSIX timer module manifest.
// - `clock`: native clock-domain resolution and sampling.
// - `runtime`: expiry, signal delivery, earliest deadline, and IRQ reprogramming.
// - `signal`: the `_timer` siginfo record + `posixtimer_rearm`'s overrun stamp.
// - `sigevent`: `good_sigevent()` notification-mode table.
// - `slots`: timer-id allocation, reuse, and lookup policy.
// - `syscalls`: timer_create/set/get/getoverrun/delete work functions.
// - `uapi`: Linux layouts and checked user copies.
// Clock-id decode and the per-clock callback table live in `crate::posix_clock`.

mod backend;
mod clock;
mod runtime;
// The `_timer` siginfo arm. NOT gated: si_code/si_tid/si_overrun/si_value are
// the user-visible half of `timer_create(2)`.
pub mod signal;
pub(crate) mod sigevent;
pub mod slots;
// CPU-time clock_nanosleep rules. NOT gated: the admission ladder and the
// interrupted-return split are the user-visible contract.
pub mod cpu_nanosleep;
#[cfg(test)] mod tests;
mod syscalls;
mod uapi;

pub use clock::{cpu_clock_sample_ns, cpu_clock_valid};
pub use runtime::{account_cpu_tick, clear_process_timers, clock_was_set, fire_due_timers,
    posixtimer_rearm,
    install_clock_was_set_hook, install_deadline_programmer, next_interrupt_deadline,
    reprogram_local, reprogram_posix_timers, wall_timer_interrupt, ACCOUNTING_TICK_NS};
pub use syscalls::{sys_timer_create, sys_timer_delete, sys_timer_getoverrun, sys_timer_gettime,
    sys_timer_settime, timer_dispatch};
