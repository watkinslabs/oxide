// POSIX timer module manifest.
// - `clock`: native clock-domain resolution and sampling.
// - `runtime`: expiry, signal delivery, earliest deadline, and IRQ reprogramming.
// - `sigevent`: `good_sigevent()` notification-mode table.
// - `slots`: timer-id allocation, reuse, and lookup policy.
// - `syscalls`: timer_create/set/get/getoverrun/delete work functions.
// - `uapi`: Linux layouts and checked user copies.
// Clock-id decode and the per-clock callback table live in `crate::posix_clock`.

mod backend;
mod clock;
mod runtime;
pub(crate) mod sigevent;
pub mod slots;
#[cfg(test)] mod tests;
mod syscalls;
mod uapi;

pub use clock::{cpu_clock_sample_ns, cpu_clock_valid};
pub use runtime::{account_cpu_tick, clear_process_timers, clock_was_set, fire_due_timers,
    install_deadline_programmer, next_interrupt_deadline, reprogram_posix_timers,
    wall_timer_interrupt, ACCOUNTING_TICK_NS};
pub use syscalls::{sys_timer_create, sys_timer_delete, sys_timer_getoverrun, sys_timer_gettime,
    sys_timer_settime, timer_dispatch};
