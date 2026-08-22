// The scheduler's entry into cpuidle: one whole cycle per park.
//
// The idle loop calls this in place of halting directly. Everything it needs
// beyond the clock — which state, whether the driver took it, how long it
// lasted — is decided in the ungated half; this file supplies the clock, the
// sleep-length estimate and the fallback for a machine with no driver.

//
// Module manifest:
// - `generic`: the architecture-halt driver a machine with no platform
//   description still gets.
#![cfg(target_os = "oxide-kernel")]

pub mod generic;

use crate::select::{idle_cycle, Conditions};

/// How long a CPU may commit to sleeping.
///
/// The earlier of the next armed timer and the next periodic tick. The tick is
/// the ceiling because this kernel does not suppress it: a state whose
/// residency exceeds the tick period will be cut short by it whatever the
/// timer list says, and a governor told otherwise would keep choosing states
/// that never pay for themselves. # C: O(N_timers)
pub fn sleep_length_ns(now_ns: u64, tick_ns: u64) -> u64 {
    let until_tick = tick_ns;
    let until_timer = timer::next_deadline_ns(now_ns)
        .map_or(u64::MAX, |deadline| deadline.saturating_sub(now_ns));
    until_timer.min(until_tick)
}

fn now_ns() -> u64 { timekeeper::monotonic_ns() }

/// Run one idle cycle on `cpu`, or report that no driver has published a
/// state table and the caller should halt directly. # C: O(N_states)
pub fn enter_idle(cpu: usize, tick_ns: u64) -> bool {
    let Some(driver) = crate::driver::driver() else { return false; };
    let conditions = Conditions::new(cpu, sleep_length_ns(now_ns(), tick_ns), tick_ns);
    idle_cycle(&driver, &conditions, now_ns).is_some()
}
