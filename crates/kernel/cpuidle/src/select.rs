// The idle cycle: ask the governor, enter the state, measure, tell the
// governor what happened.
//
// The clock is a parameter rather than a call, so the whole cycle — including
// the accounting a wrong duration would corrupt — runs in a hosted test
// against a clock the test moves by hand.

use alloc::sync::Arc;

use crate::driver::Driver;
use crate::governor::{Reflection, SelectInput, Selection};
use crate::limits::LATENCY_UNLIMITED_NS;
use crate::usage::{record_entry, record_rejection};

/// What one idle cycle did.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Cycle {
    pub selection: Selection,
    /// State actually entered, or `None` when the driver refused.
    pub entered: Option<usize>,
    /// Measured residency, nanoseconds.
    pub measured_ns: u64,
}

/// What the kernel knows about this CPU's idle at the moment it goes idle.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Conditions {
    pub cpu: usize,
    /// Time to the next event already scheduled, nanoseconds.
    pub sleep_length_ns: u64,
    /// Period of the periodic tick, nanoseconds.
    pub tick_ns: u64,
    /// Deepest wakeup latency anything on this CPU tolerates, nanoseconds.
    pub latency_req_ns: u64,
    pub tick_stopped: bool,
}

impl Conditions {
    /// Conditions on a CPU with no latency constraint. # C: O(1)
    pub fn new(cpu: usize, sleep_length_ns: u64, tick_ns: u64) -> Conditions {
        Conditions {
            cpu, sleep_length_ns, tick_ns,
            latency_req_ns: LATENCY_UNLIMITED_NS,
            tick_stopped: false,
        }
    }
}

/// Ask the governor which state this CPU should enter. # C: O(N_states)
pub fn select(driver: &Arc<Driver>, conditions: &Conditions) -> Option<Selection> {
    let states = driver.states_for(conditions.cpu)?;
    driver.with_device(conditions.cpu, |device| {
        if !device.enabled { return None; }
        let input = SelectInput {
            states,
            usage: &device.usage,
            sleep_length_ns: conditions.sleep_length_ns,
            tick_ns: conditions.tick_ns,
            latency_req_ns: conditions.latency_req_ns,
            tick_stopped: conditions.tick_stopped,
        };
        Some(device.governor.select(&input))
    })?
}

/// Fold one completed sleep into the counters and the governor's predictor.
/// # C: O(N_states)
pub fn reflect(driver: &Arc<Driver>, cpu: usize, reflection: &Reflection, tick_ns: u64,
               requested: usize)
{
    let Some(states) = driver.states_for(cpu) else { return; };
    driver.with_device(cpu, |device| {
        match reflection.entered {
            Some(entered) => {
                record_entry(states, &mut device.usage, entered,
                             reflection.measured_ns);
                device.last_residency_ns = reflection.measured_ns;
            }
            None => {
                record_rejection(&mut device.usage, requested);
                device.last_residency_ns = 0;
            }
        }
        device.governor.reflect(states, reflection, tick_ns);
    });
}

/// Run one whole idle cycle. `now_ns` is read either side of the entry, so the
/// measured residency is the sleep and not the decision that preceded it.
/// # C: O(N_states)
pub fn idle_cycle(driver: &Arc<Driver>, conditions: &Conditions, now_ns: fn() -> u64,
                  tick_wakeup: fn() -> bool) -> Option<Cycle>
{
    let selection = select(driver, conditions)?;
    let state = driver.states_for(conditions.cpu)?.get(selection.index)?;

    let started = now_ns();
    let entered = driver.ops().enter(conditions.cpu, selection.index, state).ok();
    let measured_ns = now_ns().saturating_sub(started);

    let reflection = Reflection {
        entered,
        measured_ns: if entered.is_some() { measured_ns } else { 0 },
        tick_wakeup: tick_wakeup(),
        poll_time_limit: false,
    };
    reflect(driver, conditions.cpu, &reflection, conditions.tick_ns, selection.index);
    Some(Cycle { selection, entered, measured_ns: reflection.measured_ns })
}

#[cfg(test)]
#[path = "tests/select.rs"]
mod tests;
