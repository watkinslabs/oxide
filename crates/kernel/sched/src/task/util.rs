//! Task-owned PELT utilization and the schedutil I/O-wait handoff.

use core::sync::atomic::Ordering;

use super::Task;

const UTIL_SCALE: u64 = 1024;
const PELT_PERIOD_NS: u64 = 1_024_000;
// Linux PELT decays by roughly 2^-1 every 32ms. 978/1000 per 1.024ms
// gives that same half-life without floating point or a tick dependency.
const DECAY_NUM: u64 = 978;
const DECAY_DEN: u64 = 1000;
const FP_SHIFT: u32 = 32;
const FP_ONE: u64 = 1 << FP_SHIFT;
const DECAY_FP: u64 = (DECAY_NUM << FP_SHIFT) / DECAY_DEN;
const RUNNING_CONTRIB: u64 = UTIL_SCALE * (DECAY_DEN - DECAY_NUM) / DECAY_DEN;
// Solve v = v * decay + contribution in the same units as the old recurrence.
const RUNNING_STEADY: u64 = RUNNING_CONTRIB * DECAY_DEN / (DECAY_DEN - DECAY_NUM);

fn decay_factor(mut periods: u64) -> u64 {
    let mut result = FP_ONE;
    let mut base = DECAY_FP;
    while periods != 0 {
        if periods & 1 != 0 { result = ((result as u128 * base as u128) >> FP_SHIFT) as u64; }
        periods >>= 1;
        if periods != 0 { base = ((base as u128 * base as u128) >> FP_SHIFT) as u64; }
    }
    result
}

fn decay_periods(value: u64, periods: u64, running: bool) -> u64 {
    if periods == 0 { return value; }
    let factor = decay_factor(periods);
    let residual = ((value as u128 * factor as u128) >> FP_SHIFT) as u64;
    if !running { return residual; }
    if value <= RUNNING_STEADY {
        RUNNING_STEADY.saturating_sub(((RUNNING_STEADY - value) as u128 * factor as u128 >> FP_SHIFT) as u64)
    } else {
        RUNNING_STEADY.saturating_add(((value - RUNNING_STEADY) as u128 * factor as u128 >> FP_SHIFT) as u64)
    }
}

#[inline]
fn update_value(mut value: u64, delta_ns: u64, running: bool) -> u32 {
    let periods = delta_ns / PELT_PERIOD_NS;
    let remainder = delta_ns % PELT_PERIOD_NS;
    // A task that slept for a long time has no useful residual signal. The
    // bound also keeps a corrupted clock delta from becoming unbounded work.
    value = decay_periods(value, periods.min(128), running);
    if remainder != 0 {
        let decay = DECAY_DEN.saturating_sub(
            (DECAY_DEN - DECAY_NUM) * remainder / PELT_PERIOD_NS);
        value = value * decay / DECAY_DEN;
        if running { value += UTIL_SCALE * (DECAY_DEN - decay) / DECAY_DEN; }
    }
    value.min(UTIL_SCALE) as u32
}

impl Task {
    /// Update this entity's PELT signal at a scheduler boundary. `running`
    /// describes the interval since the previous boundary, not the instant at
    /// which this function is called.
    pub(crate) fn update_util(&self, now_ns: u64, running: bool) -> u32 {
        let last = self.sched.se.avg_last_update_time.swap(now_ns, Ordering::AcqRel);
        if last == 0 || now_ns <= last {
            return self.sched.se.avg_util.load(Ordering::Acquire).min(u32::MAX as u64) as u32;
        }
        let next = update_value(self.sched.se.avg_util.load(Ordering::Acquire) as u64,
                                now_ns - last, running);
        self.sched.se.avg_util.store(next as u64, Ordering::Release);
        next
    }

    /// Begin an explicitly device-backed wait. Generic sleeps must not call
    /// this: Linux's SCHED_CPUFREQ_IOWAIT is for I/O latency, not all wakes.
    pub fn begin_iowait(&self) { self.in_iowait.store(true, Ordering::Release); }

    /// End the device wait after the task has resumed.
    pub fn end_iowait(&self) { self.in_iowait.store(false, Ordering::Release); }

    /// Consume the I/O-wait indication at the wakeup update-util hook.
    pub(crate) fn take_iowait(&self) -> bool {
        self.in_iowait.swap(false, Ordering::AcqRel)
    }
}

#[cfg(test)]
#[path = "tests/util.rs"]
mod tests;
