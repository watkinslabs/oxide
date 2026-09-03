//! Task-owned PELT utilization and the schedutil I/O-wait handoff.

use core::sync::atomic::Ordering;

use super::Task;

const UTIL_SCALE: u64 = 1024;
const PELT_PERIOD_NS: u64 = 1_024_000;
// Linux PELT decays by roughly 2^-1 every 32ms. 978/1000 per 1.024ms
// gives that same half-life without floating point or a tick dependency.
const DECAY_NUM: u64 = 978;
const DECAY_DEN: u64 = 1000;

#[inline]
fn update_value(mut value: u64, delta_ns: u64, running: bool) -> u32 {
    let periods = delta_ns / PELT_PERIOD_NS;
    let remainder = delta_ns % PELT_PERIOD_NS;
    // A task that slept for a long time has no useful residual signal. The
    // bound also keeps a corrupted clock delta from becoming unbounded work.
    for _ in 0..periods.min(128) {
        value = value * DECAY_NUM / DECAY_DEN;
        if running { value += UTIL_SCALE * (DECAY_DEN - DECAY_NUM) / DECAY_DEN; }
    }
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
mod tests {
    use super::{update_value, UTIL_SCALE, PELT_PERIOD_NS};

    #[test]
    fn short_running_burst_is_visible_before_a_tick() {
        let value = update_value(0, PELT_PERIOD_NS / 2, true);
        assert!(value > 0 && value < UTIL_SCALE as u32);
    }

    #[test]
    fn idle_signal_decays() {
        let value = update_value(UTIL_SCALE, PELT_PERIOD_NS * 32, false);
        assert!(value < 600);
    }
}
