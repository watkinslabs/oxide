// The scheduler's side of frequency scaling: turn what this kernel knows
// about how busy each CPU has been into the demand signal cpufreq consumes.
//
// The reference feeds its utilisation governor a per-entity load average
// updated on every wakeup, so the frequency can move on the same wakeup that
// created the demand. This scheduler has no such per-entity average; what it
// has is the per-CPU user/system/idle accounting the tick already maintains.
// That is a real utilisation measure over the sampling window, and it is what
// the demand signal is built from here. The consequence is recorded in
// `scratch/known_issues.md`: the signal is tick-granular rather than
// wakeup-granular, so a burst shorter than the window raises the frequency one
// window late.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::{AtomicU64, Ordering};

use cpufreq::governor::input::CAPACITY_SCALE;
use cpufreq::Demand;

/// How often the demand signal is resampled. The tick is the finest the
/// underlying accounting moves at, so sampling faster would read the same
/// numbers twice.
const SAMPLE_PERIOD_NS: u64 = crate::posix_clock::TICK_NSEC;

/// Busy and idle tick counts at the last sample, per CPU.
static LAST_BUSY: [AtomicU64; cpu::MAX_CPUS] = [const { AtomicU64::new(0) }; cpu::MAX_CPUS];
static LAST_IDLE: [AtomicU64; cpu::MAX_CPUS] = [const { AtomicU64::new(0) }; cpu::MAX_CPUS];

/// Full load, percent.
const FULL_LOAD_PERCENT: u32 = 100;

/// Busy fraction of one CPU since the previous sample, percent.
///
/// A window in which the counters did not move carries no information: the CPU
/// was neither busy nor idle for a whole tick, which happens on a CPU that was
/// offline or never scheduled. Reporting zero there would drive it to its
/// minimum on no evidence, so the previous answer is kept by reporting `None`.
/// # C: O(1)
fn busy_percent(cpu: usize) -> Option<u32> {
    let (user, system, idle) = crate::cpustat::snapshot_cpu(cpu);
    let busy = user.saturating_add(system);
    let prev_busy = LAST_BUSY[cpu].swap(busy, Ordering::Relaxed);
    let prev_idle = LAST_IDLE[cpu].swap(idle, Ordering::Relaxed);
    let busy_delta = busy.saturating_sub(prev_busy);
    let idle_delta = idle.saturating_sub(prev_idle);
    let total = busy_delta.saturating_add(idle_delta);
    if total == 0 { return None; }
    Some((busy_delta.saturating_mul(u64::from(FULL_LOAD_PERCENT)) / total) as u32)
}

/// The same fraction expressed as a utilisation out of the capacity scale.
/// # C: O(1)
fn utilisation(load_percent: u32) -> u64 {
    CAPACITY_SCALE.saturating_mul(u64::from(load_percent)) / u64::from(FULL_LOAD_PERCENT)
}

/// Resample every policy and let its governor act. # C: O(N_policies)
pub fn sample(now_ns: u64) {
    for policy in cpufreq::policies() {
        let Some(cpu) = policy.cpus.first().copied() else { continue; };
        let Some(load_percent) = busy_percent(cpu) else { continue; };
        let governor = cpufreq::governor::by_name(policy.governor());
        let sampled = governor.is_some_and(|gov| gov.sampled);
        if sampled {
            let demand = Demand {
                load_percent,
                util: utilisation(load_percent),
                capacity: CAPACITY_SCALE,
                iowait_boost: 0,
            };
            let Some(target) = cpufreq::govern_target(&policy, &demand) else { continue; };
            let _ = cpufreq::util::submit(cpu, &policy, target, now_ns);
            continue;
        }
        cpufreq::util::update_util(cpu, utilisation(load_percent), CAPACITY_SCALE, false,
                                   now_ns, SAMPLE_PERIOD_NS);
    }
}

/// Start resampling. Called once from kernel init, after the timer registry
/// exists. # C: O(1)
pub fn start() {
    // SAFETY: kernel init installs this one scheduler handoff before sampling starts.
    unsafe { cpufreq::set_deferred_transition(crate::cpufreq_work::defer); }
    timer::register_periodic(SAMPLE_PERIOD_NS, sample);
}
