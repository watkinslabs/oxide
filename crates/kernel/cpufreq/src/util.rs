// The scheduler's entry into cpufreq: the utilisation hook the load-average
// update calls.
//
// This is what makes utilisation-driven scaling different from sampling: the
// frequency can move on the wakeup that created the demand rather than at the
// next sampling boundary. Everything it costs is paid on the scheduler's own
// path, so it does as little as possible — a rate-limit check, the boost
// decay, and a resolution — and does nothing at all under a governor that
// does not consume the signal.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::{AtomicU64, Ordering};
use sync::{Devices, Spinlock};

use crate::governor::schedutil::{IowaitBoost, Tunables};
use crate::governor::{Demand, Snapshot, Target};
use crate::governor::input::CAPACITY_SCALE;
use crate::policy::Policy;

/// Per-CPU wait-for-IO boost. One slot per CPU, not per policy: the boost
/// follows the task that blocked, and two CPUs sharing a clock can be blocked
/// on different things.
static BOOST: Spinlock<[IowaitBoost; cpu::MAX_CPUS], Devices> =
    Spinlock::new([IowaitBoost { value: 0, pending: false, last_update_ns: 0 };
                   cpu::MAX_CPUS]);
/// Last time each CPU's hook actually programmed something.
static LAST_UPDATE_NS: [AtomicU64; cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; cpu::MAX_CPUS];

/// Governor that consumes this signal; every other one ignores it.
const UTIL_GOVERNOR: &str = "schedutil";

/// The scheduler's utilisation update.
///
/// `util` and `capacity` are out of `CAPACITY_SCALE`. `iowait` says the task
/// being woken was blocked on a device, which is the one case the utilisation
/// signal cannot see. # C: O(N_entries)
pub fn update_util(cpu: usize, util: u64, capacity: u64, iowait: bool, now_ns: u64,
                   tick_ns: u64)
{
    if cpu >= cpu::MAX_CPUS { return; }
    let Some(policy) = crate::driver::policy_for(cpu) else { return; };
    if policy.governor() != UTIL_GOVERNOR { return; }

    let boost = {
        let mut slots = BOOST.lock();
        let slot = &mut slots[cpu];
        let gap = now_ns.saturating_sub(slot.last_update_ns);
        slot.wakeup(iowait, gap, tick_ns);
        slot.last_update_ns = now_ns;
        slot.apply(if capacity == 0 { CAPACITY_SCALE } else { capacity })
    };

    let tunables = Tunables::from_latency(policy.transition_latency_ns);
    let last = LAST_UPDATE_NS[cpu].load(Ordering::Relaxed);
    if !crate::governor::schedutil::may_update(&tunables, now_ns, last, false) { return; }

    let snapshot = Snapshot {
        limits: policy.limits(), hw: policy.hw, cur: policy.cur(), setspeed: policy.setspeed(),
    };
    let demand = Demand { load_percent: 0, util, capacity, iowait_boost: boost };
    let Some(target) = crate::governor::schedutil::schedutil(&snapshot, &demand) else { return; };
    drive(&policy, target, now_ns);
    LAST_UPDATE_NS[cpu].store(now_ns, Ordering::Relaxed);
}

/// Program the target, discarding a failure: the scheduler cannot act on one,
/// and a driver that refuses a transition leaves the policy where it was.
/// # C: O(N_entries)
fn drive(policy: &alloc::sync::Arc<Policy>, target: Target, now_ns: u64) {
    let _ = crate::driver::drive(policy, target, now_ns);
}
