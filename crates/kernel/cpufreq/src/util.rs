// The scheduler's entry into cpufreq: the utilisation hook the load-average
// update calls.
//
// This is what makes utilisation-driven scaling different from sampling: the
// frequency can move on the wakeup that created the demand rather than at the
// next sampling boundary. Everything it costs is paid on the scheduler's own
// path, so it does as little as possible — a rate-limit check, the boost
// decay, and a resolution — and does nothing at all under a governor that
// does not consume the signal.

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
    if crate::suspended() { return; }
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
    if submit(cpu, &policy, target, now_ns) { LAST_UPDATE_NS[cpu].store(now_ns, Ordering::Relaxed); }
}

/// Submit one scheduler-originated target. Fast drivers execute directly;
/// every other driver must be accepted by the scheduler's process-context
/// handoff, because clock and regulator providers may sleep. # C: O(N_entries)
pub fn submit(cpu: usize, policy: &alloc::sync::Arc<Policy>, target: Target, now_ns: u64) -> bool {
    let Some(driver) = crate::driver::driver() else { return false; };
    if driver.ops.fast_switch_possible(policy) {
        let _ = crate::driver::fast_switch(policy, target, now_ns);
        return true;
    }
    crate::driver::defer_transition(cpu, target, now_ns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use crate::{CpufreqOps, FreqEntry, FreqTable, Policy};

    static DEFERRED: AtomicUsize = AtomicUsize::new(0);
    static DIRECT: AtomicUsize = AtomicUsize::new(0);
    static FAST: AtomicUsize = AtomicUsize::new(0);

    struct Slow;
    impl CpufreqOps for Slow {
        fn target_index(&self, _policy: &Policy, _index: usize) -> vfs::KResult<()> {
            DIRECT.fetch_add(1, Ordering::Relaxed); Ok(())
        }
    }

    struct Fast;
    impl CpufreqOps for Fast {
        fn target_index(&self, _policy: &Policy, _index: usize) -> vfs::KResult<()> {
            DIRECT.fetch_add(1, Ordering::Relaxed); Ok(())
        }

        fn fast_switch_possible(&self, policy: &Policy) -> bool { policy.related_cpus == [0] }

        fn fast_switch(&self, _policy: &Policy, _index: usize) -> vfs::KResult<()> {
            FAST.fetch_add(1, Ordering::Relaxed); Ok(())
        }
    }

    fn defer(cpu: usize, target: Target, now_ns: u64) -> bool {
        assert_eq!(cpu, 0); assert_eq!(target, Target::at_least(2_000)); assert_eq!(now_ns, 7);
        DEFERRED.fetch_add(1, Ordering::Relaxed); true
    }

    #[test]
    fn a_nonfast_driver_is_handed_to_process_context_not_called_by_the_scheduler() {
        let _guard = crate::driver::test_guard();
        DEFERRED.store(0, Ordering::Relaxed); DIRECT.store(0, Ordering::Relaxed); FAST.store(0, Ordering::Relaxed);
        crate::register_driver("slow", Arc::new(Slow)).expect("driver");
        let table = FreqTable::new(alloc::vec![FreqEntry::new(1_000, 0), FreqEntry::new(2_000, 1)]).expect("table");
        let policy = Policy::new(alloc::vec![0], table, 1, 1_000, "schedutil").expect("policy");
        // SAFETY: test guard serialises this process-global scheduler handoff.
        unsafe { crate::set_deferred_transition(defer); }
        assert!(submit(0, &policy, Target::at_least(2_000), 7));
        assert_eq!(DEFERRED.load(Ordering::Relaxed), 1);
        assert_eq!(DIRECT.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_policy_admitted_by_the_driver_fast_switches_on_the_scheduler_path() {
        let _guard = crate::driver::test_guard();
        DEFERRED.store(0, Ordering::Relaxed); DIRECT.store(0, Ordering::Relaxed); FAST.store(0, Ordering::Relaxed);
        crate::register_driver("fast", Arc::new(Fast)).expect("driver");
        let table = FreqTable::new(alloc::vec![FreqEntry::new(1_000, 0), FreqEntry::new(2_000, 1)]).expect("table");
        let policy = Policy::new(alloc::vec![0], table, 1, 1_000, "schedutil").expect("policy");
        // SAFETY: test guard serialises this process-global scheduler handoff.
        unsafe { crate::set_deferred_transition(defer); }
        assert!(submit(0, &policy, Target::at_least(2_000), 7));
        assert_eq!(FAST.load(Ordering::Relaxed), 1);
        assert_eq!(DIRECT.load(Ordering::Relaxed), 0);
        assert_eq!(DEFERRED.load(Ordering::Relaxed), 0);
    }
}
