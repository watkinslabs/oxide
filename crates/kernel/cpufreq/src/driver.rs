// The scaling driver and the registry of policies built on it.
//
// One driver at a time, and one policy per clock domain. A CPU that appeared
// in two policies would have two answers to "what may this run at", and the
// looser of the two would silently win whichever wrote last.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use sync::{Devices, Spinlock};
use vfs::{KResult, VfsError};

use crate::governor::{by_name, default_governor, ondemand, Demand, Snapshot, Target};
use crate::policy::{LimitSource, Policy, Request};
use crate::uapi::Relation;

/// The provider half of the scaling driver.
pub trait CpufreqOps: Send + Sync {
    /// Program the operating point at table index `index`. # C: O(provider)
    fn target_index(&self, policy: &Policy, index: usize) -> KResult<()>;

    /// Frequency the hardware is actually at, kilohertz. `None` where the
    /// platform cannot be read back. # C: O(provider)
    fn get(&self, cpu: usize) -> Option<u32> { let _ = cpu; None }

    /// Whether a target may be programmed from a scheduler callback, with no
    /// sleeping and no notification round. # C: O(1)
    fn fast_switch_possible(&self) -> bool { false }
}

/// The registered driver.
pub struct Driver { pub name: String, pub ops: Arc<dyn CpufreqOps> }

static DRIVER: Spinlock<Option<Arc<Driver>>, Devices> = Spinlock::new(None);
static POLICIES: Spinlock<Vec<Arc<Policy>>, Devices> = Spinlock::new(Vec::new());
/// Monotonic time of the last programmed transition, for the rate limit.
static LAST_UPDATE_NS: AtomicU64 = AtomicU64::new(0);

/// The registered driver, if there is one. # C: O(1)
pub fn driver() -> Option<Arc<Driver>> { DRIVER.lock().clone() }

/// Register the machine's scaling driver. # C: O(1)
pub fn register_driver(name: &str, ops: Arc<dyn CpufreqOps>) -> KResult<Arc<Driver>> {
    if name.is_empty() || name.len() > crate::uapi::NAME_LEN { return Err(VfsError::Einval); }
    let mut slot = DRIVER.lock();
    if slot.is_some() { return Err(VfsError::Ebusy); }
    let driver = Arc::new(Driver { name: String::from(name), ops });
    *slot = Some(Arc::clone(&driver));
    Ok(driver)
}

/// Every registered policy. # C: O(N_policies)
pub fn policies() -> Vec<Arc<Policy>> { POLICIES.lock().iter().map(Arc::clone).collect() }

/// The policy governing `cpu`. # C: O(N_policies * N_cpus)
pub fn policy_for(cpu: usize) -> Option<Arc<Policy>> {
    policies().into_iter().find(|policy| policy.related_cpus.contains(&cpu))
}

/// Register a policy, refusing one whose CPUs another policy already governs.
/// # C: O(N_policies * N_cpus)
pub fn register_policy(policy: Arc<Policy>) -> KResult<Arc<Policy>> {
    let mut registered = POLICIES.lock();
    for existing in registered.iter() {
        if policy.related_cpus.iter().any(|cpu| existing.related_cpus.contains(cpu)) {
            return Err(VfsError::Eexist);
        }
    }
    registered.push(Arc::clone(&policy));
    Ok(policy)
}

/// Build the governor's view of a policy. # C: O(1)
pub fn snapshot(policy: &Arc<Policy>) -> Snapshot {
    let state = policy.with_state(|state| (state.limits, state.cur, state.setspeed));
    Snapshot { limits: state.0, hw: policy.hw, cur: state.1, setspeed: state.2 }
}

/// Program `target` on `policy`, resolving it against the limits in force.
///
/// A resolution that lands on the frequency already in force programs nothing:
/// the transition cost is real, and a governor that recomputes the same answer
/// every sample would otherwise pay it every time. # C: O(N_entries)
pub fn drive(policy: &Arc<Policy>, target: Target, now_ns: u64) -> KResult<u32> {
    let driver = driver().ok_or(VfsError::Enodev)?;
    let (limits, boost, cur) =
        policy.with_state(|state| (state.limits, state.boost, state.cur));
    let index = policy.table
        .resolve(target.freq_khz, limits.min, limits.max, target.relation, boost)
        .ok_or(VfsError::Einval)?;
    let freq = policy.table.entries[index].frequency;
    if freq == cur { return Ok(freq); }
    driver.ops.target_index(policy, index)?;
    policy.with_state(|state| { state.cur = freq; state.stats.record(freq, now_ns); });
    LAST_UPDATE_NS.store(now_ns, Ordering::Relaxed);
    Ok(freq)
}

/// Run the policy's governor and program whatever it asks for. # C: O(N_entries)
pub fn govern(policy: &Arc<Policy>, demand: &Demand, now_ns: u64) -> KResult<Option<u32>> {
    let governor = by_name(policy.governor()).unwrap_or_else(default_governor);
    let tunables = ondemand::Tunables::from_latency(policy.transition_latency_ns);
    let snapshot = snapshot(policy);
    let Some(target) = crate::governor::registry::govern(governor.kind, &snapshot, demand,
                                                         &tunables) else {
        return Ok(None);
    };
    drive(policy, target, now_ns).map(Some)
}

/// Apply a limit request and re-drive the policy, because a cap that does not
/// take effect until the next sample is a cap that is not in force.
/// # C: O(N_entries)
pub fn set_limits(policy: &Arc<Policy>, source: LimitSource, request: Request, now_ns: u64)
    -> KResult<()>
{
    policy.set_request(source, request);
    let limits = policy.limits();
    let cur = policy.cur();
    if cur > limits.max {
        drive(policy, Target::at_most(limits.max), now_ns)?;
    } else if cur < limits.min {
        drive(policy, Target::at_least(limits.min), now_ns)?;
    }
    Ok(())
}

/// Select a governor for one policy. # C: O(N_governors)
pub fn set_governor(policy: &Arc<Policy>, name: &str) -> KResult<()> {
    let governor = by_name(name).ok_or(VfsError::Einval)?;
    policy.with_state(|state| state.governor = governor.name);
    Ok(())
}

/// Frequency the hardware reports, falling back to the cached one where the
/// driver cannot read it. # C: O(provider)
pub fn cur_freq(policy: &Arc<Policy>) -> Option<u32> {
    let cpu = *policy.cpus.first()?;
    driver().and_then(|driver| driver.ops.get(cpu)).or_else(|| Some(policy.cur()))
}

/// Frequency the driver reads back from the hardware, with no fallback. What
/// `cpuinfo_cur_freq` reports, and `None` where the platform cannot say.
/// # C: O(provider)
pub fn hardware_freq(policy: &Arc<Policy>) -> Option<u32> {
    let cpu = *policy.cpus.first()?;
    driver()?.ops.get(cpu)
}

/// Time of the last programmed transition. # C: O(1)
pub fn last_update_ns() -> u64 { LAST_UPDATE_NS.load(Ordering::Relaxed) }

/// Whether a resolution would land on a boost point. # C: O(1)
pub fn set_boost(policy: &Arc<Policy>, enabled: bool) -> bool {
    if enabled && !policy.table.boost_supported() { return false; }
    policy.with_state(|state| state.boost = enabled);
    true
}

/// Empty the registry between tests. # C: O(1)
#[cfg(test)]
pub fn clear_for_tests() {
    *DRIVER.lock() = None;
    POLICIES.lock().clear();
    LAST_UPDATE_NS.store(0, Ordering::Relaxed);
}

/// One driver and one policy list for the whole process: every test that
/// registers either must hold this.
#[cfg(test)]
pub static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take the test lock and start from an empty registry. # C: O(1)
#[cfg(test)]
pub fn test_guard() -> std::sync::MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    clear_for_tests();
    guard
}

/// Relation a limits-driven re-target uses. # C: O(1)
pub const LIMIT_RELATION: Relation = Relation::Highest;
