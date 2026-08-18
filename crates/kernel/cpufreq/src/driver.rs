// The scaling driver and the registry of policies built on it.
//
// One driver at a time, and one policy per clock domain. A CPU that appeared
// in two policies would have two answers to "what may this run at", and the
// looser of the two would silently win whichever wrote last.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use sync::{Devices, Spinlock};
use vfs::{KResult, VfsError};

use crate::governor::{by_name, default_governor, ondemand, Demand, Snapshot, Target};
use crate::policy::{LimitSource, Policy, Request};
use crate::uapi::Relation;

/// Scheduler-owned process-context handoff for a non-fast transition.
pub type DeferredTransition = fn(usize, Target, u64) -> bool;

/// The provider half of the scaling driver.
pub trait CpufreqOps: Send + Sync {
    /// Program the operating point at table index `index`. # C: O(provider)
    fn target_index(&self, policy: &Policy, index: usize) -> KResult<()>;

    /// Frequency the hardware is actually at, kilohertz. `None` where the
    /// platform cannot be read back. # C: O(provider)
    fn get(&self, cpu: usize) -> Option<u32> { let _ = cpu; None }

    /// Whether a target may be programmed from a scheduler callback, with no
    /// sleeping and no notification round. # C: O(1)
    fn fast_switch_possible(&self, policy: &Policy) -> bool { let _ = policy; false }

    /// Program one scheduler-originated target without sleeping. Implementors
    /// that admit fast switching override this separately from `target_index`,
    /// whose normal path may need cross-CPU coordination. # C: O(provider)
    fn fast_switch(&self, policy: &Policy, index: usize) -> KResult<()> {
        self.target_index(policy, index)
    }

    /// Establish this policy's suspend OPP and return its table index. # C: O(provider)
    fn suspend(&self, policy: &Policy) -> KResult<Option<usize>> { let _ = policy; Ok(None) }

    /// Resume provider state after a system suspend. # C: O(provider)
    fn resume(&self, policy: &Policy) -> KResult<()> { let _ = policy; Ok(()) }
}

/// The registered driver.
pub struct Driver { pub name: String, pub ops: Arc<dyn CpufreqOps> }

static DRIVER: Spinlock<Option<Arc<Driver>>, Devices> = Spinlock::new(None);
static POLICIES: Spinlock<Vec<Arc<Policy>>, Devices> = Spinlock::new(Vec::new());
/// Monotonic time of the last programmed transition, for the rate limit.
static LAST_UPDATE_NS: AtomicU64 = AtomicU64::new(0);
static DEFERRED_TRANSITION: AtomicUsize = AtomicUsize::new(0);
static SUSPENDED: AtomicBool = AtomicBool::new(false);

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
    let (driver, index, freq, cur) = resolve_target(policy, target)?;
    if freq == cur { return Ok(freq); }
    driver.ops.target_index(policy, index)?;
    record_transition(policy, freq, now_ns);
    Ok(freq)
}

/// Program a scheduler-originated target through a driver's non-sleeping
/// callback. Callers must first establish that this policy admits it.
/// # C: O(N_entries + provider)
pub fn fast_switch(policy: &Arc<Policy>, target: Target, now_ns: u64) -> KResult<u32> {
    let (driver, index, freq, cur) = resolve_target(policy, target)?;
    if freq == cur { return Ok(freq); }
    driver.ops.fast_switch(policy, index)?;
    record_transition(policy, freq, now_ns);
    Ok(freq)
}

/// Resolve a request and preserve the state snapshot that made it valid.
/// # C: O(N_entries)
fn resolve_target(policy: &Arc<Policy>, target: Target) -> KResult<(Arc<Driver>, usize, u32, u32)> {
    let driver = driver().ok_or(VfsError::Enodev)?;
    let (limits, boost, cur) = policy.with_state(|state| (state.limits, state.boost, state.cur));
    let index = policy.table.resolve(target.freq_khz, limits.min, limits.max, target.relation, boost)
        .ok_or(VfsError::Einval)?;
    Ok((driver, index, policy.table.entries[index].frequency, cur))
}

/// Commit the exact rate accepted by the provider. # C: O(N_entries)
fn record_transition(policy: &Arc<Policy>, freq: u32, now_ns: u64) {
    policy.with_state(|state| { state.cur = freq; state.stats.record(freq, now_ns); });
    LAST_UPDATE_NS.store(now_ns, Ordering::Relaxed);
}

/// Resolve the policy governor's target without programming hardware. # C: O(N_entries)
pub fn govern_target(policy: &Arc<Policy>, demand: &Demand) -> Option<Target> {
    let governor = by_name(policy.governor()).unwrap_or_else(default_governor);
    let tunables = ondemand::Tunables::from_latency(policy.transition_latency_ns);
    let snapshot = snapshot(policy);
    crate::governor::registry::govern(governor.kind, &snapshot, demand, &tunables)
}

/// Run the policy's governor and program whatever it asks for. # C: O(N_entries)
pub fn govern(policy: &Arc<Policy>, demand: &Demand, now_ns: u64) -> KResult<Option<u32>> {
    if suspended() { return Ok(None); }
    let Some(target) = govern_target(policy, demand) else { return Ok(None); };
    drive(policy, target, now_ns).map(Some)
}

/// Apply a limit request and re-drive the policy, because a cap that does not
/// take effect until the next sample is a cap that is not in force.
/// # C: O(N_entries + N_sources + N_thermal)
pub fn set_limits(policy: &Arc<Policy>, source: LimitSource, request: Request, now_ns: u64)
    -> KResult<()>
{
    policy.set_request(source, request);
    retarget_limits(policy, now_ns)
}

/// Apply one firmware processor's thermal request and re-drive its shared
/// policy. Releasing one processor does not release a cap held by another
/// processor in the same clock domain. # C: O(N_entries + N_sources + N_thermal)
pub fn set_thermal_limit(policy: &Arc<Policy>, key: usize, request: Request, now_ns: u64)
    -> KResult<()>
{
    policy.set_thermal_request(key, request);
    retarget_limits(policy, now_ns)
}

/// Re-target a policy after its aggregated constraints changed. # C: O(N_entries)
fn retarget_limits(policy: &Arc<Policy>, now_ns: u64) -> KResult<()> {
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

/// Install the scheduler's non-fast transition handoff before utilisation
/// updates may encounter a driver that permits sleeping. # C: O(1)
/// # SAFETY: boot installs one matching function before scheduler cpufreq use.
pub unsafe fn set_deferred_transition(hook: DeferredTransition) {
    DEFERRED_TRANSITION.store(hook as usize, Ordering::Release);
}

/// Hand a scheduler-originated non-fast transition to process context.
/// # C: O(1)
pub fn defer_transition(cpu: usize, target: Target, now_ns: u64) -> bool {
    let raw = DEFERRED_TRANSITION.load(Ordering::Acquire);
    if raw == 0 { return false; }
    // SAFETY: setter publishes only a DeferredTransition with this exact ABI.
    let hook: DeferredTransition = unsafe { core::mem::transmute(raw) };
    hook(cpu, target, now_ns)
}

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
    DEFERRED_TRANSITION.store(0, Ordering::Relaxed);
    SUSPENDED.store(false, Ordering::Relaxed);
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

/// Whether CPU-frequency governors are stopped for a system suspend. # C: O(1)
pub fn suspended() -> bool { SUSPENDED.load(Ordering::Acquire) }

/// Suspend all policy governors and let each driver establish its suspend OPP.
/// Driver errors are isolated to their policy so system sleep can continue. # C: O(policies + provider)
/// # Sleeps: yes
pub fn suspend() {
    if SUSPENDED.load(Ordering::Acquire) { return; }
    let Some(driver) = driver() else { return; };
    for policy in policies() {
        if let Ok(Some(index)) = driver.ops.suspend(&policy) {
            if let Some(entry) = policy.table.entries.get(index) {
                policy.with_state(|state| state.cur = entry.frequency);
            }
        }
    }
    SUSPENDED.store(true, Ordering::Release);
}

/// Resume drivers and allow their governors to choose normal operating points. # C: O(policies + provider)
/// # Sleeps: yes
pub fn resume() {
    if !SUSPENDED.swap(false, Ordering::AcqRel) { return; }
    let Some(driver) = driver() else { return; };
    for policy in policies() { let _ = driver.ops.resume(&policy); }
}

#[cfg(test)]
#[path = "tests/driver.rs"]
mod tests;
