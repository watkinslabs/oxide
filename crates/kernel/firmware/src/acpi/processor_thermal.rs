//! ACPI processor cooling devices backed by cpufreq policy constraints.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use thermal::CoolingOps;
use vfs::{KResult, VfsError};

use super::aml_eval;

/// The class-visible kind Linux exposes for an ACPI processor cooler.
const PROCESSOR_TYPE: &str = "Processor";
/// The shallow state plus three progressively deeper frequency reductions.
const MAX_STATE: u64 = 3;
/// Percent of the policy's hardware maximum removed by each state.
const REDUCTION_PERCENT: u32 = 20;
const PERCENT: u32 = 100;
/// Unique key for each live processor cooler's independent policy request.
static NEXT_REQUEST_KEY: AtomicUsize = AtomicUsize::new(0);

/// One ACPI processor cooling device, with its own request even when several
/// firmware CPUs share one cpufreq policy.
struct ProcessorCooling {
    policy: Arc<cpufreq::Policy>,
    request_key: usize,
    state: AtomicU64,
}

impl CoolingOps for ProcessorCooling {
    fn max_state(&self) -> KResult<u64> { Ok(MAX_STATE) }

    fn cur_state(&self) -> KResult<u64> { Ok(self.state.load(Ordering::Acquire)) }

    fn set_cur_state(&self, state: u64) -> KResult<()> {
        let cap = cap_for(self.policy.hw.max, state).ok_or(VfsError::Einval)?;
        let request = if state == 0 { cpufreq::Request::default() }
                      else { cpufreq::Request { min: None, max: Some(cap) } };
        cpufreq::set_thermal_limit(&self.policy, self.request_key, request, timekeeper::monotonic_ns())?;
        self.state.store(state, Ordering::Release);
        Ok(())
    }
}

/// Publish every ACPI processor that has a registered cpufreq policy as an
/// exact-path cooling device. It runs before ACPI thermal zones, so `_PSL`
/// references can bind while each zone is registered. # C: O(namespace * policies)
pub fn init() -> usize {
    let mut registered = 0;
    for scope in aml_eval::processor_scopes() {
        let Some(cpu) = cpu::logical_id_for_acpi_uid(scope.uid).map(|id| id as usize) else { continue; };
        let Some(policy) = cpufreq::policy_for(cpu) else { continue; };
        let cooling = Arc::new(ProcessorCooling {
            policy,
            request_key: NEXT_REQUEST_KEY.fetch_add(1, Ordering::Relaxed),
            state: AtomicU64::new(0),
        });
        if thermal::register_cdev_for_path(PROCESSOR_TYPE, &scope.path, cooling,
                                           timekeeper::monotonic_ns()).is_ok() {
            registered += 1;
        }
    }
    registered
}

/// Frequency ceiling for one cooling state, or `None` outside the device's
/// declared state ladder. # C: O(1)
fn cap_for(hw_max_khz: u32, state: u64) -> Option<u32> {
    if state > MAX_STATE { return None; }
    let reduction = u32::try_from(state).ok()?.saturating_mul(REDUCTION_PERCENT);
    Some(hw_max_khz.saturating_mul(PERCENT.saturating_sub(reduction)) / PERCENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_remove_one_fifth_of_the_hardware_ceiling_each() {
        assert_eq!(cap_for(2_400_000, 0), Some(2_400_000));
        assert_eq!(cap_for(2_400_000, 1), Some(1_920_000));
        assert_eq!(cap_for(2_400_000, 2), Some(1_440_000));
        assert_eq!(cap_for(2_400_000, 3), Some(960_000));
        assert_eq!(cap_for(2_400_000, 4), None);
    }
}
