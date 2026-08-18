//! Typed DT CPU-idle records.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// One CPU's complete PSCI idle-state ladder, excluding architectural WFI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuIdleTable { pub cpu_mpidr: u64, pub states: Vec<CpuIdleState> }

/// One enabled `arm,idle-state` the CPU references by phandle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuIdleState {
    pub name: String,
    pub description: String,
    /// Worst wakeup latency in microseconds. This is either the declared
    /// `wakeup-latency-us` or the entry plus exit latency fallback.
    pub wakeup_latency_us: u32,
    pub target_residency_us: u32,
    pub local_timer_stop: bool,
    pub psci_suspend_param: u32,
}
