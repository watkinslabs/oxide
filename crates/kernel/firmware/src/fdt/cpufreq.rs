//! Device-tree CPU-frequency provider.
//!
//! Module manifest:
//! - `plan` — pure OPP-sharing domain admission.
//! - `assemble` — concrete clock/regulator domain assembly, host-tested.
//! - `platform` — aarch64 clock/regulator ownership and cpufreq registration.

mod plan;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
mod assemble;

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
mod platform;

pub use plan::{Candidate, DomainPlan, domains, initial_index};

/// Register each usable device-tree OPP policy. # C: O(FDT)
pub fn init() -> usize {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { return platform::init(); }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { 0 }
}

/// Enable workqueue-backed retries after per-CPU workers exist. # C: O(1)
pub fn start_deferred() {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { platform::start_deferred(); }
}
