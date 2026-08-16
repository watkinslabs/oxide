// The idle driver every machine gets, whatever its firmware describes.
//
// One state: the architecture's own halt. That is not a placeholder — it is
// what the hardware actually offers absent a platform description, and
// registering it is what makes the residency accounting real. A deeper ladder
// arrives from the platform provider and replaces this table.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use vfs::KResult;

use crate::driver::IdleOps;
use crate::state::{Entry, IdleState};

/// Name the driver reports through `current_driver`.
pub const DRIVER_NAME: &str = "oxide_idle";
/// Name of the one state.
pub const STATE_NAME: &str = "HALT";
/// Description of the one state.
pub const STATE_DESC: &str = "architecture halt until interrupt";

/// Cost of leaving the halt, microseconds. A halt returns on the interrupt
/// that ended it, so the cost is the interrupt entry itself.
pub const HALT_EXIT_LATENCY_US: u64 = 1;
/// Shortest sleep the halt is worth, microseconds.
pub const HALT_TARGET_RESIDENCY_US: u64 = 1;

struct Generic;

impl IdleOps for Generic {
    /// # C: O(1)
    fn enter(&self, index: usize, _state: &IdleState) -> KResult<usize> {
        #[cfg(target_arch = "x86_64")] hal_x86_64::halt();
        #[cfg(target_arch = "aarch64")] hal_aarch64::halt();
        Ok(index)
    }
}

/// The one-state table. # C: O(1)
pub fn states() -> alloc::vec::Vec<IdleState> {
    alloc::vec![IdleState::from_us(
        STATE_NAME, STATE_DESC, HALT_EXIT_LATENCY_US, HALT_TARGET_RESIDENCY_US, Entry::Halt,
    )]
}

/// Register the generic driver where the platform published none. A platform
/// provider that later finds a real ladder withdraws this one first.
/// # C: O(N_cpus)
pub fn init(cpus: usize) -> bool {
    if crate::driver::driver().is_some() { return false; }
    crate::driver::register(DRIVER_NAME, states(), Arc::new(Generic), cpus).is_ok()
}

/// Whether the driver currently registered is this fallback rather than a
/// platform one. # C: O(1)
pub fn is_generic() -> bool {
    crate::driver::driver().is_some_and(|driver| driver.name() == DRIVER_NAME)
}
