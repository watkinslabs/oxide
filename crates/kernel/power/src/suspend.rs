// System sleep per `32a`.
//
// Module manifest:
// - `state`:     sleep-state identity, availability, sysfs label decoding.
// - `ops`:       the two platform operation tables and their registration.
// - `platform`:  which table each sequence step consults.
// - `sequence`:  the forward step order and the unwind for a failure at each.
// - `run`:       the orchestrator, over an injectable backend.
// - `freezer`:   the freeze decision, the pass cadence and the live phase flags.
// - `wakeup`:    wakeup-event accounting and the abort race.
// - `s2idle`:    the suspend-to-idle state machine and loop.
// - `syscore`:   core-subsystem callbacks, run with interrupts off.
// - `stats`:     the `suspend_stats` records.
// - `tunables`:  the `/sys/power` booleans and the `mem_sleep` selection.
// - `attrs`:     `/sys/power` attribute rendering and write parsing.
// - `sysfs_api`: the `/sys/power` surface as data plus show/store.
// - `wire`:      assembles the machine's backend from boot-installed hooks.
// - `psci_sleep`: the aarch64 platform sleep table (PSCI `SYSTEM_SUSPEND`).
// - `freezer_walk`: the freeze/thaw passes over the live task registry.
// - `s2idle_wait`:  the blocking primitives the idle loop parks on.
// - `boot`:      assembles the machine's wiring in one place.

pub mod state;
pub mod ops;
pub mod platform;
pub mod sequence;
pub mod run;
pub mod freezer;
pub mod wakeup;
pub mod s2idle;
pub mod syscore;
pub mod stats;
pub mod tunables;
pub mod attrs;
pub mod sysfs_api;
pub mod wire;
#[cfg(any(test, all(target_os = "oxide-kernel", target_arch = "x86_64")))] pub mod acpi_sleep;
// aarch64 deep sleep via PSCI SYSTEM_SUSPEND (`32a§9`). Present on aarch64 and
// in a hosted run, so its admission decisions stay testable; absent from an x86
// kernel build, which must not link the aarch64 HAL alongside its own.
#[cfg(any(target_arch = "aarch64", not(target_os = "oxide-kernel")))]
pub mod psci_sleep;
pub mod freezer_walk;
pub mod s2idle_wait;
pub mod boot;

pub use state::{SuspendState, StateSet};
pub use run::{pm_suspend, SuspendBackend};
pub use wakeup::{pm_system_wakeup, pm_system_irq_wakeup, pm_wakeup_pending};
pub use wire::{set_hooks, SuspendHooks};

/// Serialises tests that touch this subtree's module statics. `cargo test`
/// runs test functions on parallel threads, and the statics under test are
/// per-machine by design; without this the parallelism, not the code, decides
/// what a test observes.
/// # C: O(1)
#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}
