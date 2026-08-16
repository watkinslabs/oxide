// The idle driver: one state table for the machine, and the per-CPU counters
// and predictor that go with it.
//
// One driver at a time. A second registered table would leave two answers to
// "what is state 2", and every counter, attribute and governor decision is
// keyed by that index.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Devices, Spinlock};
use vfs::{KResult, VfsError};

use crate::governor::{default_governor, Governor, State as GovState};
use crate::state::{validate, IdleState, TableError};
use crate::usage::{new_usage, StateUsage};

/// The provider half of the driver: how a state is actually entered.
pub trait IdleOps: Send + Sync {
    /// Put this CPU into `index`, returning the state actually entered — a
    /// driver may substitute a shallower one. `Err` means it refused, and the
    /// CPU did not sleep. # C: O(1)
    fn enter(&self, index: usize, state: &IdleState) -> KResult<usize>;
}

/// Everything one CPU carries.
pub struct Device {
    pub usage: Vec<StateUsage>,
    pub governor: GovState,
    /// Measured length of the last sleep, nanoseconds; zero after a refusal.
    pub last_residency_ns: u64,
    /// Whether this CPU participates at all.
    pub enabled: bool,
}

/// The registered driver.
pub struct Driver {
    name: String,
    states: Vec<IdleState>,
    ops: Arc<dyn IdleOps>,
    devices: Spinlock<Vec<Device>, Devices>,
    governor: Spinlock<Governor, Devices>,
}

impl Driver {
    /// Driver name, as `current_driver` reads it back. # C: O(1)
    pub fn name(&self) -> &str { &self.name }
    /// The state table. # C: O(1)
    pub fn states(&self) -> &[IdleState] { &self.states }
    /// The governor every CPU runs. # C: O(1)
    pub fn governor(&self) -> Governor { *self.governor.lock() }
    /// The provider. # C: O(1)
    pub fn ops(&self) -> &Arc<dyn IdleOps> { &self.ops }

    /// Select a governor, resetting every CPU's predictor: the counters a
    /// governor learned are its own, and handing them to a different one that
    /// reads the same fields differently is worse than starting fresh.
    /// # C: O(N_cpus)
    pub fn set_governor(&self, governor: Governor) {
        *self.governor.lock() = governor;
        let mut devices = self.devices.lock();
        for device in devices.iter_mut() { device.governor = GovState::new(governor.kind); }
    }

    /// Read one CPU's counters. # C: O(N_states)
    pub fn usage(&self, cpu: usize) -> Option<Vec<StateUsage>> {
        self.devices.lock().get(cpu).map(|device| device.usage.clone())
    }

    /// Apply a `disable` write for one state on one CPU. # C: O(1)
    pub fn set_disable(&self, cpu: usize, index: usize, disable: bool) -> KResult<()> {
        let mut devices = self.devices.lock();
        let device = devices.get_mut(cpu).ok_or(VfsError::Enoent)?;
        let slot = device.usage.get_mut(index).ok_or(VfsError::Enoent)?;
        slot.set_user_disable(disable);
        Ok(())
    }

    /// Run one closure against a CPU's mutable half. # C: O(closure)
    pub(crate) fn with_device<R>(&self, cpu: usize, f: impl FnOnce(&mut Device) -> R)
        -> Option<R>
    {
        let mut devices = self.devices.lock();
        devices.get_mut(cpu).map(f)
    }

    /// How many CPUs the driver was built for. # C: O(1)
    pub fn cpu_count(&self) -> usize { self.devices.lock().len() }
}

static DRIVER: Spinlock<Option<Arc<Driver>>, Devices> = Spinlock::new(None);

/// The registered driver, if there is one. # C: O(1)
pub fn driver() -> Option<Arc<Driver>> { DRIVER.lock().clone() }

/// Register the machine's idle driver. # C: O(N_cpus * N_states)
pub fn register(name: &str, states: Vec<IdleState>, ops: Arc<dyn IdleOps>, cpus: usize)
    -> Result<Arc<Driver>, TableError>
{
    validate(&states)?;
    let governor = default_governor();
    let devices: Vec<Device> = (0..cpus.max(1)).map(|_| Device {
        usage: new_usage(&states),
        governor: GovState::new(governor.kind),
        last_residency_ns: 0,
        enabled: true,
    }).collect();
    let driver = Arc::new(Driver {
        name: String::from(name),
        states,
        ops,
        devices: Spinlock::new(devices),
        governor: Spinlock::new(governor),
    });
    let mut slot = DRIVER.lock();
    if slot.is_some() { return Err(TableError::AlreadyRegistered); }
    *slot = Some(Arc::clone(&driver));
    Ok(driver)
}

/// Withdraw the registered driver so a platform one can take its place. The
/// generic architecture-halt table is registered before anything has read the
/// firmware; a provider that later finds a real state ladder replaces it
/// rather than being refused. Every per-CPU counter goes with it, because the
/// state indexes they were keyed by no longer mean the same thing. # C: O(1)
pub fn unregister() -> bool { DRIVER.lock().take().is_some() }

/// Forget the registered driver. # C: O(1)
#[cfg(test)]
pub fn clear_for_tests() { *DRIVER.lock() = None; }

/// There is one registered driver for the whole process, so every test that
/// registers one must hold this. One lock, not one per test module: two locks
/// over one global is the same race the single-driver rule exists to prevent.
#[cfg(test)]
pub static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take the test lock and start from an empty registry. # C: O(1)
#[cfg(test)]
pub fn test_guard() -> std::sync::MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    clear_for_tests();
    guard
}
