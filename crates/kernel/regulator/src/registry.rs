//! Registered regulator-provider operations.

use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Devices, Spinlock};
use vfs::{KResult, VfsError};

/// A requested voltage and its allowed tolerance, in microvolts.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Voltage { pub target_uv: u32, pub min_uv: u32, pub max_uv: u32 }

impl Voltage {
    /// Whether the voltage range contains its requested target. # C: O(1)
    pub fn valid(self) -> bool { self.target_uv != 0 && self.min_uv <= self.target_uv && self.target_uv <= self.max_uv }
}

/// Hardware owner of one regulator voltage.
pub trait RegulatorOps: Send + Sync {
    /// Current hardware voltage in microvolts. # C: O(provider)
    fn voltage_uv(&self) -> Option<u32>;
    /// Program a voltage within the supplied range. # C: O(provider)
    fn set_voltage(&self, voltage: Voltage) -> KResult<()>;
}

/// One DT-addressable regulator provider.
pub struct Regulator { phandle: u32, ops: Arc<dyn RegulatorOps> }

impl Regulator {
    /// Device-tree phandle naming this regulator. # C: O(1)
    pub fn phandle(&self) -> u32 { self.phandle }
    /// Current voltage in microvolts. # C: O(provider)
    pub fn voltage_uv(&self) -> Option<u32> { self.ops.voltage_uv() }
    /// Program a voltage range. # C: O(provider)
    pub fn set_voltage(&self, voltage: Voltage) -> KResult<()> {
        if !voltage.valid() { return Err(VfsError::Einval); }
        self.ops.set_voltage(voltage)
    }
}

static REGULATORS: Spinlock<Vec<Arc<Regulator>>, Devices> = Spinlock::new(Vec::new());
/// Called after a newly registered owner becomes visible to lookups.
pub type AvailabilityListener = fn();
static AVAILABILITY_LISTENERS: Spinlock<Vec<AvailabilityListener>, Devices> = Spinlock::new(Vec::new());

/// Register one regulator owner at its device-tree phandle. # C: O(regulators)
pub fn register(phandle: u32, ops: Arc<dyn RegulatorOps>) -> KResult<Arc<Regulator>> {
    if phandle == 0 { return Err(VfsError::Einval); }
    let mut regulators = REGULATORS.lock();
    if regulators.iter().any(|regulator| regulator.phandle == phandle) { return Err(VfsError::Eexist); }
    let regulator = Arc::new(Regulator { phandle, ops });
    regulators.push(Arc::clone(&regulator));
    drop(regulators);
    notify_available();
    Ok(regulator)
}

/// Resolve a registered DT regulator phandle. # C: O(regulators)
pub fn by_phandle(phandle: u32) -> Option<Arc<Regulator>> {
    REGULATORS.lock().iter().find(|regulator| regulator.phandle == phandle).cloned()
}

/// Subscribe a platform-probe receiver to future regulator-owner registration. # C: O(listeners)
pub fn subscribe_availability(listener: AvailabilityListener) {
    let mut listeners = AVAILABILITY_LISTENERS.lock();
    if !listeners.iter().any(|registered| core::ptr::fn_addr_eq(*registered, listener)) {
        listeners.push(listener);
    }
}

fn notify_available() {
    let listeners = AVAILABILITY_LISTENERS.lock().clone();
    for listener in listeners { listener(); }
}

#[cfg(test)]
pub fn clear_for_tests() {
    REGULATORS.lock().clear();
    AVAILABILITY_LISTENERS.lock().clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    static AVAILABLE: AtomicUsize = AtomicUsize::new(0);
    static ALSO_AVAILABLE: AtomicUsize = AtomicUsize::new(0);

    fn available() { AVAILABLE.fetch_add(1, Ordering::Relaxed); }
    fn also_available() { ALSO_AVAILABLE.fetch_add(1, Ordering::Relaxed); }

    struct Mock { voltage: AtomicU32 }
    impl RegulatorOps for Mock {
        fn voltage_uv(&self) -> Option<u32> { Some(self.voltage.load(Ordering::Acquire)) }
        fn set_voltage(&self, voltage: Voltage) -> KResult<()> {
            self.voltage.store(voltage.target_uv, Ordering::Release); Ok(())
        }
    }

    #[test]
    fn a_regulator_validates_voltage_before_the_hardware_owner_sees_it() {
        clear_for_tests();
        AVAILABLE.store(0, Ordering::Relaxed);
        ALSO_AVAILABLE.store(0, Ordering::Relaxed);
        subscribe_availability(available);
        subscribe_availability(available);
        subscribe_availability(also_available);
        let regulator = register(8, Arc::new(Mock { voltage: AtomicU32::new(900_000) })).expect("regulator");
        let voltage = Voltage { target_uv: 1_000_000, min_uv: 950_000, max_uv: 1_050_000 };
        regulator.set_voltage(voltage).expect("voltage");
        assert_eq!(regulator.voltage_uv(), Some(1_000_000));
        assert_eq!(AVAILABLE.load(Ordering::Relaxed), 1);
        assert_eq!(ALSO_AVAILABLE.load(Ordering::Relaxed), 1);
        assert_eq!(regulator.set_voltage(Voltage { target_uv: 0, min_uv: 0, max_uv: 0 }), Err(VfsError::Einval));
    }
}
