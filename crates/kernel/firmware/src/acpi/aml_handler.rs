//! Canonical AML OperationRegion backend boundary.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use aml::{AmlError, AmlName, Handler, RegionAccess};
use sync::{Devices, Spinlock};

/// Kernel-supplied, fallible access to one AML OperationRegion field.
pub type RegionBackend = fn(RegionAccess, u64) -> Result<u64, AmlError>;

static BACKEND: AtomicUsize = AtomicUsize::new(0);
static NOTIFICATIONS: Spinlock<Vec<(String, u64)>, Devices> = Spinlock::new(Vec::new());

pub struct FirmwareHandler;

impl Handler for FirmwareHandler {
    fn access(&self, access: RegionAccess, value: u64) -> Result<u64, AmlError> {
        access_with(region_backend(), access, value)
    }

    fn notify(&self, path: &AmlName, value: u64) {
        NOTIFICATIONS.lock().push((path.as_string(), value));
    }
}

fn access_with(backend: Option<RegionBackend>, access: RegionAccess, value: u64) -> Result<u64, AmlError> {
    backend.ok_or(AmlError::RegionAccessUnavailable)?(access, value)
}

/// Install the one architecture-owned AML OperationRegion backend. # C: O(1)
pub fn install_region_backend(backend: RegionBackend) {
    let _ = BACKEND.compare_exchange(0, backend as usize, Ordering::AcqRel, Ordering::Acquire);
}

/// Resolve a naturally aligned SystemMemory transaction into its containing
/// page and byte offset. # C: O(1)
pub fn system_memory_location(base: u64, offset: u64, width: u64,
                              page_bytes: u64) -> Option<(u64, u64)> {
    if !page_bytes.is_power_of_two() { return None; }
    let bytes = match width { 8 => 1, 16 => 2, 32 => 4, 64 => 8, _ => return None };
    let pa = base.checked_add(offset)?;
    if pa & (bytes - 1) != 0 { return None; }
    let page_pa = pa & !(page_bytes - 1);
    let in_page = pa - page_pa;
    if in_page.checked_add(bytes)? > page_bytes { return None; }
    Some((page_pa, in_page))
}

/// Read or write one fixed register through the canonical OperationRegion
/// backend. # C: O(backend)
pub(crate) fn access_region(access: RegionAccess, value: u64) -> Result<u64, AmlError> {
    access_with(region_backend(), access, value)
}

fn region_backend() -> Option<RegionBackend> {
    let raw = BACKEND.load(Ordering::Acquire);
    if raw == 0 { return None; }
    // SAFETY: install_region_backend publishes only this exact function type.
    Some(unsafe { core::mem::transmute(raw) })
}

/// Take the AML `Notify` requests emitted by the last completed method.
/// Called only after the namespace lock is released. # C: O(N)
pub(crate) fn take_notifications() -> Vec<(String, u64)> {
    core::mem::take(&mut *NOTIFICATIONS.lock())
}

pub(crate) fn has_notifications() -> bool { !NOTIFICATIONS.lock().is_empty() }

#[cfg(test)]
mod tests {
    use super::*;
    use aml::{RegionAccessDirection, value::RegionSpace};

    fn access() -> RegionAccess {
        RegionAccess { space: RegionSpace::SystemMemory, base: 0, length: 1, offset: 0,
            width: 8, direction: RegionAccessDirection::Read, pci: None }
    }

    fn echo(_: RegionAccess, value: u64) -> Result<u64, AmlError> { Ok(value) }

    #[test]
    fn no_backend_refuses_region_access() {
        assert_eq!(access_with(None, access(), 0), Err(AmlError::RegionAccessUnavailable));
    }

    #[test]
    fn backend_receives_complete_access_and_value() {
        assert_eq!(access_with(Some(echo), access(), 0x5a), Ok(0x5a));
    }

    #[test]
    fn system_memory_registers_require_supported_natural_accesses() {
        assert_eq!(system_memory_location(0xfed8_1000, 4, 32, 4096),
                   Some((0xfed8_1000, 4)));
        assert_eq!(system_memory_location(0xfed8_1000, 3, 32, 4096), None);
        assert_eq!(system_memory_location(u64::MAX, 1, 8, 4096), None);
        assert_eq!(system_memory_location(0xfed8_1000, 0, 24, 4096), None);
        assert_eq!(system_memory_location(0xfed8_1000, 0, 8, 0), None);
    }
}
