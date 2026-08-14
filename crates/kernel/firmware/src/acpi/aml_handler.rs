//! Canonical AML OperationRegion backend boundary.

use aml::{AmlError, Handler, RegionAccess};
use sync::{Devices, Spinlock};

/// Kernel-supplied, fallible access to one AML OperationRegion field.
pub type RegionBackend = fn(RegionAccess, u64) -> Result<u64, AmlError>;

static BACKEND: Spinlock<Option<RegionBackend>, Devices> = Spinlock::new(None);

pub struct FirmwareHandler;

impl Handler for FirmwareHandler {
    fn access(&self, access: RegionAccess, value: u64) -> Result<u64, AmlError> {
        access_with(*BACKEND.lock(), access, value)
    }
}

fn access_with(backend: Option<RegionBackend>, access: RegionAccess, value: u64) -> Result<u64, AmlError> {
    backend.ok_or(AmlError::RegionAccessUnavailable)?(access, value)
}

/// Install the one architecture-owned AML OperationRegion backend. # C: O(1)
pub fn install_region_backend(backend: RegionBackend) {
    let mut installed = BACKEND.lock();
    if installed.is_none() { *installed = Some(backend); }
}

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
}
