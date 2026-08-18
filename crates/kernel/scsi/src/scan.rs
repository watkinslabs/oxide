//! LUN inquiry and capacity discovery before `sd*` publication.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use block::{BlockError, KResult};

use crate::{Command, DataDirection, Lun, Transport};

const INQUIRY_BYTES: usize = 36;
const CAPACITY_10_BYTES: usize = 8;
const CAPACITY_16_BYTES: usize = 32;
const DIRECT_ACCESS: u8 = 0;
const NO_LUN: u8 = 0x1f;

/// Geometry and device class observed while probing one addressed LUN.
/// # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ScannedLun { lun: Lun, peripheral: u8, block_size: u32, capacity: u64 }

impl ScannedLun {
    /// Addressed LUN that answered INQUIRY. # C: O(1)
    pub const fn lun(self) -> Lun { self.lun }

    /// SCSI peripheral-device type. # C: O(1)
    pub const fn peripheral(self) -> u8 { self.peripheral }

    /// Logical block size reported by the LUN. # C: O(1)
    pub const fn block_size(self) -> u32 { self.block_size }

    /// Count of logical blocks reported by the LUN. # C: O(1)
    pub const fn capacity(self) -> u64 { self.capacity }
}

/// Probe one LUN through INQUIRY then READ CAPACITY. A non-existent LUN is
/// distinct from a transport error, so callers can continue scanning a host.
/// # C: O(one inquiry and one or two capacity commands)
pub fn scan_lun(transport: &dyn Transport, lun: Lun) -> KResult<Option<ScannedLun>> {
    let mut inquiry = [0u8; INQUIRY_BYTES];
    transport.execute(lun, &Command::inquiry(), &mut inquiry, DataDirection::FromDevice)?;
    let peripheral = inquiry[0] & NO_LUN;
    if peripheral == NO_LUN { return Ok(None); }

    let mut capacity_10 = [0u8; CAPACITY_10_BYTES];
    transport.execute(lun, &Command::capacity_10(), &mut capacity_10, DataDirection::FromDevice)?;
    let last_10 = u32::from_be_bytes(capacity_10[..4].try_into().map_err(|_| BlockError::Eio)?);
    let (last, block_size) = if last_10 == u32::MAX {
        let mut capacity_16 = [0u8; CAPACITY_16_BYTES];
        transport.execute(lun, &Command::capacity_16(), &mut capacity_16, DataDirection::FromDevice)?;
        (u64::from_be_bytes(capacity_16[..8].try_into().map_err(|_| BlockError::Eio)?),
         u32::from_be_bytes(capacity_16[8..12].try_into().map_err(|_| BlockError::Eio)?))
    } else {
        (u64::from(last_10), u32::from_be_bytes(capacity_10[4..8].try_into().map_err(|_| BlockError::Eio)?))
    };
    if block_size < 512 || !block_size.is_power_of_two() { return Err(BlockError::Einval); }
    let capacity = last.checked_add(1).ok_or(BlockError::Eoverflow)?;
    Ok(Some(ScannedLun { lun, peripheral, block_size, capacity }))
}

/// Probe every reported LUN and publish direct-access devices in the shared
/// `sd*` namespace. A missing or failing LUN leaves the other reported LUNs
/// independently discoverable. # C: O(LUNs × inquiry/capacity)
pub fn scan_and_publish(transport: Arc<dyn Transport>, serial: Option<&str>) -> Vec<block::ScsiDiskName> {
    let mut names = Vec::new();
    for raw_lun in 0..=transport.max_lun().value() {
        let lun = Lun::new(raw_lun);
        let Ok(Some(found)) = scan_lun(transport.as_ref(), lun) else { continue; };
        if found.peripheral != DIRECT_ACCESS { continue; }
        if let Some(name) = crate::publish_lun(Arc::clone(&transport), lun, found.block_size, found.capacity,
                                                (lun == Lun::ZERO).then_some(serial).flatten()) {
            names.push(name);
        }
    }
    names
}
