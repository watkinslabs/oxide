//! AQC113 ATL2 firmware-reset transaction.

pub const VENDOR_AQUANTIA: u16 = 0x1d6a;
pub const DEVICE_AQC113: u16 = 0x04c0;
pub const MIF_BOOT_REG: u64 = 0x3040;
pub const HOST_REQUEST_INTERRUPT: u64 = 0x0f00;
pub const HOST_REQUEST_INTERRUPT_CLEAR: u64 = 0x0f08;
pub const HOST_REQUEST_READY: u32 = 1;
pub const REQUEST_REBOOT: u32 = 1;
pub const STATUS_BOOT_STARTED: u32 = 1 << 24;
pub const STATUS_CRASH_INIT: u32 = 1 << 27;
pub const STATUS_BOOT_CODE_FAILED: u32 = 1 << 28;
pub const STATUS_FIRMWARE_INIT_FAILED: u32 = 1 << 29;
pub const STATUS_FIRMWARE_READY: u32 = 1 << 31;
pub const STATUS_FAILED: u32 = STATUS_CRASH_INIT | STATUS_BOOT_CODE_FAILED | STATUS_FIRMWARE_INIT_FAILED;
pub const POLL_INTERVAL_NS: u64 = 10_000;
pub const BOOT_START_TIMEOUT_NS: u64 = 200_000_000;
pub const FIRMWARE_READY_TIMEOUT_NS: u64 = 2_000_000_000;

/// MMIO and deadline owner for one reset transaction.
pub trait Access { fn read32(&mut self, offset: u64) -> u32; fn write32(&mut self, offset: u64, value: u32); fn now_ns(&mut self) -> u64; fn relax(&mut self); }
#[derive(Copy, Clone, Debug, Eq, PartialEq)] pub enum ResetError { BootStartTimeout, FirmwareReadyTimeout, FirmwareFailed, HostFirmwareRequired }
/// Exact native ATL2 AQC113 PCI identity. # C: O(1)
pub const fn matches(vendor: u16, device: u16) -> bool { vendor == VENDOR_AQUANTIA && device == DEVICE_AQC113 }
/// Reset one ATL2 controller and wait for its resident firmware. # C: bounded by firmware timeout
pub fn reset(access: &mut impl Access) -> Result<(), ResetError> {
    access.write32(HOST_REQUEST_INTERRUPT_CLEAR, HOST_REQUEST_READY); access.write32(MIF_BOOT_REG, REQUEST_REBOOT);
    let start = access.now_ns();
    let status = poll(access, start, BOOT_START_TIMEOUT_NS, |status| status != u32::MAX && status & STATUS_BOOT_STARTED != 0).ok_or(ResetError::BootStartTimeout)?;
    if status & STATUS_FAILED != 0 { return Err(ResetError::FirmwareFailed); }
    let ready_start = access.now_ns();
    loop {
        let status = access.read32(MIF_BOOT_REG);
        if status & STATUS_FAILED != 0 { return Err(ResetError::FirmwareFailed); }
        if access.read32(HOST_REQUEST_INTERRUPT) & HOST_REQUEST_READY != 0 { return Err(ResetError::HostFirmwareRequired); }
        if status & STATUS_FIRMWARE_READY != 0 { return Ok(()); }
        if access.now_ns().saturating_sub(ready_start) >= FIRMWARE_READY_TIMEOUT_NS { return Err(ResetError::FirmwareReadyTimeout); }
        access.relax();
    }
}
fn poll(access: &mut impl Access, start: u64, timeout: u64, done: impl Fn(u32) -> bool) -> Option<u32> { loop { let status = access.read32(MIF_BOOT_REG); if done(status) { return Some(status); } if access.now_ns().saturating_sub(start) >= timeout { return None; } access.relax(); } }

#[cfg(test)] mod tests {
    use super::*;
    struct Fake { statuses: [u32; 3], index: usize, host: u32, time: u64, writes: [(u64, u32); 2], write_count: usize }
    impl Access for Fake { fn read32(&mut self, offset: u64) -> u32 { if offset == HOST_REQUEST_INTERRUPT { self.host } else { let value = self.statuses[self.index.min(2)]; self.index += 1; value } } fn write32(&mut self, offset: u64, value: u32) { self.writes[self.write_count] = (offset, value); self.write_count += 1; } fn now_ns(&mut self) -> u64 { self.time } fn relax(&mut self) { self.time += POLL_INTERVAL_NS; } }
    #[test] fn resident_firmware_boots_before_any_queue_can_be_enabled() { let mut fake = Fake { statuses: [STATUS_BOOT_STARTED, STATUS_FIRMWARE_READY, STATUS_FIRMWARE_READY], index: 0, host: 0, time: 0, writes: [(0, 0); 2], write_count: 0 }; assert_eq!(reset(&mut fake), Ok(())); assert_eq!(fake.writes, [(HOST_REQUEST_INTERRUPT_CLEAR, HOST_REQUEST_READY), (MIF_BOOT_REG, REQUEST_REBOOT)]); }
    #[test] fn host_firmware_request_is_not_mistaken_for_a_ready_controller() { let mut fake = Fake { statuses: [STATUS_BOOT_STARTED, STATUS_FIRMWARE_READY, STATUS_FIRMWARE_READY], index: 0, host: HOST_REQUEST_READY, time: 0, writes: [(0, 0); 2], write_count: 0 }; assert_eq!(reset(&mut fake), Err(ResetError::HostFirmwareRequired)); }
}
