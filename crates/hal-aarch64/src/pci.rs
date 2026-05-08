// PCIe ECAM (Enhanced Configuration Access Mechanism) reader for
// aarch64 per ACPI MCFG / PCI Express base spec §7.2.2. Each
// (bus, dev, func, reg) tuple maps to a 4 KiB-stride MMIO offset
// from the per-segment ECAM base:
//
//     addr = base + (bus << 20) | (dev << 15) | (func << 12) | reg
//
// One bus = 1 MiB; one segment = 256 buses = 256 MiB. Caller is
// responsible for device-mapping the relevant range into kernel VA
// before constructing `EcamPci` with the matching base VA.
//
// Mirrors `hal_x86_64::pci::LegacyPci` so `pci::ConfigSpaceReader`
// drives both arches uniformly from `pci::enumerate`.

#[cfg(target_arch = "aarch64")]
use core::sync::atomic::{AtomicU64, Ordering};

/// Process-wide kernel VA for the ECAM segment. Set by the boot
/// device-map after MCFG decode publishes the PA. Zero means ECAM
/// has not been brought up yet.
#[cfg(target_arch = "aarch64")]
pub static ECAM_BASE_VA: AtomicU64 = AtomicU64::new(0);

/// ECAM-backed PCI config-space reader. Construct with the kernel
/// VA the device-map placed the ECAM region at.
#[cfg(target_arch = "aarch64")]
pub struct EcamPci {
    pub base_va: u64,
}

#[cfg(target_arch = "aarch64")]
impl EcamPci {
    /// Build from the published `ECAM_BASE_VA`. Returns `None` if
    /// the boot path didn't bring ECAM up (e.g. MCFG absent).
    /// # C: O(1) — atomic load + struct.
    pub fn from_published() -> Option<Self> {
        let v = ECAM_BASE_VA.load(Ordering::Acquire);
        if v == 0 { None } else { Some(Self { base_va: v }) }
    }

    #[inline]
    fn ecam_addr(&self, bus: u8, dev: u8, func: u8, reg: u8) -> u64 {
        self.base_va
            + ((bus  as u64) << 20)
            + ((dev  as u64) << 15)
            + ((func as u64) << 12)
            + ((reg  as u64) & 0xFC)
    }

    /// Read a 4-byte aligned dword from PCI config space.
    /// # SAFETY: caller asserts the matching ECAM page has been
    /// device-mapped (Device-nGnRnE) into `base_va`'s region; reads
    /// from non-existent BDFs return all-1s by hardware convention.
    /// # C: O(1)
    pub fn read32(&self, bus: u8, dev: u8, func: u8, reg: u8) -> u32 {
        let p = self.ecam_addr(bus, dev, func, reg) as *const u32;
        // SAFETY: per fn contract — Device-nGnRnE mapping lets the
        // load complete with the BDF-decoded read.
        unsafe { core::ptr::read_volatile(p) }
    }

    /// Write a 4-byte aligned dword to PCI config space.
    /// # SAFETY: same contract as read32; writes affect device
    /// state per BAR/cmd-reg semantics.
    /// # C: O(1)
    pub fn write32(&self, bus: u8, dev: u8, func: u8, reg: u8, val: u32) {
        let p = self.ecam_addr(bus, dev, func, reg) as *mut u32;
        // SAFETY: caller asserts the matching ECAM page is Device-nGnRnE-mapped at base_va; PCI config writes have hardware-defined effects per BAR / cmd-reg semantics; aligned u32 access.
        unsafe { core::ptr::write_volatile(p, val); }
    }
}

#[cfg(target_arch = "aarch64")]
impl pci::ConfigSpaceReader for EcamPci {
    fn read32(&self, bdf: pci::Bdf, offset: u8) -> u32 {
        Self::read32(self, bdf.bus, bdf.device, bdf.function, offset)
    }
    fn write32(&self, bdf: pci::Bdf, offset: u8, val: u32) {
        Self::write32(self, bdf.bus, bdf.device, bdf.function, offset, val);
    }
}
