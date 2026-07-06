// PCIe ECAM config-space accessor for x86_64. docs/34 requires ECAM-only
// config cycles, so the boot device-map publishes a kernel VA for the ACPI
// MCFG segment before PCI enumeration runs.

#[cfg(target_arch = "x86_64")]
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_arch = "x86_64")]
pub static ECAM_BASE_VA: AtomicU64 = AtomicU64::new(0);

#[cfg(target_arch = "x86_64")]
pub struct EcamPci {
    pub base_va: u64,
}

#[cfg(target_arch = "x86_64")]
impl EcamPci {
    /// Build from the boot-published ECAM VA. # C: O(1)
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

    /// Read a 4-byte aligned dword from PCIe ECAM config space.
    /// # C: O(1)
    pub fn read32(bus: u8, dev: u8, func: u8, reg: u8) -> u32 {
        Self::from_published().map(|r| r.read32_at(bus, dev, func, reg)).unwrap_or(u32::MAX)
    }

    /// Write a 4-byte aligned dword to PCIe ECAM config space.
    /// # C: O(1)
    pub fn write32(bus: u8, dev: u8, func: u8, reg: u8, val: u32) {
        if let Some(r) = Self::from_published() {
            r.write32_at(bus, dev, func, reg, val);
        }
    }

    fn read32_at(&self, bus: u8, dev: u8, func: u8, reg: u8) -> u32 {
        let p = self.ecam_addr(bus, dev, func, reg) as *const u32;
        // SAFETY: ECAM_BASE_VA is published only after the MCFG aperture is
        // mapped Device-uncacheable; aligned volatile load hits config space.
        unsafe { core::ptr::read_volatile(p) }
    }

    fn write32_at(&self, bus: u8, dev: u8, func: u8, reg: u8, val: u32) {
        let p = self.ecam_addr(bus, dev, func, reg) as *mut u32;
        // SAFETY: same mapping contract as read32_at; aligned volatile store
        // writes the requested device config dword.
        unsafe { core::ptr::write_volatile(p, val); }
    }
}

#[cfg(target_arch = "x86_64")]
impl pci::ConfigSpaceReader for EcamPci {
    fn read32(&self, bdf: pci::Bdf, offset: u8) -> u32 {
        self.read32_at(bdf.bus, bdf.device, bdf.function, offset)
    }
    fn write32(&self, bdf: pci::Bdf, offset: u8, val: u32) {
        self.write32_at(bdf.bus, bdf.device, bdf.function, offset, val);
    }
}
