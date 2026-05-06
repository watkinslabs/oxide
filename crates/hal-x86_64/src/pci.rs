// Legacy PCI config-space accessor on x86. CF8 = 32-bit address,
// CFC = 32-bit data. Per Intel® 82c93/PIIX-era convention; every
// modern board still exposes the legacy mechanism even when ECAM
// (PCIe extended config space) is also present.
//
// Address word: bit 31 = enable, bits 23..16 = bus, 15..11 = dev,
// 10..8 = func, 7..2 = reg (4-byte aligned), 1..0 = 0.

#[cfg(target_arch = "x86_64")]
use core::arch::asm;

#[cfg(target_arch = "x86_64")]
pub struct LegacyPci;

#[cfg(target_arch = "x86_64")]
impl LegacyPci {
    fn cf8_address(bus: u8, dev: u8, func: u8, reg: u8) -> u32 {
        0x8000_0000
            | ((bus  as u32) << 16)
            | ((dev  as u32) << 11)
            | ((func as u32) << 8)
            | ((reg  as u32) & 0xFC)
    }

    /// # SAFETY: writes to I/O port 0xCF8 + reads from 0xCFC are
    /// always-safe operations on x86 (no kernel-state side-effects
    /// outside the config-space mechanism's hardware semantics).
    /// # C: O(1)
    pub fn read32(bus: u8, dev: u8, func: u8, reg: u8) -> u32 {
        let addr = Self::cf8_address(bus, dev, func, reg);
        let val: u32;
        unsafe {
            asm!(
                "out dx, eax",
                in("dx") 0xCF8u16,
                in("eax") addr,
                options(nomem, nostack, preserves_flags),
            );
            asm!(
                "in eax, dx",
                in("dx") 0xCFCu16,
                out("eax") val,
                options(nomem, nostack, preserves_flags),
            );
        }
        val
    }

    /// # SAFETY: same as read32 — port I/O has well-defined
    /// hardware behavior; PCI config space writes affect device
    /// state only when the caller asks for it.
    /// # C: O(1)
    pub fn write32(bus: u8, dev: u8, func: u8, reg: u8, val: u32) {
        let addr = Self::cf8_address(bus, dev, func, reg);
        unsafe {
            asm!(
                "out dx, eax",
                in("dx") 0xCF8u16,
                in("eax") addr,
                options(nomem, nostack, preserves_flags),
            );
            asm!(
                "out dx, eax",
                in("dx") 0xCFCu16,
                in("eax") val,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl pci::ConfigSpaceReader for LegacyPci {
    fn read32(&self, bdf: pci::Bdf, offset: u8) -> u32 {
        Self::read32(bdf.bus, bdf.device, bdf.function, offset)
    }
    fn write32(&self, bdf: pci::Bdf, offset: u8, val: u32) {
        Self::write32(bdf.bus, bdf.device, bdf.function, offset, val);
    }
}
