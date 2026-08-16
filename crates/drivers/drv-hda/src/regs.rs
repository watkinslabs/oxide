// Typed MMIO over the controller's BAR0 register file. Nothing here decides
// anything; every offset and bit comes from `uapi`.

#![cfg(target_os = "oxide-kernel")]

use crate::uapi::*;

/// A mapped controller register file.
#[derive(Copy, Clone)]
pub struct Regs {
    base: u64,
}

impl Regs {
    /// # C: O(1)
    pub fn new(base_va: u64) -> Self { Self { base: base_va } }

    /// # C: O(1)
    pub fn r8(&self, offset: u64) -> u8 {
        // SAFETY: `Regs::new` is only built from an owned BAR0 mapping whose
        // span covers the controller register file; every offset is inside it.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u8) }
    }
    /// # C: O(1)
    pub fn r16(&self, offset: u64) -> u16 {
        // SAFETY: as r8 — the controller register file mapping owns this span
        // and every register offset used here is naturally aligned.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u16) }
    }
    /// # C: O(1)
    pub fn r32(&self, offset: u64) -> u32 {
        // SAFETY: as r8 — an aligned 4-byte read inside the owned BAR0 span.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) }
    }
    /// # C: O(1)
    pub fn w8(&self, offset: u64, value: u8) {
        // SAFETY: as r8 — a byte write to a controller register inside the
        // owned BAR0 mapping.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u8, value); }
    }
    /// # C: O(1)
    pub fn w16(&self, offset: u64, value: u16) {
        // SAFETY: as r8 — an aligned 2-byte controller register write inside
        // the owned BAR0 mapping.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u16, value); }
    }
    /// # C: O(1)
    pub fn w32(&self, offset: u64, value: u32) {
        // SAFETY: as r8 — an aligned 4-byte controller register write inside
        // the owned BAR0 mapping.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value); }
    }

    /// Read-modify-write a 32-bit register. # C: O(1)
    pub fn set32(&self, offset: u64, bits: u32) { self.w32(offset, self.r32(offset) | bits); }
    /// # C: O(1)
    pub fn clear32(&self, offset: u64, bits: u32) { self.w32(offset, self.r32(offset) & !bits); }
    /// # C: O(1)
    pub fn set8(&self, offset: u64, bits: u8) { self.w8(offset, self.r8(offset) | bits); }
    /// # C: O(1)
    pub fn clear8(&self, offset: u64, bits: u8) { self.w8(offset, self.r8(offset) & !bits); }

    /// Base offset of stream descriptor `index`. # C: O(1)
    pub fn sd(&self, index: u8) -> u64 { SD_BASE + SD_STRIDE * u64::from(index) }

    /// Output streams the controller implements. # C: O(1)
    pub fn output_streams(&self) -> u8 {
        ((self.r16(REG_GCAP) >> GCAP_OSS_SHIFT) & GCAP_STREAM_MASK) as u8
    }
    /// Input streams the controller implements. # C: O(1)
    pub fn input_streams(&self) -> u8 {
        ((self.r16(REG_GCAP) >> GCAP_ISS_SHIFT) & GCAP_STREAM_MASK) as u8
    }
    /// Bidirectional streams, which sit between the input and output blocks.
    /// # C: O(1)
    pub fn bidir_streams(&self) -> u8 {
        ((self.r16(REG_GCAP) >> GCAP_BSS_SHIFT) & GCAP_BSS_MASK) as u8
    }
    /// The controller accepts 64-bit DMA addresses. # C: O(1)
    pub fn addr64(&self) -> bool { self.r16(REG_GCAP) & GCAP_64OK != 0 }
}
