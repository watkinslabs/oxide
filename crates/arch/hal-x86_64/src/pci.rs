// PCIe ECAM config-space routing. Every published MCFG allocation owns one
// exact `(segment, bus range)` window; config transactions select it by BDF.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use pci::ConfigSpaceReader;
use sync::{Devices, Spinlock};

const LEGACY_CONFIG_ADDRESS: u16 = 0xCF8;
const LEGACY_CONFIG_DATA: u16 = 0xCFC;
const LEGACY_CONFIG_ENABLE: u32 = 1 << 31;
const LEGACY_WINDOW: EcamWindow = EcamWindow {
    base_va: 0,
    segment: 0,
    bus_start: 0,
    bus_end: u8::MAX,
};

// CF8 selects one config dword globally, so a transaction is address-write
// plus data access under one IRQ-safe lock. ECAM has independent MMIO pages
// and does not need this serialization.
static LEGACY_CONFIG_LOCK: Spinlock<(), Devices> = Spinlock::new(());

static ECAM_WINDOW_COUNT: AtomicU32 = AtomicU32::new(0);
static ECAM_WINDOW_BASE: [AtomicU64; pci::MAX_ECAM_WINDOWS]
    = [const { AtomicU64::new(0) }; pci::MAX_ECAM_WINDOWS];
static ECAM_WINDOW_SEGMENT: [AtomicU32; pci::MAX_ECAM_WINDOWS]
    = [const { AtomicU32::new(0) }; pci::MAX_ECAM_WINDOWS];
static ECAM_WINDOW_BUS_START: [AtomicU32; pci::MAX_ECAM_WINDOWS]
    = [const { AtomicU32::new(0) }; pci::MAX_ECAM_WINDOWS];
static ECAM_WINDOW_BUS_END: [AtomicU32; pci::MAX_ECAM_WINDOWS]
    = [const { AtomicU32::new(0) }; pci::MAX_ECAM_WINDOWS];

#[derive(Copy, Clone)]
pub struct EcamWindow {
    pub base_va: u64,
    pub segment: u16,
    pub bus_start: u8,
    pub bus_end: u8,
}

const EMPTY_WINDOW: EcamWindow = EcamWindow { base_va: 0, segment: 0, bus_start: 0, bus_end: 0 };

/// Publish every boot-mapped MCFG window before PCI enumeration. # C: O(N)
pub fn publish_windows(windows: &[EcamWindow]) {
    if windows.is_empty() || windows.len() > pci::MAX_ECAM_WINDOWS { return; }
    if ECAM_WINDOW_COUNT.load(Ordering::Acquire) != 0 { return; }
    for (i, w) in windows.iter().enumerate() {
        if w.base_va == 0 || w.bus_start > w.bus_end { return; }
        ECAM_WINDOW_BASE[i].store(w.base_va, Ordering::Relaxed);
        ECAM_WINDOW_SEGMENT[i].store(w.segment as u32, Ordering::Relaxed);
        ECAM_WINDOW_BUS_START[i].store(w.bus_start as u32, Ordering::Relaxed);
        ECAM_WINDOW_BUS_END[i].store(w.bus_end as u32, Ordering::Relaxed);
    }
    ECAM_WINDOW_COUNT.store(windows.len() as u32, Ordering::Release);
}

pub struct EcamPci {
    windows: [EcamWindow; pci::MAX_ECAM_WINDOWS],
    count: usize,
    legacy: bool,
}

impl EcamPci {
    /// Build the router from the atomically published MCFG window set. # C: O(N)
    pub fn from_published() -> Option<Self> {
        let count = ECAM_WINDOW_COUNT.load(Ordering::Acquire) as usize;
        if count == 0 {
            let mut windows = [EMPTY_WINDOW; pci::MAX_ECAM_WINDOWS];
            windows[0] = LEGACY_WINDOW;
            // Linux x86 uses configuration mechanism #1 when firmware has
            // no MCFG. The portable form is limited to segment 0 and the
            // conventional 256-byte configuration space. (Linux enables its
            // non-standard 4-KiB I/O extension only after an AMD platform
            // capability check.) It still discovers real PCI storage,
            // network, USB, and display controllers.
            return Some(Self { windows, count: 1, legacy: true });
        }
        if count > pci::MAX_ECAM_WINDOWS { return None; }
        let mut windows = [EMPTY_WINDOW; pci::MAX_ECAM_WINDOWS];
        for i in 0..count {
            windows[i] = EcamWindow {
                base_va: ECAM_WINDOW_BASE[i].load(Ordering::Relaxed),
                segment: ECAM_WINDOW_SEGMENT[i].load(Ordering::Relaxed) as u16,
                bus_start: ECAM_WINDOW_BUS_START[i].load(Ordering::Relaxed) as u8,
                bus_end: ECAM_WINDOW_BUS_END[i].load(Ordering::Relaxed) as u8,
            };
            if windows[i].base_va == 0 || windows[i].bus_start > windows[i].bus_end { return None; }
        }
        Some(Self { windows, count, legacy: false })
    }
    /// Exact host-bridge windows owned by this reader. # C: O(1)
    pub fn windows(&self) -> &[EcamWindow] { &self.windows[..self.count] }
    fn ecam_addr(&self, bdf: pci::Bdf, reg: u16) -> Option<u64> {
        if self.legacy { return None; }
        let w = self.windows().iter().find(|w| w.segment == bdf.segment
            && bdf.bus >= w.bus_start && bdf.bus <= w.bus_end)?;
        Some(w.base_va + (u64::from(bdf.bus - w.bus_start) << 20)
            + (u64::from(bdf.device) << 15) + (u64::from(bdf.function) << 12)
            + (u64::from(reg) & 0xffc))
    }
    fn read32_at(&self, bdf: pci::Bdf, reg: u16) -> u32 {
        if self.legacy { return legacy_read32(bdf, reg); }
        let Some(a) = self.ecam_addr(bdf, reg) else { return u32::MAX };
        // SAFETY: selected ECAM window was mapped Device-uncacheable before publication.
        unsafe { core::ptr::read_volatile(a as *const u32) }
    }
    fn write32_at(&self, bdf: pci::Bdf, reg: u16, val: u32) {
        if self.legacy { legacy_write32(bdf, reg, val); return; }
        let Some(a) = self.ecam_addr(bdf, reg) else { return };
        // SAFETY: selected ECAM window was mapped Device-uncacheable before publication.
        unsafe { core::ptr::write_volatile(a as *mut u32, val) }
    }
    /// Perform one naturally aligned AML PCI configuration transaction. # C: O(1)
    pub fn operation_region_access(&self, bdf: pci::Bdf, offset: u16, width: u64,
        write: Option<u64>) -> Option<u64> {
        let bytes = operation_region_bytes(offset, width)?;
        if self.legacy {
            legacy_address(bdf, offset)?;
        } else {
            self.ecam_addr(bdf, offset)?;
        }
        Some(match (bytes, write) {
            (1, None) => u64::from(self.read8_ext(bdf, offset)),
            (2, None) => u64::from(self.read16_ext(bdf, offset)),
            (4, None) => u64::from(self.read32_ext(bdf, offset)),
            (1, Some(value)) => { self.write8_ext(bdf, offset, value as u8); 0 }
            (2, Some(value)) => { self.write16_ext(bdf, offset, value as u16); 0 }
            (4, Some(value)) => { self.write32_ext(bdf, offset, value as u32); 0 }
            _ => return None,
        })
    }
}

fn operation_region_bytes(offset: u16, width: u64) -> Option<u16> {
    let bytes = match width { 8 => 1, 16 => 2, 32 => 4, _ => return None };
    if offset % bytes != 0 || offset.checked_add(bytes)? > pci::uapi::CFG_SPACE_SIZE as u16 { return None; }
    Some(bytes)
}

impl pci::ConfigSpaceReader for EcamPci {
    fn read32(&self, bdf: pci::Bdf, offset: u8) -> u32 { self.read32_at(bdf, u16::from(offset)) }
    fn write32(&self, bdf: pci::Bdf, offset: u8, val: u32) { self.write32_at(bdf, u16::from(offset), val) }
    fn read32_ext(&self, bdf: pci::Bdf, offset: u16) -> u32 { self.read32_at(bdf, offset) }
    fn write32_ext(&self, bdf: pci::Bdf, offset: u16, val: u32) { self.write32_at(bdf, offset, val) }
    fn read8_ext(&self, bdf: pci::Bdf, offset: u16) -> u8 {
        if self.legacy { return legacy_read8(bdf, offset); }
        let Some(a) = self.ecam_addr(bdf, offset) else { return u8::MAX };
        // SAFETY: selected ECAM function page is Device-uncacheable and byte-addressable.
        unsafe { core::ptr::read_volatile((a + u64::from(offset & 3)) as *const u8) }
    }
    fn read16_ext(&self, bdf: pci::Bdf, offset: u16) -> u16 {
        if self.legacy { return legacy_read16(bdf, offset); }
        let Some(a) = self.ecam_addr(bdf, offset) else { return u16::MAX };
        // SAFETY: selected ECAM function page is Device-uncacheable and word-aligned.
        unsafe { core::ptr::read_volatile((a + u64::from(offset & 3)) as *const u16) }
    }
    fn write8_ext(&self, bdf: pci::Bdf, offset: u16, val: u8) {
        if self.legacy { legacy_write8(bdf, offset, val); return; }
        let Some(a) = self.ecam_addr(bdf, offset) else { return };
        // SAFETY: selected ECAM function page is Device-uncacheable and byte-addressable.
        unsafe { core::ptr::write_volatile((a + u64::from(offset & 3)) as *mut u8, val) }
    }
    fn write16_ext(&self, bdf: pci::Bdf, offset: u16, val: u16) {
        if self.legacy { legacy_write16(bdf, offset, val); return; }
        let Some(a) = self.ecam_addr(bdf, offset) else { return };
        // SAFETY: selected ECAM function page is Device-uncacheable and word-aligned.
        unsafe { core::ptr::write_volatile((a + u64::from(offset & 3)) as *mut u16, val) }
    }
}

/// Legacy PCI configuration mechanism #1 address. It can only address segment
/// zero and the conventional 256-byte header/configuration area. # C: O(1)
const fn legacy_address(bdf: pci::Bdf, offset: u16) -> Option<u32> {
    if bdf.segment != 0 || bdf.device >= 32 || bdf.function >= 8 || offset >= 256 {
        return None;
    }
    Some(LEGACY_CONFIG_ENABLE | ((bdf.bus as u32) << 16)
        | ((bdf.device as u32) << 11) | ((bdf.function as u32) << 8)
        | ((offset & !3) as u32))
}

fn legacy_read32(bdf: pci::Bdf, offset: u16) -> u32 {
    let Some(address) = legacy_address(bdf, offset) else { return u32::MAX; };
    let _guard = LEGACY_CONFIG_LOCK.lock_irqsave::<crate::X86IrqGate>();
    // SAFETY: CF8/CFC are the architected x86 PCI configuration mechanism #1
    // ports; the lock keeps the selector and data transaction indivisible.
    unsafe { pio_out32(LEGACY_CONFIG_ADDRESS, address); pio_in32(LEGACY_CONFIG_DATA) }
}

fn legacy_write32(bdf: pci::Bdf, offset: u16, value: u32) {
    let Some(address) = legacy_address(bdf, offset) else { return; };
    let _guard = LEGACY_CONFIG_LOCK.lock_irqsave::<crate::X86IrqGate>();
    // SAFETY: as `legacy_read32`; the caller owns the selected config field.
    unsafe { pio_out32(LEGACY_CONFIG_ADDRESS, address); pio_out32(LEGACY_CONFIG_DATA, value); }
}

fn legacy_read8(bdf: pci::Bdf, offset: u16) -> u8 {
    let Some(address) = legacy_address(bdf, offset) else { return u8::MAX; };
    let _guard = LEGACY_CONFIG_LOCK.lock_irqsave::<crate::X86IrqGate>();
    // SAFETY: as `legacy_read32`; CFC+byte is the native byte transaction.
    unsafe { pio_out32(LEGACY_CONFIG_ADDRESS, address); pio_in8(LEGACY_CONFIG_DATA + (offset & 3)) }
}

fn legacy_read16(bdf: pci::Bdf, offset: u16) -> u16 {
    if offset & 1 != 0 { return u16::MAX; }
    let Some(address) = legacy_address(bdf, offset) else { return u16::MAX; };
    let _guard = LEGACY_CONFIG_LOCK.lock_irqsave::<crate::X86IrqGate>();
    // SAFETY: as `legacy_read32`; offset is naturally word-aligned.
    unsafe { pio_out32(LEGACY_CONFIG_ADDRESS, address); pio_in16(LEGACY_CONFIG_DATA + (offset & 3)) }
}

fn legacy_write8(bdf: pci::Bdf, offset: u16, value: u8) {
    let Some(address) = legacy_address(bdf, offset) else { return; };
    let _guard = LEGACY_CONFIG_LOCK.lock_irqsave::<crate::X86IrqGate>();
    // SAFETY: as `legacy_read32`; CFC+byte is the native byte transaction.
    unsafe { pio_out32(LEGACY_CONFIG_ADDRESS, address); pio_out8(LEGACY_CONFIG_DATA + (offset & 3), value); }
}

fn legacy_write16(bdf: pci::Bdf, offset: u16, value: u16) {
    if offset & 1 != 0 { return; }
    let Some(address) = legacy_address(bdf, offset) else { return; };
    let _guard = LEGACY_CONFIG_LOCK.lock_irqsave::<crate::X86IrqGate>();
    // SAFETY: as `legacy_read32`; offset is naturally word-aligned.
    unsafe { pio_out32(LEGACY_CONFIG_ADDRESS, address); pio_out16(LEGACY_CONFIG_DATA + (offset & 3), value); }
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn pio_in8(port: u16) -> u8 {
    let value: u8;
    // SAFETY: caller names an architected PCI config-data port.
    unsafe { core::arch::asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags)); }
    value
}
#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
unsafe fn pio_in8(_port: u16) -> u8 { u8::MAX }
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn pio_in16(port: u16) -> u16 {
    let value: u16;
    // SAFETY: caller names an architected PCI config-data port.
    unsafe { core::arch::asm!("in ax, dx", out("ax") value, in("dx") port, options(nomem, nostack, preserves_flags)); }
    value
}
#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
unsafe fn pio_in16(_port: u16) -> u16 { u16::MAX }
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn pio_in32(port: u16) -> u32 {
    let value: u32;
    // SAFETY: caller names an architected PCI config-data port.
    unsafe { core::arch::asm!("in eax, dx", out("eax") value, in("dx") port, options(nomem, nostack, preserves_flags)); }
    value
}
#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
unsafe fn pio_in32(_port: u16) -> u32 { u32::MAX }
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn pio_out8(port: u16, value: u8) {
    // SAFETY: caller names an architected PCI config-data port.
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags)); }
}
#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
unsafe fn pio_out8(_port: u16, _value: u8) {}
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn pio_out16(port: u16, value: u16) {
    // SAFETY: caller names an architected PCI config-data port.
    unsafe { core::arch::asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack, preserves_flags)); }
}
#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
unsafe fn pio_out16(_port: u16, _value: u16) {}
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn pio_out32(port: u16, value: u32) {
    // SAFETY: caller names an architected PCI config-data port.
    unsafe { core::arch::asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags)); }
}
#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
unsafe fn pio_out32(_port: u16, _value: u32) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_address_is_segment_zero_and_256_byte_limited() {
        let bdf = pci::Bdf { segment: 0, bus: 0x12, device: 0x1f, function: 7 };
        assert_eq!(legacy_address(bdf, 0xfc), Some(0x8012_fffc));
        assert_eq!(legacy_address(bdf, 0x03), Some(0x8012_ff00));
        assert_eq!(legacy_address(bdf, 0x100), None);
        assert_eq!(legacy_address(pci::Bdf { segment: 1, ..bdf }, 0), None);
    }

    #[test]
    fn operation_region_width_stays_aligned_and_in_config_space() {
        assert_eq!(operation_region_bytes(0xffc, 32), Some(4));
        assert_eq!(operation_region_bytes(0xffd, 16), None);
        assert_eq!(operation_region_bytes(0xfff, 16), None);
        assert_eq!(operation_region_bytes(0, 64), None);
    }
}
