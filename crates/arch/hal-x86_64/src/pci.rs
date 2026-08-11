// PCIe ECAM config-space routing. Every published MCFG allocation owns one
// exact `(segment, bus range)` window; config transactions select it by BDF.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

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

pub struct EcamPci { windows: [EcamWindow; pci::MAX_ECAM_WINDOWS], count: usize }

impl EcamPci {
    /// Build the router from the atomically published MCFG window set. # C: O(N)
    pub fn from_published() -> Option<Self> {
        let count = ECAM_WINDOW_COUNT.load(Ordering::Acquire) as usize;
        if count == 0 || count > pci::MAX_ECAM_WINDOWS { return None; }
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
        Some(Self { windows, count })
    }
    /// Exact host-bridge windows owned by this reader. # C: O(1)
    pub fn windows(&self) -> &[EcamWindow] { &self.windows[..self.count] }
    fn ecam_addr(&self, bdf: pci::Bdf, reg: u16) -> Option<u64> {
        let w = self.windows().iter().find(|w| w.segment == bdf.segment
            && bdf.bus >= w.bus_start && bdf.bus <= w.bus_end)?;
        Some(w.base_va + (u64::from(bdf.bus - w.bus_start) << 20)
            + (u64::from(bdf.device) << 15) + (u64::from(bdf.function) << 12)
            + (u64::from(reg) & 0xffc))
    }
    fn read32_at(&self, bdf: pci::Bdf, reg: u16) -> u32 {
        let Some(a) = self.ecam_addr(bdf, reg) else { return u32::MAX };
        // SAFETY: selected ECAM window was mapped Device-uncacheable before publication.
        unsafe { core::ptr::read_volatile(a as *const u32) }
    }
    fn write32_at(&self, bdf: pci::Bdf, reg: u16, val: u32) {
        let Some(a) = self.ecam_addr(bdf, reg) else { return };
        // SAFETY: selected ECAM window was mapped Device-uncacheable before publication.
        unsafe { core::ptr::write_volatile(a as *mut u32, val) }
    }
}

impl pci::ConfigSpaceReader for EcamPci {
    fn read32(&self, bdf: pci::Bdf, offset: u8) -> u32 { self.read32_at(bdf, u16::from(offset)) }
    fn write32(&self, bdf: pci::Bdf, offset: u8, val: u32) { self.write32_at(bdf, u16::from(offset), val) }
    fn read32_ext(&self, bdf: pci::Bdf, offset: u16) -> u32 { self.read32_at(bdf, offset) }
    fn write32_ext(&self, bdf: pci::Bdf, offset: u16, val: u32) { self.write32_at(bdf, offset, val) }
    fn read8_ext(&self, bdf: pci::Bdf, offset: u16) -> u8 {
        let Some(a) = self.ecam_addr(bdf, offset) else { return u8::MAX };
        // SAFETY: selected ECAM function page is Device-uncacheable and byte-addressable.
        unsafe { core::ptr::read_volatile((a + u64::from(offset & 3)) as *const u8) }
    }
    fn read16_ext(&self, bdf: pci::Bdf, offset: u16) -> u16 {
        let Some(a) = self.ecam_addr(bdf, offset) else { return u16::MAX };
        // SAFETY: selected ECAM function page is Device-uncacheable and word-aligned.
        unsafe { core::ptr::read_volatile((a + u64::from(offset & 3)) as *const u16) }
    }
    fn write8_ext(&self, bdf: pci::Bdf, offset: u16, val: u8) {
        let Some(a) = self.ecam_addr(bdf, offset) else { return };
        // SAFETY: selected ECAM function page is Device-uncacheable and byte-addressable.
        unsafe { core::ptr::write_volatile((a + u64::from(offset & 3)) as *mut u8, val) }
    }
    fn write16_ext(&self, bdf: pci::Bdf, offset: u16, val: u16) {
        let Some(a) = self.ecam_addr(bdf, offset) else { return };
        // SAFETY: selected ECAM function page is Device-uncacheable and word-aligned.
        unsafe { core::ptr::write_volatile((a + u64::from(offset & 3)) as *mut u16, val) }
    }
}
