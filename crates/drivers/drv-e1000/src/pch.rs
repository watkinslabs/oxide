use sync::{Spinlock, TaskList as DriverLockClass};

use crate::{imp::Controller, regs};

const PAGE: u64 = 4096;
const PCH_SHARED_WAIT_NS: u64 = 1_000_000;
const PCH_SHARED_RETRIES: usize = 100;
const PCH_FLAG_RETRIES: usize = 1000;
const PCH_MDIC_RETRIES: usize = 300;
const PCH_MDIC_WAIT_NS: u64 = 50_000;
const PCH_HV_PAGE_SELECT: u8 = 22;
const PCH_HV_DEBUG_82577: u8 = 16;
const PCH_HV_DEBUG_82578: u8 = 29;
const PCH_HV_DEBUG_DATA: u8 = 1;
const PCH_HV_INTC_PAGE: u16 = 768;
const PCH_HV_MAX_PAGE_REG: u8 = 15;
const PCH_FLASH_GFPREG: u64 = 0;
const PCH_FLASH_HSFSTS: u64 = 4;
const PCH_FLASH_HSFCTL: u64 = 6;
const PCH_FLASH_FADDR: u64 = 8;
const PCH_FLASH_FDATA0: u64 = 16;
const PCH_FLASH_DONE: u16 = 1;
const PCH_FLASH_ERROR: u16 = 1 << 1;
const PCH_FLASH_ACCESS_ERROR: u16 = 1 << 2;
const PCH_FLASH_IN_PROGRESS: u16 = 1 << 5;
const PCH_FLASH_DESCRIPTOR_VALID: u16 = 1 << 14;
const PCH_FLASH_GO: u16 = 1;
const PCH_FLASH_BYTE_COUNT: u16 = 1 << 8;
const PCH_FLASH_BYTE_COUNT_MASK: u16 = 0x3 << 8;
const PCH_FLASH_CYCLE_MASK: u16 = 0x3 << 1;
const PCH_FLASH_LINEAR_MASK: u32 = 0x00ff_ffff;
const PCH_FLASH_RETRIES: usize = 10;
const PCH_FLASH_TIMEOUT_NS: u64 = 10_000_000_000;
const PCH_EXTCNF_SWFLAG: u32 = 1 << 5;

static PCH_SHARED: Spinlock<(), DriverLockClass> = Spinlock::new(());

fn wait_ns(ns: u64) {
    let deadline = sched::deadline::clock::now_ns().saturating_add(ns);
    while sched::deadline::clock::now_ns() < deadline { core::hint::spin_loop(); }
}

fn mdic(c: &Controller, phy: u32, reg: u8, write: Option<u16>) -> Option<u16> {
    c.write(regs::MDIC, regs::mdic_command_at(phy, reg, write));
    for _ in 0..PCH_MDIC_RETRIES {
        let value = c.read(regs::MDIC);
        if value & regs::MDIC_READY == 0 { wait_ns(PCH_MDIC_WAIT_NS); continue; }
        if value & regs::MDIC_ERROR != 0 || value & regs::MDIC_REGISTER_MASK != (reg as u32) << regs::MDIC_REGISTER_SHIFT { return None; }
        return Some(value as u16);
    }
    None
}

fn acquire_swflag(c: &Controller) -> bool {
    for _ in 0..PCH_SHARED_RETRIES {
        if c.read(regs::EXTCNF_CTRL) & PCH_EXTCNF_SWFLAG == 0 { break; }
        wait_ns(PCH_SHARED_WAIT_NS);
    }
    if c.read(regs::EXTCNF_CTRL) & PCH_EXTCNF_SWFLAG != 0 { return false; }
    c.write(regs::EXTCNF_CTRL, c.read(regs::EXTCNF_CTRL) | PCH_EXTCNF_SWFLAG);
    for _ in 0..PCH_FLAG_RETRIES {
        if c.read(regs::EXTCNF_CTRL) & PCH_EXTCNF_SWFLAG != 0 { return true; }
        wait_ns(PCH_SHARED_WAIT_NS);
    }
    c.write(regs::EXTCNF_CTRL, c.read(regs::EXTCNF_CTRL) & !PCH_EXTCNF_SWFLAG);
    false
}

fn release_swflag(c: &Controller) {
    c.write(regs::EXTCNF_CTRL, c.read(regs::EXTCNF_CTRL) & !PCH_EXTCNF_SWFLAG);
}

pub(crate) fn with_shared<T>(c: &Controller, f: impl FnOnce(&Controller) -> Option<T>) -> Option<T> {
    let _shared = PCH_SHARED.lock();
    if !acquire_swflag(c) { return None; }
    let result = f(c);
    release_swflag(c);
    result
}

#[derive(Copy, Clone)]
pub(crate) enum HvPhy { I82577, I82578, I82579, I217 }

impl HvPhy {
    fn debug_address(self) -> u8 {
        match self { Self::I82578 => PCH_HV_DEBUG_82578, Self::I82577 | Self::I82579 | Self::I217 => PCH_HV_DEBUG_82577 }
    }
    pub(crate) fn from_id(id: u32) -> Option<Self> {
        match id {
            regs::PCH_PHY_ID_82577 => Some(Self::I82577), regs::PCH_PHY_ID_82578 => Some(Self::I82578),
            regs::PCH_PHY_ID_82579 => Some(Self::I82579), regs::PCH_PHY_ID_I217 => Some(Self::I217), _ => None,
        }
    }
}

fn hv_debug(c: &Controller, phy: HvPhy, reg: u8, write: Option<u16>) -> Option<u16> {
    mdic(c, regs::PCH_PHY_DEBUG_ADDRESS, phy.debug_address(), Some(reg as u16))?;
    mdic(c, regs::PCH_PHY_DEBUG_ADDRESS, phy.debug_address() + PCH_HV_DEBUG_DATA, write)
}

fn hv_address(page: u16) -> u32 { if page >= PCH_HV_INTC_PAGE { regs::PCH_PHY_ADDRESS } else { regs::PCH_PHY_DEBUG_ADDRESS } }

fn hv_access(c: &Controller, phy: HvPhy, offset: u32, write: Option<u16>) -> Option<u16> {
    let (page, reg) = regs::pch_hv_address(offset);
    if page > 0 && page < PCH_HV_INTC_PAGE { return hv_debug(c, phy, reg, write); }
    let address = hv_address(page);
    if reg > PCH_HV_MAX_PAGE_REG {
        let select_page = if page == PCH_HV_INTC_PAGE { 0 } else { page << 5 };
        mdic(c, regs::PCH_PHY_ADDRESS, PCH_HV_PAGE_SELECT, Some(select_page))?;
    }
    mdic(c, address, reg & 0x1f, write)
}

pub(crate) fn hv_read(c: &Controller, phy: HvPhy, offset: u32) -> Option<u16> { with_shared(c, |c| hv_access(c, phy, offset, None)) }
pub(crate) fn hv_write(c: &Controller, phy: HvPhy, offset: u32, value: u16) -> bool { with_shared(c, |c| hv_access(c, phy, offset, Some(value))).is_some() }

pub(crate) struct FlashBar { mmio: mmio_map::Mapping, offset: u64 }

impl FlashBar {
    pub(crate) fn map(parent: &drv::Device) -> Option<Self> {
        let resource = parent.resources.iter().find(|resource| resource.bar == 1 && resource.flags & drv::IORESOURCE_MEM != 0)?;
        let bytes = resource.end.checked_sub(resource.start)?.checked_add(1)?;
        if resource.start == 0 || bytes < PCH_FLASH_FDATA0 + 4 { return None; }
        let offset = resource.start & (PAGE - 1);
        let pages = offset.checked_add(bytes)?.checked_add(PAGE - 1)?.checked_div(PAGE)?;
        // SAFETY: BAR1 belongs to the matched PCH function and this handle owns its mapping lifetime.
        Some(Self { mmio: unsafe { mmio_map::map_owned(resource.start & !(PAGE - 1), pages) }, offset })
    }
    fn read16(&self, off: u64) -> u16 {
        // SAFETY: all flash sequencer offsets below are aligned and within the owned BAR1 mapping.
        unsafe { core::ptr::read_volatile((self.mmio.base_va() + self.offset + off) as *const u16) }
    }
    fn write16(&self, off: u64, value: u16) {
        // SAFETY: all flash sequencer offsets below are aligned and within the owned BAR1 mapping.
        unsafe { core::ptr::write_volatile((self.mmio.base_va() + self.offset + off) as *mut u16, value); }
    }
    fn read32(&self, off: u64) -> u32 {
        // SAFETY: all flash sequencer offsets below are aligned and within the owned BAR1 mapping.
        unsafe { core::ptr::read_volatile((self.mmio.base_va() + self.offset + off) as *const u32) }
    }
    fn write32(&self, off: u64, value: u32) {
        // SAFETY: all flash sequencer offsets below are aligned and within the owned BAR1 mapping.
        unsafe { core::ptr::write_volatile((self.mmio.base_va() + self.offset + off) as *mut u32, value); }
    }
    pub(crate) fn layout(&self) -> Option<regs::PchFlashLayout> { regs::pch_flash_layout(self.read32(PCH_FLASH_GFPREG)) }
    fn ready(&self) -> bool {
        let status = self.read16(PCH_FLASH_HSFSTS);
        if status & PCH_FLASH_DESCRIPTOR_VALID == 0 { return false; }
        self.write16(PCH_FLASH_HSFSTS, status & (PCH_FLASH_ERROR | PCH_FLASH_ACCESS_ERROR));
        if status & PCH_FLASH_IN_PROGRESS == 0 { self.write16(PCH_FLASH_HSFSTS, PCH_FLASH_DONE); return true; }
        let deadline = sched::deadline::clock::now_ns().saturating_add(PCH_FLASH_TIMEOUT_NS);
        while sched::deadline::clock::now_ns() < deadline {
            if self.read16(PCH_FLASH_HSFSTS) & PCH_FLASH_IN_PROGRESS == 0 { self.write16(PCH_FLASH_HSFSTS, PCH_FLASH_DONE); return true; }
            core::hint::spin_loop();
        }
        false
    }
    fn cycle(&self) -> bool {
        self.write16(PCH_FLASH_HSFCTL, self.read16(PCH_FLASH_HSFCTL) | PCH_FLASH_GO);
        let deadline = sched::deadline::clock::now_ns().saturating_add(PCH_FLASH_TIMEOUT_NS);
        while sched::deadline::clock::now_ns() < deadline {
            let status = self.read16(PCH_FLASH_HSFSTS);
            if status & PCH_FLASH_DONE != 0 { return status & PCH_FLASH_ERROR == 0; }
            core::hint::spin_loop();
        }
        false
    }
    pub(crate) fn read_word(&self, layout: regs::PchFlashLayout, word: u32) -> Option<u16> {
        let offset = word.checked_mul(2)?;
        if offset.checked_add(2)? > layout.bytes { return None; }
        let address = layout.base.checked_add(offset)?;
        if address > PCH_FLASH_LINEAR_MASK { return None; }
        for _ in 0..PCH_FLASH_RETRIES {
            if !self.ready() { return None; }
            let control = self.read16(PCH_FLASH_HSFCTL);
            self.write16(PCH_FLASH_HSFCTL, (control & !(PCH_FLASH_BYTE_COUNT_MASK | PCH_FLASH_CYCLE_MASK)) | PCH_FLASH_BYTE_COUNT);
            self.write32(PCH_FLASH_FADDR, address);
            if self.cycle() { return Some(self.read32(PCH_FLASH_FDATA0) as u16); }
        }
        None
    }
}
