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
const PCH_NVM_SIGNATURE_WORD: u32 = 0x13;
const PCH_NVM_SIGNATURE_MASK: u16 = 0xc000;
const PCH_NVM_SIGNATURE_VALUE: u16 = 0x8000;
const PCH_KMRN_TIMEOUTS: u32 = 4;
const PCH_KMRN_INBAND: u32 = 9;
const PCH_RAR_ENTRIES: usize = 7;
const PCH2_RAR_ENTRIES: usize = 5;
const PCH_MTA_ENTRIES: usize = 32;
const PCH_82577_CONFIG: u32 = 22;
const PCH_82577_CTRL2: u32 = 18;
const PCH_82577_ASSERT_CRS: u16 = 1 << 15;
const PCH_82577_DOWNSHIFT: u16 = 3 << 10;
const PCH_82577_MDIX: u16 = 0x0600;
const PCH_82577_AUTO_MDIX: u16 = 0x0400;
const PCH_HV_KMRN_MODE_CTRL: u32 = (769 << 5) | 16;
const PCH_HV_KMRN_MDIO_SLOW: u16 = 0x0400;
const PCH_82579_EMI_ADDR: u32 = 0x10;
const PCH_82579_EMI_DATA: u32 = 0x11;
const PCH_82579_MSE_THRESHOLD: u16 = 0x084f;
const PCH_82579_MSE_LINK_DOWN: u16 = 0x2411;
const PCH_I217_TIMEOUTS: u32 = (770 << 5) | 21;
const PCH_I217_TIMEOUTS_K1_MASK: u16 = 0x0fc0;
const PCH_I217_TIMEOUTS_K1_DEFAULT: u16 = 0x0f00;
const PCH_BM_PORT_CTRL_PAUSE: u32 = (769 << 5) | 27;

static PCH_SHARED: Spinlock<(), DriverLockClass> = Spinlock::new(());

fn wait_ns(ns: u64) {
    let deadline = sched::deadline::clock::now_ns().saturating_add(ns);
    while sched::deadline::clock::now_ns() < deadline { core::hint::spin_loop(); }
}

fn mdic(c: &Controller, phy: u32, reg: u8, write: Option<u16>) -> Option<u16> {
    c.write(regs::MDIC, regs::mdic_command_at(phy, reg, write));
    if c.pch2() { wait_ns(regs::PCH2_MDIC_SETTLE_NS); }
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
        if !regs::pch_phy_id_supported(id) { return None; }
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

fn phy_id(c: &Controller) -> Option<HvPhy> {
    with_shared(c, |c| {
        let high = mdic(c, regs::PCH_PHY_DEBUG_ADDRESS, regs::BM_PHY_ID_HIGH, None)?;
        let low = mdic(c, regs::PCH_PHY_DEBUG_ADDRESS, regs::BM_PHY_ID_LOW, None)?;
        HvPhy::from_id(((high as u32) << 16) | low as u32)
    })
}

fn kmrn_read(c: &Controller, reg: u32) -> u16 {
    c.write(regs::KMRNCTRLSTA, (reg << regs::KMRN_OFFSET_SHIFT) | regs::KMRN_READ);
    let _ = c.read(regs::KMRNCTRLSTA); wait_ns(2_000);
    c.read(regs::KMRNCTRLSTA) as u16
}

fn kmrn_write(c: &Controller, reg: u32, value: u16) {
    c.write(regs::KMRNCTRLSTA, (reg << regs::KMRN_OFFSET_SHIFT) | value as u32);
    let _ = c.read(regs::KMRNCTRLSTA); wait_ns(2_000);
}

fn configure_link(c: &Controller, phy: HvPhy) -> bool {
    let ctrl = c.read(regs::CTRL);
    c.write(regs::CTRL, (ctrl | regs::CTRL_SLU) & !(regs::CTRL_FRCSPD | regs::CTRL_FRCDPX));
    kmrn_write(c, PCH_KMRN_TIMEOUTS, u16::MAX);
    kmrn_write(c, PCH_KMRN_INBAND, kmrn_read(c, PCH_KMRN_INBAND) | 0x003f);
    if !matches!(phy, HvPhy::I82578) {
        let Some(config) = hv_read(c, phy, PCH_82577_CONFIG) else { return false; };
        if !hv_write(c, phy, PCH_82577_CONFIG, config | PCH_82577_ASSERT_CRS | PCH_82577_DOWNSHIFT) { return false; }
        let Some(ctrl2) = hv_read(c, phy, PCH_82577_CTRL2) else { return false; };
        if !hv_write(c, phy, PCH_82577_CTRL2, (ctrl2 & !PCH_82577_MDIX) | PCH_82577_AUTO_MDIX) { return false; }
    }
    let Some(advertisement) = hv_read(c, phy, regs::MII_ADVERTISE as u32) else { return false; };
    let advertisement = (advertisement & !(regs::MII_ADVERTISE_SPEEDS | regs::MII_ADVERTISE_PAUSE | regs::MII_ADVERTISE_ASYM_PAUSE))
        | regs::MII_ADVERTISE_SPEEDS | regs::MII_ADVERTISE_PAUSE | regs::MII_ADVERTISE_ASYM_PAUSE;
    if !hv_write(c, phy, regs::MII_ADVERTISE as u32, advertisement) { return false; }
    let Some(gigabit) = hv_read(c, phy, regs::MII_CTRL1000 as u32) else { return false; };
    if !hv_write(c, phy, regs::MII_CTRL1000 as u32, (gigabit & !regs::MII_CTRL1000_HALF) | regs::MII_CTRL1000_FULL) { return false; }
    let Some(control) = hv_read(c, phy, regs::MII_BMCR as u32) else { return false; };
    if !hv_write(c, phy, regs::MII_BMCR as u32, control | regs::MII_BMCR_AN_ENABLE | regs::MII_BMCR_AN_RESTART) { return false; }
    if matches!(phy, HvPhy::I217) {
        let Some(timeouts) = hv_read(c, phy, PCH_I217_TIMEOUTS) else { return false; };
        if !hv_write(c, phy, PCH_I217_TIMEOUTS, (timeouts & !PCH_I217_TIMEOUTS_K1_MASK) | PCH_I217_TIMEOUTS_K1_DEFAULT) { return false; }
        let pwr = c.read(regs::FEXTNVM12);
        c.write(regs::FEXTNVM12, (pwr & !regs::FEXTNVM12_PHYPD_CTRL) | regs::FEXTNVM12_PHYPD_CTRL_P1);
    }
    c.write(regs::FCT, regs::FLOW_CONTROL_TYPE); c.write(regs::FCAH, regs::FLOW_CONTROL_ADDRESS_HIGH); c.write(regs::FCAL, regs::FLOW_CONTROL_ADDRESS_LOW);
    c.write(regs::FCTTV, regs::FLOW_CONTROL_PAUSE_TIME); c.write(regs::FCRTV_PCH, regs::FLOW_CONTROL_REFRESH_TIME);
    if !hv_write(c, phy, PCH_BM_PORT_CTRL_PAUSE, regs::FLOW_CONTROL_PAUSE_TIME as u16) { return false; }
    c.write(regs::FCRTL, 0); c.write(regs::FCRTH, 0);
    c.write(regs::CTRL, (c.read(regs::CTRL) & !(regs::CTRL_RFCE | regs::CTRL_TFCE)) | regs::CTRL_RFCE);
    true
}

fn initialize_mac(c: &Controller, rar_entries: usize) -> bool {
    let Some(phy) = phy_id(c) else { return false; };
    for index in 1..rar_entries {
        let Some((low, high)) = regs::rar_offset(index) else { return false; };
        c.write(low, 0); c.write(high, 0);
    }
    for index in 0..PCH_MTA_ENTRIES {
        let Some(offset) = regs::table_offset(regs::MTA, index) else { return false; };
        c.write(offset, 0);
    }
    for offset in [regs::TXDCTL0, regs::TXDCTL1] {
        let value = c.read(offset);
        c.write(offset, (value & !(regs::TXDCTL_WTHRESH | regs::TXDCTL_PTHRESH)) | regs::TXDCTL_WRITEBACK | regs::TXDCTL_MAX_PREFETCH);
    }
    configure_link(c, phy)
}
pub(crate) fn initialize(c: &Controller) -> bool { initialize_mac(c, PCH_RAR_ENTRIES) }
pub(crate) fn initialize_pch2(c: &Controller) -> bool { configure_pch2_lv(c) && initialize_mac(c, PCH2_RAR_ENTRIES) }

pub(crate) fn activate(c: &Controller) -> bool { phy_id(c).is_some_and(|phy| configure_link(c, phy)) }

pub(crate) fn reconcile(c: &Controller) -> bool {
    let Some(phy) = phy_id(c) else { return false; };
    hv_read(c, phy, regs::MII_BMSR as u32).is_some()
}

pub(crate) fn write_lpt_rar(c: &Controller, mac: net::MacAddr, index: usize) -> bool {
    let low = u32::from_le_bytes([mac.0[0], mac.0[1], mac.0[2], mac.0[3]]);
    let high = u16::from_le_bytes([mac.0[4], mac.0[5]]) as u32 | (1 << 31);
    if index == 0 { c.write(regs::RAL0, low); let _ = c.read(regs::RAL0); c.write(regs::RAH0, high); let _ = c.read(regs::RAH0); return true; }
    if index >= regs::pch_lpt_rar_count(c.read(regs::FWSM)) { return false; }
    let Some((low_off, high_off)) = regs::pch_lpt_shra_offset(index - 1) else { return false; };
    with_shared(c, |c| {
        c.write(low_off, low); let _ = c.read(low_off); c.write(high_off, high); let _ = c.read(high_off);
        (c.read(low_off) == low && c.read(high_off) == high).then_some(())
    }).is_some()
}

pub(crate) fn initialize_lpt_addrs(c: &Controller) -> Option<net::MacAddr> {
    let flash = LptFlash::new(c);
    if !flash.validate_nvm() { return None; }
    let mac = flash.read_mac()?;
    if !write_lpt_rar(c, mac, 0) { return None; }
    let clear = net::MacAddr::ZERO;
    let count = regs::pch_lpt_rar_count(c.read(regs::FWSM));
    for index in 1..count { if !write_lpt_rar(c, clear, index) { return None; } }
    Some(mac)
}

pub(crate) struct LptFlash<'a> { c: &'a Controller }
impl<'a> LptFlash<'a> {
    pub(crate) fn new(c: &'a Controller) -> Self { Self { c } }
    fn read(&self, offset: u64) -> Option<u32> { Some(self.c.read(regs::pch_lpt_flash_offset(offset)?)) }
    fn read16(&self, offset: u64) -> Option<u16> { Some(self.c.read16(regs::pch_lpt_flash_offset(offset)?)) }
    fn write(&self, offset: u64, value: u32) -> bool { let Some(offset) = regs::pch_lpt_flash_offset(offset) else { return false; }; self.c.write(offset, value); true }
    fn write16(&self, offset: u64, value: u16) -> bool { let Some(offset) = regs::pch_lpt_flash_offset(offset) else { return false; }; self.c.write16(offset, value); true }
    pub(crate) fn descriptor(&self) -> Option<regs::PchFlashLayout> { regs::pch_flash_layout(self.read(PCH_FLASH_GFPREG)?) }
    pub(crate) fn read_word(&self, layout: regs::PchFlashLayout, word: u32) -> Option<u16> {
        let offset = word.checked_mul(2)?;
        if offset.checked_add(2)? > layout.bytes { return None; }
        let address = layout.base.checked_add(offset)?;
        if address > PCH_FLASH_LINEAR_MASK { return None; }
        for _ in 0..PCH_FLASH_RETRIES {
            let status = self.read16(PCH_FLASH_HSFSTS)?;
            if status & PCH_FLASH_DESCRIPTOR_VALID == 0 || status & PCH_FLASH_IN_PROGRESS != 0 { return None; }
            if !self.write16(PCH_FLASH_HSFSTS, status & (PCH_FLASH_ERROR | PCH_FLASH_ACCESS_ERROR | PCH_FLASH_DONE)) { return None; }
            let control = self.read16(PCH_FLASH_HSFCTL)?;
            if !self.write16(PCH_FLASH_HSFCTL, (control & !(PCH_FLASH_BYTE_COUNT_MASK | PCH_FLASH_CYCLE_MASK)) | PCH_FLASH_BYTE_COUNT) { return None; }
            if !self.write(PCH_FLASH_FADDR, address) || !self.write16(PCH_FLASH_HSFCTL, (control & !(PCH_FLASH_BYTE_COUNT_MASK | PCH_FLASH_CYCLE_MASK)) | PCH_FLASH_BYTE_COUNT | PCH_FLASH_GO) { return None; }
            let deadline = sched::deadline::clock::now_ns().saturating_add(PCH_FLASH_TIMEOUT_NS);
            while sched::deadline::clock::now_ns() < deadline {
                let status = self.read16(PCH_FLASH_HSFSTS)?;
                if status & PCH_FLASH_DONE != 0 { if status & PCH_FLASH_ERROR == 0 { return Some(self.read(PCH_FLASH_FDATA0)? as u16); } break; }
                core::hint::spin_loop();
            }
        }
        None
    }
    fn valid_bank(&self, layout: regs::PchFlashLayout) -> Option<u32> {
        let bank_words = layout.bytes.checked_div(4)?;
        if bank_words <= PCH_NVM_SIGNATURE_WORD { return None; }
        for bank in [0, bank_words] {
            if self.read_word(layout, bank.checked_add(PCH_NVM_SIGNATURE_WORD)?)? & PCH_NVM_SIGNATURE_MASK == PCH_NVM_SIGNATURE_VALUE { return Some(bank); }
        }
        None
    }
    pub(crate) fn validate_nvm(&self) -> bool {
        let Some(layout) = self.descriptor() else { return false; };
        let Some(bank) = self.valid_bank(layout) else { return false; };
        let mut words = [0u16; regs::NVM_CHECKSUM_WORD as usize + 1];
        for (index, word) in words.iter_mut().enumerate() { let Some(value) = self.read_word(layout, bank + index as u32) else { return false; }; *word = value; }
        regs::nvm_checksum_valid(&words)
    }
    pub(crate) fn read_mac(&self) -> Option<net::MacAddr> {
        let layout = self.descriptor()?; let bank = self.valid_bank(layout)?;
        let low = self.read_word(layout, bank)? as u32 | ((self.read_word(layout, bank + 1)? as u32) << 16);
        regs::mac_from_rar(low, self.read_word(layout, bank + 2)? as u32).map(net::MacAddr)
    }
}

fn reset_with_phy(c: &Controller, phy_reset: bool) -> bool {
    c.write(regs::IMC, u32::MAX);
    c.write(regs::RCTL, 0);
    c.write(regs::TCTL, c.read(regs::TCTL) & !regs::TCTL_EN);
    wait_ns(10_000_000);
    let reset = if phy_reset { regs::CTRL_PHY_RST | regs::CTRL_RST } else { regs::CTRL_RST };
    if with_shared(c, |c| { c.write(regs::CTRL, c.read(regs::CTRL) | reset); Some(()) }).is_none() { return false; }
    wait_ns(20_000_000);
    let deadline = sched::deadline::clock::now_ns().saturating_add(regs::NVM_AUTO_READ_TIMEOUT_NS);
    while !regs::e1000e_auto_read_done(c.read(regs::EECD)) {
        if sched::deadline::clock::now_ns() >= deadline { return false; }
        wait_ns(PCH_SHARED_WAIT_NS);
    }
    let _ = c.read(regs::ICR);
    true
}
pub(crate) fn reset(c: &Controller) -> bool { reset_with_phy(c, true) }

pub(crate) fn reset_pch2(c: &Controller) -> bool {
    let managed = c.read(regs::FWSM) & regs::FWSM_FW_VALID != 0;
    if !managed { c.write(regs::EXTCNF_CTRL, c.read(regs::EXTCNF_CTRL) | regs::EXTCNF_CTRL_GATE_PHY_CFG); }
    if !reset(c) { return false; }
    let counter = c.read(regs::FEXTNVM3);
    c.write(regs::FEXTNVM3, (counter & !regs::FEXTNVM3_PHY_CFG_COUNTER) | regs::FEXTNVM3_PHY_CFG_COUNTER_50MS);
    if !managed { wait_ns(10_000_000); c.write(regs::EXTCNF_CTRL, c.read(regs::EXTCNF_CTRL) & !regs::EXTCNF_CTRL_GATE_PHY_CFG); }
    true
}

fn lpt_phy_accessible(c: &Controller) -> bool { matches!(phy_id(c), Some(HvPhy::I217)) }

fn lpt_toggle_lanphypc(c: &Controller) -> bool {
    let counter = c.read(regs::FEXTNVM3);
    c.write(regs::FEXTNVM3, (counter & !regs::FEXTNVM3_PHY_CFG_COUNTER) | regs::FEXTNVM3_PHY_CFG_COUNTER_50MS);
    let ctrl = c.read(regs::CTRL);
    c.write(regs::CTRL, (ctrl | regs::CTRL_LANPHYPC_OVERRIDE) & !regs::CTRL_LANPHYPC_VALUE);
    let _ = c.read(regs::CTRL);
    wait_ns(20_000);
    c.write(regs::CTRL, ctrl & !regs::CTRL_LANPHYPC_OVERRIDE);
    let _ = c.read(regs::CTRL);
    for _ in 0..20 {
        if c.read(regs::CTRL_EXT) & regs::CTRL_EXT_LPCD != 0 { wait_ns(30_000_000); return true; }
        wait_ns(5_000_000);
    }
    false
}

fn lpt_prepare_phy(c: &Controller) -> bool {
    if lpt_phy_accessible(c) { return true; }
    let fwsm = c.read(regs::FWSM);
    if fwsm & (regs::FWSM_FW_VALID | regs::FWSM_RSPCIPHY) != 0 { return false; }
    c.write(regs::CTRL_EXT, c.read(regs::CTRL_EXT) | regs::CTRL_EXT_FORCE_SMBUS);
    wait_ns(50_000_000);
    if lpt_phy_accessible(c) { c.write(regs::CTRL_EXT, c.read(regs::CTRL_EXT) & !regs::CTRL_EXT_FORCE_SMBUS); return true; }
    if !lpt_toggle_lanphypc(c) { return false; }
    c.write(regs::CTRL_EXT, c.read(regs::CTRL_EXT) & !regs::CTRL_EXT_FORCE_SMBUS);
    lpt_phy_accessible(c)
}

/// Reset LPT only after the I217 transport is accessible and firmware allows a PHY reset. # C: O(retries)
pub(crate) fn reset_lpt(c: &Controller) -> bool { lpt_prepare_phy(c) && reset_with_phy(c, c.read(regs::FWSM) & regs::FWSM_RSPCIPHY == 0) }

/// Reopen I217 through its dedicated PHY accessibility and copper autonegotiation path. # C: O(retries)
pub(crate) fn activate_lpt(c: &Controller) -> bool {
    if !lpt_prepare_phy(c) { return false; }
    activate(c)
}

/// Consume both latched I217 BMSR samples before reporting a link-transition completion. # C: O(retries)
pub(crate) fn reconcile_lpt(c: &Controller) -> bool {
    let Some(phy) = phy_id(c) else { return false; };
    let _ = hv_read(c, phy, regs::MII_BMSR as u32);
    hv_read(c, phy, regs::MII_BMSR as u32).is_some_and(|status| status & regs::MII_BMSR_LINK != 0 || status & regs::MII_BMSR_AN_COMPLETE == 0)
}

pub(crate) fn configure_pch2_lv(c: &Controller) -> bool {
    with_shared(c, |c| {
        let slow = hv_access(c, HvPhy::I82579, PCH_HV_KMRN_MODE_CTRL, None)?;
        hv_access(c, HvPhy::I82579, PCH_HV_KMRN_MODE_CTRL, Some(slow | PCH_HV_KMRN_MDIO_SLOW))?;
        let high = mdic(c, regs::PCH_PHY_DEBUG_ADDRESS, regs::BM_PHY_ID_HIGH, None)?;
        let low = mdic(c, regs::PCH_PHY_DEBUG_ADDRESS, regs::BM_PHY_ID_LOW, None)?;
        if ((high as u32) << 16) | low as u32 != regs::PCH_PHY_ID_82579 { return None; }
        hv_access(c, HvPhy::I82579, PCH_82579_EMI_ADDR, Some(PCH_82579_MSE_THRESHOLD))?;
        hv_access(c, HvPhy::I82579, PCH_82579_EMI_DATA, Some(0x0034))?;
        hv_access(c, HvPhy::I82579, PCH_82579_EMI_ADDR, Some(PCH_82579_MSE_LINK_DOWN))?;
        hv_access(c, HvPhy::I82579, PCH_82579_EMI_DATA, Some(0x0005))
    }).is_some()
}

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
    fn valid_bank(&self, layout: regs::PchFlashLayout) -> Option<u32> {
        let bank_words = layout.bytes.checked_div(4)?;
        if bank_words <= PCH_NVM_SIGNATURE_WORD { return None; }
        for bank in [0, bank_words] {
            let word = self.read_word(layout, bank.checked_add(PCH_NVM_SIGNATURE_WORD)?)?;
            if word & PCH_NVM_SIGNATURE_MASK == PCH_NVM_SIGNATURE_VALUE { return Some(bank); }
        }
        None
    }
    pub(crate) fn validate_nvm(&self) -> bool {
        let Some(layout) = self.layout() else { return false; };
        let Some(bank) = self.valid_bank(layout) else { return false; };
        let mut words = [0u16; regs::NVM_CHECKSUM_WORD as usize + 1];
        for (index, word) in words.iter_mut().enumerate() {
            let Some(value) = self.read_word(layout, bank + index as u32) else { return false; };
            *word = value;
        }
        regs::nvm_checksum_valid(&words)
    }
    pub(crate) fn read_mac(&self) -> Option<net::MacAddr> {
        let layout = self.layout()?;
        let bank = self.valid_bank(layout)?;
        let low = self.read_word(layout, bank)? as u32 | ((self.read_word(layout, bank + 1)? as u32) << 16);
        let high = self.read_word(layout, bank + 2)? as u32;
        regs::mac_from_rar(low, high).map(net::MacAddr)
    }
}
