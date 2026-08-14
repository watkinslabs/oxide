use sync::{Spinlock, TaskList as DriverLockClass};

use crate::{imp::Controller, regs};

const SWSM_RETRIES: usize = regs::NVM_CHECKSUM_WORD as usize + 1;
const SWSM_WAIT_NS: u64 = 100_000;
const MDIC_RETRIES: usize = 300;
const MDIC_WAIT_NS: u64 = 50_000;
const BM_PHY_SPEC_CTRL: u8 = 0x10;
const BM_PHY_AUTO_X: u16 = 0x0060;
const BM_PHY_DOWN_SHIFT: u16 = 0x0800;
const BM_PHY_PAGE: u8 = 29;
const BM_PHY_CONTROL: u8 = 30;
const BM_PHY_PAGE_ZERO: u16 = 0x0003;
const BM_PHY_CONTROL_ZERO: u16 = 0;
const BM_PHY_CONTROL_REGISTER: u8 = 0;
const BM_PHY_RESET: u16 = 0x8000;

static BM_SERIAL: Spinlock<(), DriverLockClass> = Spinlock::new(());

fn wait_ns(ns: u64) {
    let deadline = sched::deadline::clock::now_ns().saturating_add(ns);
    while sched::deadline::clock::now_ns() < deadline { core::hint::spin_loop(); }
}

/// Linux `e1000_get_hw_semaphore_82574`: one SWSM semaphore covers both
/// PHY and NVM access on 82574/82583.  EXTCNF MDIO ownership is 82573-only.
fn acquire_hw_semaphore(c: &Controller) -> bool {
    for _ in 0..SWSM_RETRIES {
        if c.read(regs::SWSM) & regs::SWSM_SMBI == 0 { break; }
        wait_ns(SWSM_WAIT_NS);
    }
    for _ in 0..SWSM_RETRIES {
        let swsm = c.read(regs::SWSM);
        c.write(regs::SWSM, swsm | regs::SWSM_SWESMBI);
        if c.read(regs::SWSM) & regs::SWSM_SWESMBI != 0 { return true; }
        wait_ns(SWSM_WAIT_NS);
    }
    release_hw_semaphore(c);
    false
}

fn release_hw_semaphore(c: &Controller) {
    c.write(regs::SWSM, c.read(regs::SWSM) & !(regs::SWSM_SMBI | regs::SWSM_SWESMBI));
}

fn read_eerd(c: &Controller, word: u16) -> Option<u16> {
    c.write(regs::EERD, regs::eerd_command(word));
    for _ in 0..MDIC_RETRIES {
        let value = c.read(regs::EERD);
        if value & regs::EERD_DONE != 0 { return Some(regs::eerd_data(value)); }
        wait_ns(MDIC_WAIT_NS);
    }
    None
}

fn validate_nvm(c: &Controller) -> bool {
    let mut words = [0u16; regs::NVM_CHECKSUM_WORD as usize + 1];
    for (index, word) in words.iter_mut().enumerate() {
        let Some(value) = read_eerd(c, index as u16) else { return false; };
        *word = value;
    }
    regs::nvm_checksum_valid(&words)
}

fn mdic(c: &Controller, register: u8, write: Option<u16>) -> Option<u16> {
    c.write(regs::MDIC, regs::mdic_command(register, write));
    for _ in 0..MDIC_RETRIES {
        let value = c.read(regs::MDIC);
        if value & regs::MDIC_READY == 0 { wait_ns(MDIC_WAIT_NS); continue; }
        if value & regs::MDIC_ERROR != 0 || value & regs::MDIC_REGISTER_MASK != (register as u32) << regs::MDIC_REGISTER_SHIFT { return None; }
        return Some(value as u16);
    }
    None
}

fn validate_and_configure_bm_phy(c: &Controller) -> bool {
    let Some(high) = mdic(c, regs::BM_PHY_ID_HIGH, None) else { return false; };
    wait_ns(MDIC_WAIT_NS);
    let Some(low) = mdic(c, regs::BM_PHY_ID_LOW, None) else { return false; };
    if ((high as u32) << 16) | low as u32 != regs::BM_PHY_ID_R2 { return false; }
    let Some(spec) = mdic(c, BM_PHY_SPEC_CTRL, None) else { return false; };
    let disabled = (spec & !(BM_PHY_AUTO_X | BM_PHY_DOWN_SHIFT)) | BM_PHY_AUTO_X;
    if mdic(c, BM_PHY_SPEC_CTRL, Some(disabled)).is_none() { return false; }
    if mdic(c, BM_PHY_CONTROL_REGISTER, Some(BM_PHY_RESET)).is_none() { return false; }
    let enabled = disabled | BM_PHY_DOWN_SHIFT;
    if mdic(c, BM_PHY_SPEC_CTRL, Some(enabled)).is_none() { return false; }
    if mdic(c, BM_PHY_PAGE, Some(BM_PHY_PAGE_ZERO)).is_none() { return false; }
    if mdic(c, BM_PHY_CONTROL, Some(BM_PHY_CONTROL_ZERO)).is_none() { return false; }
    mdic(c, BM_PHY_CONTROL_REGISTER, Some(BM_PHY_RESET)).is_some()
}

fn initialize_mac(c: &Controller) {
    for index in 1..regs::RAR_ENTRIES {
        let Some((low, high)) = regs::rar_offset(index) else { return; };
        c.write(low, 0);
        c.write(high, 0);
    }
    for index in 0..regs::FILTER_TABLE_ENTRIES {
        let Some(mta) = regs::table_offset(regs::MTA, index) else { return; };
        let Some(vfta) = regs::table_offset(regs::VFTA, index) else { return; };
        c.write(mta, 0);
        c.write(vfta, 0);
    }
    let txdctl = c.read(regs::TXDCTL0);
    c.write(regs::TXDCTL0, (txdctl & !regs::TXDCTL_WTHRESH) | regs::TXDCTL_WRITEBACK | regs::TXDCTL_COUNT_DESC);
    let tarc = c.read(regs::TARC0);
    c.write(regs::TARC0, (tarc & !regs::TARC0_RESERVED) | regs::TARC0_82574);
    c.write(regs::CTRL, c.read(regs::CTRL) & !regs::CTRL_82574_CLEAR);
    c.write(regs::CTRL_EXT, (c.read(regs::CTRL_EXT) & !regs::CTRL_EXT_DRV_LOAD) | regs::CTRL_EXT_IAME);
    c.write(regs::GCR, c.read(regs::GCR) | regs::GCR_QUEUE_WORKAROUND | regs::GCR_L1_ACTIVE_RX);
    c.write(regs::GCR2, c.read(regs::GCR2) | regs::GCR2_COMPLETION_WORKAROUND);
    let _ = c.read(regs::GCR2);
}

fn configure_flow_control(c: &Controller, mode: regs::PauseMode) {
    c.write(regs::FCT, regs::FLOW_CONTROL_TYPE);
    c.write(regs::FCAH, regs::FLOW_CONTROL_ADDRESS_HIGH);
    c.write(regs::FCAL, regs::FLOW_CONTROL_ADDRESS_LOW);
    c.write(regs::FCTTV, regs::FLOW_CONTROL_PAUSE_TIME);
    let (low, high, ctrl_bits) = match mode {
        regs::PauseMode::None => (0, 0, 0),
        regs::PauseMode::Rx => (0, 0, regs::CTRL_RFCE),
        regs::PauseMode::Tx => (regs::FLOW_CONTROL_LOW_WATER | regs::FCRTL_XON, regs::FLOW_CONTROL_HIGH_WATER, regs::CTRL_TFCE),
        regs::PauseMode::Full => (regs::FLOW_CONTROL_LOW_WATER | regs::FCRTL_XON, regs::FLOW_CONTROL_HIGH_WATER, regs::CTRL_RFCE | regs::CTRL_TFCE),
    };
    c.write(regs::FCRTL, low);
    c.write(regs::FCRTH, high);
    let ctrl = c.read(regs::CTRL) & !(regs::CTRL_RFCE | regs::CTRL_TFCE);
    c.write(regs::CTRL, ctrl | ctrl_bits);
}

fn configure_autoneg(c: &Controller) -> bool {
    let Some(advertisement) = mdic(c, regs::MII_ADVERTISE, None) else { return false; };
    let advertisement = (advertisement & !(regs::MII_ADVERTISE_SPEEDS | regs::MII_ADVERTISE_PAUSE | regs::MII_ADVERTISE_ASYM_PAUSE))
        | regs::MII_ADVERTISE_SPEEDS | regs::MII_ADVERTISE_PAUSE | regs::MII_ADVERTISE_ASYM_PAUSE;
    if mdic(c, regs::MII_ADVERTISE, Some(advertisement)).is_none() { return false; }
    let Some(gigabit) = mdic(c, regs::MII_CTRL1000, None) else { return false; };
    if mdic(c, regs::MII_CTRL1000, Some((gigabit & !regs::MII_CTRL1000_HALF) | regs::MII_CTRL1000_FULL)).is_none() { return false; }
    let Some(control) = mdic(c, regs::MII_BMCR, None) else { return false; };
    mdic(c, regs::MII_BMCR, Some(control | regs::MII_BMCR_AN_ENABLE | regs::MII_BMCR_AN_RESTART)).is_some()
}

fn negotiated_pause(c: &Controller) -> Option<regs::PauseMode> {
    let _ = mdic(c, regs::MII_BMSR, None)?;
    if mdic(c, regs::MII_BMSR, None)? & regs::MII_BMSR_AN_COMPLETE == 0 { return None; }
    let advertisement = mdic(c, regs::MII_ADVERTISE, None)?;
    let partner = mdic(c, regs::MII_LPA, None)?;
    Some(regs::resolve_pause(advertisement, partner))
}

fn setup_copper_link(c: &Controller) -> bool {
    let ctrl = c.read(regs::CTRL);
    c.write(regs::CTRL, (ctrl | regs::CTRL_SLU) & !(regs::CTRL_FRCSPD | regs::CTRL_FRCDPX));
    if !configure_autoneg(c) { return false; }
    configure_flow_control(c, negotiated_pause(c).unwrap_or(regs::PauseMode::Full));
    true
}

pub(crate) fn prepare(c: &Controller) -> bool {
    let _serial = BM_SERIAL.lock();
    if !acquire_hw_semaphore(c) { return false; }
    let result = validate_nvm(c) && validate_and_configure_bm_phy(c);
    if result { initialize_mac(c); }
    release_hw_semaphore(c);
    result
}

pub(crate) fn activate(c: &Controller) -> bool {
    let _serial = BM_SERIAL.lock();
    if !acquire_hw_semaphore(c) { return false; }
    let result = setup_copper_link(c);
    release_hw_semaphore(c);
    result
}

pub(crate) fn reconcile(c: &Controller) -> bool {
    let _serial = BM_SERIAL.lock();
    if !acquire_hw_semaphore(c) { return false; }
    let result = match negotiated_pause(c) { Some(mode) => { configure_flow_control(c, mode); true }, None => true };
    release_hw_semaphore(c);
    result
}
