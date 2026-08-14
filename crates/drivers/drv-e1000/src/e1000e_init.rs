use sync::{Spinlock, TaskList as DriverLockClass};

use crate::{imp::Controller, regs};

const MDIO_RETRIES: usize = 10;
const MDIO_WAIT_NS: u64 = 2_000_000;
const NVM_GRANT_RETRIES: usize = 1000;
const NVM_GRANT_WAIT_NS: u64 = 5_000;
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

fn acquire_mdio(c: &Controller) -> bool {
    for _ in 0..MDIO_RETRIES {
        c.write(regs::EXTCNF_CTRL, c.read(regs::EXTCNF_CTRL) | regs::EXTCNF_CTRL_MDIO_SW_OWNERSHIP);
        if c.read(regs::EXTCNF_CTRL) & regs::EXTCNF_CTRL_MDIO_SW_OWNERSHIP != 0 { return true; }
        wait_ns(MDIO_WAIT_NS);
    }
    false
}

fn release_mdio(c: &Controller) {
    c.write(regs::EXTCNF_CTRL, c.read(regs::EXTCNF_CTRL) & !regs::EXTCNF_CTRL_MDIO_SW_OWNERSHIP);
}

fn acquire_nvm(c: &Controller) -> bool {
    c.write(regs::EECD, c.read(regs::EECD) | regs::EECD_NVM_REQUEST);
    for _ in 0..NVM_GRANT_RETRIES {
        if c.read(regs::EECD) & regs::EECD_NVM_GRANT != 0 { return true; }
        wait_ns(NVM_GRANT_WAIT_NS);
    }
    c.write(regs::EECD, c.read(regs::EECD) & !regs::EECD_NVM_REQUEST);
    false
}

fn release_nvm(c: &Controller) {
    c.write(regs::EECD, c.read(regs::EECD) & !regs::EECD_NVM_REQUEST);
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
    if !acquire_nvm(c) { return false; }
    let mut words = [0u16; regs::NVM_CHECKSUM_WORD as usize + 1];
    for (index, word) in words.iter_mut().enumerate() {
        let Some(value) = read_eerd(c, index as u16) else { release_nvm(c); return false; };
        *word = value;
    }
    release_nvm(c);
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

pub(crate) fn prepare(c: &Controller) -> bool {
    let _serial = BM_SERIAL.lock();
    if !acquire_mdio(c) { return false; }
    let result = validate_nvm(c) && validate_and_configure_bm_phy(c);
    release_mdio(c);
    result
}
