use crate::{imp::Controller, profile::ResetProfile, regs};

const SWSM_RETRIES: usize = regs::NVM_CHECKSUM_WORD as usize + 1;
const SWSM_WAIT_NS: u64 = 100_000;
const PRE_RESET_WAIT_NS: u64 = 10_000_000;

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
fn io_write32(port: u16, value: u32) {
    // SAFETY: the matched legacy function owns this BAR1 register window during reset.
    unsafe { core::arch::asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags)); }
}

fn wait_ns(ns: u64) {
    let deadline = sched::deadline::clock::now_ns().saturating_add(ns);
    while sched::deadline::clock::now_ns() < deadline { core::hint::spin_loop(); }
}

/// Linux `e1000_get_hw_semaphore_82574`: 82574/82583 own PHY and NVM through
/// SWSM, not the 82573-only EXTCNF MDIO ownership bit.
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

fn wait_auto_read(c: &Controller) -> bool {
    let auto_deadline = sched::deadline::clock::now_ns().saturating_add(regs::NVM_AUTO_READ_TIMEOUT_NS);
    while !regs::e1000e_auto_read_done(c.read(regs::EECD)) {
        if sched::deadline::clock::now_ns() >= auto_deadline { return false; }
        wait_ns(regs::RESET_STATUS_POLL_NS);
    }
    true
}

pub(crate) fn apply(c: &Controller, io_base: Option<u16>, profile: ResetProfile) -> bool {
    c.write(regs::IMC, u32::MAX);
    c.write(regs::RCTL, 0);
    c.write(regs::TCTL, c.read(regs::TCTL) & !regs::TCTL_EN);
    let _ = c.read(regs::ICR);
    wait_ns(PRE_RESET_WAIT_NS);
    if profile.mdio_ownership && !acquire_hw_semaphore(c) { return false; }
    let ctrl = c.read(regs::CTRL);
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    if let Some(port) = io_base.filter(|_| profile.legacy_io_reset) {
        io_write32(port, regs::CTRL as u32);
        io_write32(port.wrapping_add(4), ctrl | regs::CTRL_RST);
    } else { c.write(regs::CTRL, ctrl | regs::CTRL_RST); }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { let _ = io_base; c.write(regs::CTRL, ctrl | regs::CTRL_RST); }
    if profile.mdio_ownership { release_hw_semaphore(c); }
    if profile.e1000e_nvm_phy && !wait_auto_read(c) { return false; }
    wait_ns(profile.reset_ns);
    let _ = c.read(regs::ICR);
    true
}
