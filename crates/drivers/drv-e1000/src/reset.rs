use crate::{imp::Controller, profile::ResetProfile, regs};

const SEMAPHORE_RETRIES: usize = 64;
const SEMAPHORE_WAIT_NS: u64 = 50_000;
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

fn acquire_phy(c: &Controller) -> bool {
    for _ in 0..SEMAPHORE_RETRIES {
        if c.read(regs::SWSM) & regs::SWSM_SMBI == 0 { break; }
        wait_ns(SEMAPHORE_WAIT_NS);
    }
    for _ in 0..SEMAPHORE_RETRIES {
        c.write(regs::SWSM, c.read(regs::SWSM) | regs::SWSM_SWESMBI);
        if c.read(regs::SWSM) & regs::SWSM_SWESMBI != 0 { return true; }
        wait_ns(SEMAPHORE_WAIT_NS);
    }
    release_phy(c);
    false
}

fn release_phy(c: &Controller) {
    c.write(regs::SWSM, c.read(regs::SWSM) & !(regs::SWSM_SMBI | regs::SWSM_SWESMBI));
}

pub(crate) fn apply(c: &Controller, io_base: Option<u16>, profile: ResetProfile) -> bool {
    c.write(regs::IMC, u32::MAX);
    c.write(regs::RCTL, 0);
    c.write(regs::TCTL, c.read(regs::TCTL) & !regs::TCTL_EN);
    let _ = c.read(regs::ICR);
    wait_ns(PRE_RESET_WAIT_NS);
    let owned = profile.owns_phy && acquire_phy(c);
    if profile.owns_phy && !owned { return false; }
    let ctrl = c.read(regs::CTRL);
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    if let Some(port) = io_base.filter(|_| profile.legacy_io_reset) {
        io_write32(port, regs::CTRL as u32);
        io_write32(port.wrapping_add(4), ctrl | regs::CTRL_RST);
    } else { c.write(regs::CTRL, ctrl | regs::CTRL_RST); }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { let _ = io_base; c.write(regs::CTRL, ctrl | regs::CTRL_RST); }
    if owned { release_phy(c); }
    wait_ns(profile.reset_ns);
    let _ = c.read(regs::ICR);
    true
}
