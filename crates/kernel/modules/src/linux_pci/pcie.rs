use super::config::{bdf, read8, read16, read32, write16};
use super::types::*;
use sync::{Modules as ModulesLockClass, Spinlock};

const PCI_STATUS: u8 = 0x06;
const PCI_STATUS_CAP_LIST: u16 = 1 << 4;
const PCI_CAPABILITY_LIST: u8 = 0x34;
const PCI_CAP_ID_EXP: u8 = 0x10;
const PCI_EXP_DEVCTL: u8 = 0x08;
const PCI_EXP_DEVCTL_READRQ: u16 = 0x7000;
const PCI_EXP_DEVCTL_BCR_FLR: u16 = 0x8000;
const PCI_EXP_DEVSTA: u8 = 0x0a;
const PCI_EXP_DEVSTA_TRPND: u16 = 0x0020;
const PCI_EXP_DEVCAP_FLR: u32 = 0x1000_0000;
const PCI_DEV_FLAGS_NO_FLR_RESET: u16 = 1 << 10;
const PCI_COMMAND: u8 = 0x04;
const PCI_ERROR_RESPONSE: u32 = u32::MAX;
const PCIE_RESET_READY_POLL_MS: u32 = 60_000;
const LINUX_ENOTTY: i32 = 25;
const PCI_EXP_READRQ_MIN: i32 = 128;
const PCI_EXP_READRQ_MAX: i32 = 4096;
const PCI_EXP_READRQ_SHIFT: u32 = 12;
const PCI_CONFIG_CAP_MIN: u8 = 0x40;
const PCI_CONFIG_CAP_MAX: u8 = 0xfc;
const MAX_CAPABILITIES: usize = 48;

static PCIE_CAP_LOCK: Spinlock<(), ModulesLockClass> = Spinlock::new(());

/// Register Linux PCIe capability KPI symbols. # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("pcie_capability_clear_and_set_word_locked", pcie_capability_clear_and_set_word_locked as *const () as usize),
        ("pcie_set_readrq", pcie_set_readrq as *const () as usize),
        ("pcie_reset_flr", pcie_reset_flr as *const () as usize),
        ("pcie_aspm_enabled", pcie_aspm_enabled as *const () as usize),
    ] { export(name, addr, false); }
}

pub(super) extern "C" fn pcie_capability_clear_and_set_word_locked(dev: *mut LinuxPciDev, pos: i32, clear: u16, set: u16) -> i32 {
    let _guard = PCIE_CAP_LOCK.lock();
    clear_and_set_word(dev, pos, clear, set)
}

pub(super) extern "C" fn pcie_set_readrq(dev: *mut LinuxPciDev, rq: i32) -> i32 {
    if !valid_readrq(rq) { return -LINUX_EINVAL; }
    let value = ((rq.trailing_zeros() - PCI_EXP_READRQ_MIN.trailing_zeros()) << PCI_EXP_READRQ_SHIFT) as u16;
    pcie_capability_clear_and_set_word_locked(dev, PCI_EXP_DEVCTL as i32, PCI_EXP_DEVCTL_READRQ, value)
}

/// Return whether this PCIe device has an upstream link with ASPM enabled. # C: O(1)
pub(super) extern "C" fn pcie_aspm_enabled(_dev: *mut LinuxPciDev) -> bool {
    // PCIe ASPM link-state ownership is not installed, so no link may report ASPM enabled.
    false
}

/// Initiate a PCIe function-level reset after IOMMU DMA admission is blocked. # C: O(reset delay)
pub(super) extern "C" fn pcie_reset_flr(dev: *mut LinuxPciDev, probe: bool) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    // SAFETY: dev is non-null and these fields are part of the stable PCI device ABI.
    let supported = unsafe { ((*dev).dev_flags & PCI_DEV_FLAGS_NO_FLR_RESET) == 0 && (*dev).devcap & PCI_EXP_DEVCAP_FLR != 0 };
    if !supported { return -LINUX_ENOTTY; }
    if probe { return LINUX_OK; }
    let requester = bdf(dev);
    iommu::begin_pci_reset(requester);
    let result = pcie_flr(dev);
    iommu::end_pci_reset(requester);
    result
}

fn pcie_flr(dev: *mut LinuxPciDev) -> i32 {
    let Some(cap) = pcie_capability(dev) else { return -LINUX_ENOTTY; };
    let _ = wait_for_pending(dev, cap + PCI_EXP_DEVSTA, PCI_EXP_DEVSTA_TRPND);
    write_word(dev, cap + PCI_EXP_DEVCTL, read_word(dev, cap + PCI_EXP_DEVCTL) | PCI_EXP_DEVCTL_BCR_FLR);
    crate::linux_time::sleep_ms(100);
    wait_for_ready(dev)
}

fn wait_for_pending(dev: *mut LinuxPciDev, offset: u8, mask: u16) -> bool {
    for delay in [0, 100, 200, 400] {
        if delay != 0 { crate::linux_time::sleep_ms(delay); }
        if read_word(dev, offset) & mask == 0 { return true; }
    }
    false
}

fn wait_for_ready(dev: *mut LinuxPciDev) -> i32 {
    let mut delay = 1;
    loop {
        if read32(dev, PCI_COMMAND) != PCI_ERROR_RESPONSE { return LINUX_OK; }
        if delay > PCIE_RESET_READY_POLL_MS { return -LINUX_ENOTTY; }
        crate::linux_time::sleep_ms(delay);
        delay = delay.saturating_mul(2);
    }
}

fn clear_and_set_word(dev: *mut LinuxPciDev, pos: i32, clear: u16, set: u16) -> i32 {
    if dev.is_null() || pos < 0 || pos & 1 != 0 { return -LINUX_EINVAL; }
    let Some(cap) = pcie_capability(dev) else { return LINUX_OK; };
    if pos > (PCI_CONFIG_CAP_MAX - cap) as i32 { return -LINUX_EINVAL; }
    let offset = cap + pos as u8;
    if offset > PCI_CONFIG_CAP_MAX || offset & 1 != 0 { return -LINUX_EINVAL; }
    let mut value = read_word(dev, offset);
    value &= !clear;
    value |= set;
    write_word(dev, offset, value);
    LINUX_OK
}

fn pcie_capability(dev: *mut LinuxPciDev) -> Option<u8> {
    if dev.is_null() || read_word(dev, PCI_STATUS) & PCI_STATUS_CAP_LIST == 0 { return None; }
    let mut pos = read_byte(dev, PCI_CAPABILITY_LIST) & !3;
    for _ in 0..MAX_CAPABILITIES {
        if !(PCI_CONFIG_CAP_MIN..=PCI_CONFIG_CAP_MAX).contains(&pos) { return None; }
        let header = read32(dev, pos);
        if header as u8 == PCI_CAP_ID_EXP { return Some(pos); }
        let next = ((header >> 8) & u8::MAX as u32) as u8 & !3;
        if next == pos { return None; }
        pos = next;
    }
    None
}

fn valid_readrq(rq: i32) -> bool {
    (PCI_EXP_READRQ_MIN..=PCI_EXP_READRQ_MAX).contains(&rq) && rq & (rq - 1) == 0
}

fn read_byte(dev: *mut LinuxPciDev, offset: u8) -> u8 {
    read8(dev, offset)
}

fn read_word(dev: *mut LinuxPciDev, offset: u8) -> u16 {
    read16(dev, offset)
}

fn write_word(dev: *mut LinuxPciDev, offset: u8, value: u16) {
    write16(dev, offset, value);
}
