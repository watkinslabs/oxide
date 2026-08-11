use super::registry;
use super::types::*;
use pci::Bdf;

const PCI_DEVFN_DEV_SHIFT: u8 = 3;
const PCI_CONFIG_ALIGN: u8 = 4;
const PCI_CONFIG_SPACE_BYTES: u16 = 256;
const PCI_SLOT_MASK: u8 = 0x1f;
const PCI_FUNC_MASK: u8 = 0x07;
const WORD_ALIGN_MASK: u8 = 1;

pub(super) fn bdf(dev: *const LinuxPciDev) -> Bdf {
    if let Some(bdf) = registry::bdf_for(dev) { return bdf; }
    // SAFETY: callers validate dev before deriving the BDF.
    unsafe {
        Bdf {
            segment: 0,
            bus: (*dev).bus,
            device: ((*dev).devfn >> PCI_DEVFN_DEV_SHIFT) & PCI_SLOT_MASK,
            function: (*dev).devfn & PCI_FUNC_MASK,
        }
    }
}

pub(super) extern "C" fn pci_read_config_byte(dev: *mut LinuxPciDev, pos: i32, val: *mut u8) -> i32 {
    if val.is_null() || !config_pos_valid(pos, 1) { return -LINUX_EINVAL; }
    // SAFETY: val is caller-provided writable storage for one byte.
    unsafe { *val = read8(dev, pos as u8); }
    LINUX_OK
}

pub(super) extern "C" fn pci_read_config_word(dev: *mut LinuxPciDev, pos: i32, val: *mut u16) -> i32 {
    if val.is_null() || pos as u8 & WORD_ALIGN_MASK != 0 || !config_pos_valid(pos, 2) { return -LINUX_EINVAL; }
    // SAFETY: val is caller-provided writable storage for one word.
    unsafe { *val = read16(dev, pos as u8); }
    LINUX_OK
}

pub(super) extern "C" fn pci_read_config_dword(dev: *mut LinuxPciDev, pos: i32, val: *mut u32) -> i32 {
    if val.is_null() || !config_pos_valid(pos, PCI_CONFIG_ALIGN) { return -LINUX_EINVAL; }
    // SAFETY: val is caller-provided writable storage for one dword.
    unsafe { *val = read32(dev, pos as u8); }
    LINUX_OK
}

pub(super) extern "C" fn pci_write_config_byte(dev: *mut LinuxPciDev, pos: i32, val: u8) -> i32 {
    if !config_pos_valid(pos, 1) { return -LINUX_EINVAL; }
    write8(dev, pos as u8, val);
    LINUX_OK
}

pub(super) extern "C" fn pci_write_config_word(dev: *mut LinuxPciDev, pos: i32, val: u16) -> i32 {
    if pos as u8 & WORD_ALIGN_MASK != 0 || !config_pos_valid(pos, 2) { return -LINUX_EINVAL; }
    write16(dev, pos as u8, val);
    LINUX_OK
}

pub(super) extern "C" fn pci_write_config_dword(dev: *mut LinuxPciDev, pos: i32, val: u32) -> i32 {
    if !config_pos_valid(pos, PCI_CONFIG_ALIGN) { return -LINUX_EINVAL; }
    write32(dev, pos as u8, val);
    LINUX_OK
}

pub(super) fn read8(dev: *mut LinuxPciDev, off: u8) -> u8 {
    if dev.is_null() { return u8::MAX; }
    if let Some(v) = hw_read8(bdf(dev), off) { return v; }
    (read32(dev, off & !(PCI_CONFIG_ALIGN - 1)) >> ((off & (PCI_CONFIG_ALIGN - 1)) * u8::BITS as u8)) as u8
}

pub(super) fn read16(dev: *mut LinuxPciDev, off: u8) -> u16 {
    if dev.is_null() { return u16::MAX; }
    if let Some(v) = hw_read16(bdf(dev), off) { return v; }
    (read32(dev, off & !(PCI_CONFIG_ALIGN - 1)) >> ((off & (PCI_CONFIG_ALIGN - 1)) * u8::BITS as u8)) as u16
}

pub(super) fn read32(dev: *mut LinuxPciDev, off: u8) -> u32 {
    if dev.is_null() { return u32::MAX; }
    if let Some(v) = hw_read32(bdf(dev), off) { return v; }
    // SAFETY: dev points at a caller-owned Linux struct pci_dev.
    unsafe { (*dev).config_space[(off / PCI_CONFIG_ALIGN) as usize] }
}

pub(super) fn write8(dev: *mut LinuxPciDev, off: u8, val: u8) {
    if dev.is_null() { return; }
    if hw_write8(bdf(dev), off, val) { return; }
    let aligned = off & !(PCI_CONFIG_ALIGN - 1);
    let shift = (off & (PCI_CONFIG_ALIGN - 1)) * u8::BITS as u8;
    let old = read32(dev, aligned);
    write32(dev, aligned, (old & !((u8::MAX as u32) << shift)) | (val as u32) << shift);
}

pub(super) fn write16(dev: *mut LinuxPciDev, off: u8, val: u16) {
    if dev.is_null() { return; }
    if hw_write16(bdf(dev), off, val) { return; }
    let aligned = off & !(PCI_CONFIG_ALIGN - 1);
    let shift = (off & (PCI_CONFIG_ALIGN - 1)) * u8::BITS as u8;
    let old = read32(dev, aligned);
    write32(dev, aligned, (old & !((u16::MAX as u32) << shift)) | (val as u32) << shift);
}

pub(super) fn clear16_w1c(dev: *mut LinuxPciDev, off: u8, mask: u16) {
    if dev.is_null() { return; }
    if hw_write16(bdf(dev), off, mask) { return; }
    let aligned = off & !(PCI_CONFIG_ALIGN - 1);
    let shift = (off & (PCI_CONFIG_ALIGN - 1)) * u8::BITS as u8;
    let old = read32(dev, aligned);
    write32(dev, aligned, old & !((mask as u32) << shift));
}

pub(super) fn write32(dev: *mut LinuxPciDev, off: u8, val: u32) {
    if dev.is_null() { return; }
    hw_write32(bdf(dev), off, val);
    // SAFETY: dev points at a caller-owned Linux struct pci_dev.
    unsafe { (*dev).config_space[(off / PCI_CONFIG_ALIGN) as usize] = val; }
}

fn config_pos_valid(pos: i32, width: u8) -> bool {
    pos >= 0 && (pos as u16).saturating_add(width as u16) <= PCI_CONFIG_SPACE_BYTES
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn hw_read8(bdf: Bdf, off: u8) -> Option<u8> { hal_x86_64::pci::EcamPci::from_published().map(|r| pci::ConfigSpaceReader::read8_ext(&r, bdf, off.into())) }
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn hw_read8(bdf: Bdf, off: u8) -> Option<u8> { hal_aarch64::pci::EcamPci::from_published().map(|r| pci::ConfigSpaceReader::read8_ext(&r, bdf, off.into())) }
#[cfg(not(all(target_os = "oxide-kernel", any(target_arch = "x86_64", target_arch = "aarch64"))))]
fn hw_read8(_bdf: Bdf, _off: u8) -> Option<u8> { None }

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn hw_read16(bdf: Bdf, off: u8) -> Option<u16> { hal_x86_64::pci::EcamPci::from_published().map(|r| pci::ConfigSpaceReader::read16_ext(&r, bdf, off.into())) }
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn hw_read16(bdf: Bdf, off: u8) -> Option<u16> { hal_aarch64::pci::EcamPci::from_published().map(|r| pci::ConfigSpaceReader::read16_ext(&r, bdf, off.into())) }
#[cfg(not(all(target_os = "oxide-kernel", any(target_arch = "x86_64", target_arch = "aarch64"))))]
fn hw_read16(_bdf: Bdf, _off: u8) -> Option<u16> { None }

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn hw_read32(bdf: Bdf, off: u8) -> Option<u32> { hal_x86_64::pci::EcamPci::from_published().map(|r| pci::ConfigSpaceReader::read32(&r, bdf, off)) }
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn hw_read32(bdf: Bdf, off: u8) -> Option<u32> { hal_aarch64::pci::EcamPci::from_published().map(|r| pci::ConfigSpaceReader::read32(&r, bdf, off)) }
#[cfg(not(all(target_os = "oxide-kernel", any(target_arch = "x86_64", target_arch = "aarch64"))))]
fn hw_read32(_bdf: Bdf, _off: u8) -> Option<u32> { None }

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn hw_write8(bdf: Bdf, off: u8, val: u8) -> bool { let Some(r) = hal_x86_64::pci::EcamPci::from_published() else { return false; }; pci::ConfigSpaceReader::write8_ext(&r, bdf, off.into(), val); true }
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn hw_write8(bdf: Bdf, off: u8, val: u8) -> bool { let Some(r) = hal_aarch64::pci::EcamPci::from_published() else { return false; }; pci::ConfigSpaceReader::write8_ext(&r, bdf, off.into(), val); true }
#[cfg(not(all(target_os = "oxide-kernel", any(target_arch = "x86_64", target_arch = "aarch64"))))]
fn hw_write8(_bdf: Bdf, _off: u8, _val: u8) -> bool { false }

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn hw_write16(bdf: Bdf, off: u8, val: u16) -> bool { let Some(r) = hal_x86_64::pci::EcamPci::from_published() else { return false; }; pci::ConfigSpaceReader::write16_ext(&r, bdf, off.into(), val); true }
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn hw_write16(bdf: Bdf, off: u8, val: u16) -> bool { let Some(r) = hal_aarch64::pci::EcamPci::from_published() else { return false; }; pci::ConfigSpaceReader::write16_ext(&r, bdf, off.into(), val); true }
#[cfg(not(all(target_os = "oxide-kernel", any(target_arch = "x86_64", target_arch = "aarch64"))))]
fn hw_write16(_bdf: Bdf, _off: u8, _val: u16) -> bool { false }

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn hw_write32(bdf: Bdf, off: u8, val: u32) { if let Some(r) = hal_x86_64::pci::EcamPci::from_published() { pci::ConfigSpaceReader::write32(&r, bdf, off, val); } }
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn hw_write32(bdf: Bdf, off: u8, val: u32) { if let Some(r) = hal_aarch64::pci::EcamPci::from_published() { pci::ConfigSpaceReader::write32(&r, bdf, off, val); } }
#[cfg(not(all(target_os = "oxide-kernel", any(target_arch = "x86_64", target_arch = "aarch64"))))]
fn hw_write32(_bdf: Bdf, _off: u8, _val: u32) {}
