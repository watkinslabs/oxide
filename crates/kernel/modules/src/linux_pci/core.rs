use super::types::*;
use core::ffi::{c_char, c_void};
use core::ptr::null_mut;
use pci::{
    Bdf, COMMAND_BUS_MASTER, COMMAND_IO, COMMAND_MEMORY, IORESOURCE_IO, IORESOURCE_MEM,
};
use sync::{Modules as ModulesLockClass, Spinlock};

const MAX_REGION_CLAIMS: usize = 64;
const PCI_DEVFN_DEV_SHIFT: u8 = 3;
const PCI_CONFIG_ALIGN: u8 = 4;
const PCI_CONFIG_BYTE_MASK: u32 = 0xff;
const PCI_CONFIG_WORD_MASK: u32 = 0xffff;
const PCI_CONFIG_SPACE_BYTES: u16 = 256;
const PCI_RESOURCE_EMPTY: u64 = 0;
const INVALID_RESOURCE: usize = usize::MAX;

#[derive(Copy, Clone)]
struct RegionClaim {
    dev: usize,
    bar: usize,
    start: u64,
    end: u64,
}

static REGIONS: Spinlock<[Option<RegionClaim>; MAX_REGION_CLAIMS], ModulesLockClass> =
    Spinlock::new([None; MAX_REGION_CLAIMS]);

/// Register Linux PCI KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("__pci_register_driver",    __pci_register_driver    as *const () as usize),
        ("pci_register_driver",       pci_register_driver       as *const () as usize),
        ("pci_unregister_driver",     pci_unregister_driver     as *const () as usize),
        ("pci_enable_device",         pci_enable_device         as *const () as usize),
        ("pci_enable_device_mem",     pci_enable_device_mem     as *const () as usize),
        ("pci_disable_device",        pci_disable_device        as *const () as usize),
        ("pcim_enable_device",        pcim_enable_device        as *const () as usize),
        ("pcim_pin_device",           pcim_pin_device           as *const () as usize),
        ("pci_set_master",            pci_set_master            as *const () as usize),
        ("pci_clear_master",          pci_clear_master          as *const () as usize),
        ("pci_set_drvdata",           pci_set_drvdata           as *const () as usize),
        ("pci_get_drvdata",           pci_get_drvdata           as *const () as usize),
        ("pci_name",                  pci_name                  as *const () as usize),
        ("pci_resource_start",        pci_resource_start        as *const () as usize),
        ("pci_resource_end",          pci_resource_end          as *const () as usize),
        ("pci_resource_flags",        pci_resource_flags        as *const () as usize),
        ("pci_resource_len",          pci_resource_len          as *const () as usize),
        ("pci_request_region",        pci_request_region        as *const () as usize),
        ("pci_release_region",        pci_release_region        as *const () as usize),
        ("pci_request_regions",       pci_request_regions       as *const () as usize),
        ("pci_release_regions",       pci_release_regions       as *const () as usize),
        ("pcim_request_all_regions",  pcim_request_all_regions  as *const () as usize),
        ("pcim_release_all_regions",  pcim_release_all_regions  as *const () as usize),
        ("pci_iomap",                 pci_iomap                 as *const () as usize),
        ("pcim_iomap",                pcim_iomap                as *const () as usize),
        ("pcim_iounmap",              pcim_iounmap              as *const () as usize),
        ("pci_ioremap_bar",           pci_ioremap_bar           as *const () as usize),
        ("pci_ioremap_wc_bar",        pci_ioremap_wc_bar        as *const () as usize),
        ("pci_iounmap",               pci_iounmap               as *const () as usize),
        ("pci_enable_msi",            pci_enable_msi            as *const () as usize),
        ("pci_disable_msi",           pci_disable_msi           as *const () as usize),
        ("pci_msix_vec_count",        pci_msix_vec_count        as *const () as usize),
        ("pci_alloc_irq_vectors",     pci_alloc_irq_vectors     as *const () as usize),
        ("pci_free_irq_vectors",      pci_free_irq_vectors      as *const () as usize),
        ("pci_irq_vector",            pci_irq_vector            as *const () as usize),
        ("pci_read_config_byte",      pci_read_config_byte      as *const () as usize),
        ("pci_read_config_word",      pci_read_config_word      as *const () as usize),
        ("pci_read_config_dword",     pci_read_config_dword     as *const () as usize),
        ("pci_write_config_byte",     pci_write_config_byte     as *const () as usize),
        ("pci_write_config_word",     pci_write_config_word     as *const () as usize),
        ("pci_write_config_dword",    pci_write_config_dword    as *const () as usize),
    ] { export(name, addr, false); }
}

extern "C" fn __pci_register_driver(
    driver: *mut LinuxPciDriver,
    _owner: *mut c_void,
    _mod_name: *const c_char,
) -> i32 {
    pci_register_driver(driver)
}

extern "C" fn pci_register_driver(driver: *mut LinuxPciDriver) -> i32 {
    super::registry::register_driver(driver)
}

extern "C" fn pci_unregister_driver(driver: *mut LinuxPciDriver) {
    super::registry::unregister_driver(driver);
}

extern "C" fn pci_enable_device(dev: *mut LinuxPciDev) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    let old = read_config32(dev, PCI_COMMAND_STATUS_OFF);
    let mut cmd = old & PCI_COMMAND_MASK;
    if has_resource(dev, IORESOURCE_IO) { cmd |= COMMAND_IO as u32; }
    if has_resource(dev, IORESOURCE_MEM) { cmd |= COMMAND_MEMORY as u32; }
    write_config32(dev, PCI_COMMAND_STATUS_OFF, (old & PCI_STATUS_MASK) | cmd);
    LINUX_OK
}

extern "C" fn pci_enable_device_mem(dev: *mut LinuxPciDev) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    let old = read_config32(dev, PCI_COMMAND_STATUS_OFF);
    write_config32(dev, PCI_COMMAND_STATUS_OFF, (old & PCI_STATUS_MASK) | COMMAND_MEMORY as u32);
    LINUX_OK
}

extern "C" fn pci_disable_device(dev: *mut LinuxPciDev) {
    if dev.is_null() { return; }
    let old = read_config32(dev, PCI_COMMAND_STATUS_OFF);
    let cmd = (old & PCI_COMMAND_MASK) & !(COMMAND_IO as u32 | COMMAND_MEMORY as u32);
    write_config32(dev, PCI_COMMAND_STATUS_OFF, (old & PCI_STATUS_MASK) | cmd);
}

extern "C" fn pcim_enable_device(dev: *mut LinuxPciDev) -> i32 { pci_enable_device(dev) }

extern "C" fn pcim_pin_device(_dev: *mut LinuxPciDev) -> i32 { LINUX_OK }

extern "C" fn pci_set_master(dev: *mut LinuxPciDev) {
    if dev.is_null() { return; }
    update_command(dev, COMMAND_BUS_MASTER, true);
}

extern "C" fn pci_clear_master(dev: *mut LinuxPciDev) {
    if dev.is_null() { return; }
    update_command(dev, COMMAND_BUS_MASTER, false);
}

extern "C" fn pci_set_drvdata(dev: *mut LinuxPciDev, data: *mut c_void) {
    if dev.is_null() { return; }
    // SAFETY: dev points at a caller-owned Linux struct pci_dev.
    unsafe { (*dev).driver_data = data; }
}

extern "C" fn pci_get_drvdata(dev: *const LinuxPciDev) -> *mut c_void {
    if dev.is_null() { null_mut() } else {
        // SAFETY: dev points at a caller-owned Linux struct pci_dev.
        unsafe { (*dev).driver_data }
    }
}

extern "C" fn pci_name(dev: *const LinuxPciDev) -> *const c_char {
    if dev.is_null() { return core::ptr::null(); }
    populate_name(dev as *mut LinuxPciDev);
    // SAFETY: dev points at a caller-owned Linux struct pci_dev.
    unsafe { (*dev).name.as_ptr() }
}

extern "C" fn pci_resource_start(dev: *const LinuxPciDev, bar: i32) -> u64 {
    resource(dev, bar).map(|r| r.start).unwrap_or(PCI_RESOURCE_EMPTY)
}

extern "C" fn pci_resource_end(dev: *const LinuxPciDev, bar: i32) -> u64 {
    resource(dev, bar).map(|r| r.end).unwrap_or(PCI_RESOURCE_EMPTY)
}

extern "C" fn pci_resource_flags(dev: *const LinuxPciDev, bar: i32) -> u64 {
    resource(dev, bar).map(|r| r.flags).unwrap_or(PCI_RESOURCE_EMPTY)
}

extern "C" fn pci_resource_len(dev: *const LinuxPciDev, bar: i32) -> u64 {
    resource(dev, bar).map(resource_len).unwrap_or(PCI_RESOURCE_EMPTY)
}

extern "C" fn pci_request_region(dev: *mut LinuxPciDev, bar: i32, _name: *const c_char) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    let idx = match valid_bar(bar) { Some(v) => v, None => return -LINUX_EINVAL };
    let res = match resource(dev, bar) {
        Some(v) if resource_len(v) != 0 => v,
        _ => return -LINUX_ENODEV,
    };
    claim_region(dev, idx, res)
}

extern "C" fn pci_release_region(dev: *mut LinuxPciDev, bar: i32) {
    if dev.is_null() { return; }
    if let Some(idx) = valid_bar(bar) { release_region(dev, idx); }
}

extern "C" fn pci_request_regions(dev: *mut LinuxPciDev, name: *const c_char) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    let mut claimed = [INVALID_RESOURCE; PCI_STD_NUM_BARS];
    let mut n = 0usize;
    for bar in 0..PCI_STD_NUM_BARS {
        if pci_resource_len(dev, bar as i32) == 0 { continue; }
        let rc = pci_request_region(dev, bar as i32, name);
        if rc != LINUX_OK {
            for old in claimed.iter().take(n) { release_region(dev, *old); }
            return rc;
        }
        claimed[n] = bar;
        n += 1;
    }
    LINUX_OK
}

extern "C" fn pci_release_regions(dev: *mut LinuxPciDev) {
    if dev.is_null() { return; }
    for bar in 0..PCI_STD_NUM_BARS { release_region(dev, bar); }
}

extern "C" fn pcim_request_all_regions(dev: *mut LinuxPciDev, name: *const c_char) -> i32 { pci_request_regions(dev, name) }

extern "C" fn pcim_release_all_regions(dev: *mut LinuxPciDev) { pci_release_regions(dev); }

extern "C" fn pci_iomap(dev: *mut LinuxPciDev, bar: i32, maxlen: usize) -> *mut c_void {
    let res = match resource(dev, bar) { Some(v) => v, None => return null_mut() };
    let len = bounded_resource_len(res, maxlen);
    if len == 0 { return null_mut(); }
    super::maps::iomap_resource(res, len).unwrap_or(null_mut())
}

extern "C" fn pcim_iomap(dev: *mut LinuxPciDev, bar: i32, maxlen: usize) -> *mut c_void { pci_iomap(dev, bar, maxlen) }

extern "C" fn pcim_iounmap(dev: *mut LinuxPciDev, addr: *mut c_void) { pci_iounmap(dev, addr); }

extern "C" fn pci_ioremap_bar(dev: *mut LinuxPciDev, bar: i32) -> *mut c_void {
    pci_iomap(dev, bar, 0)
}

extern "C" fn pci_ioremap_wc_bar(dev: *mut LinuxPciDev, bar: i32) -> *mut c_void {
    pci_iomap(dev, bar, 0)
}

extern "C" fn pci_iounmap(_dev: *mut LinuxPciDev, addr: *mut c_void) {
    super::maps::iounmap(addr);
}

extern "C" fn pci_enable_msi(dev: *mut LinuxPciDev) -> i32 {
    match pci_alloc_irq_vectors(dev, 1, 1, PCI_IRQ_MSI) {
        1 => LINUX_OK,
        err => err,
    }
}

extern "C" fn pci_disable_msi(dev: *mut LinuxPciDev) {
    if dev.is_null() { return; }
    // SAFETY: pci_disable_msi's KPI contract is that dev is the struct pci_dev the probe callback
    // was handed, which registry::bind_model_device keeps Box-alive in BINDINGS until unbind; dev
    // was checked non-null above, and only the irq_vector_flags word set by alloc_irq_vectors is
    // read here.
    let flags = unsafe {
        (*dev).irq_vector_flags
    };
    if flags & PCI_IRQ_MSI != 0 { pci_free_irq_vectors(dev); }
}

extern "C" fn pci_msix_vec_count(_dev: *mut LinuxPciDev) -> i32 { -LINUX_EINVAL }

extern "C" fn pci_alloc_irq_vectors(dev: *mut LinuxPciDev, min_vecs: i32, max_vecs: i32, flags: u32) -> i32 {
    super::vectors::alloc_irq_vectors(dev, min_vecs, max_vecs, flags)
}

extern "C" fn pci_free_irq_vectors(dev: *mut LinuxPciDev) {
    super::vectors::free_irq_vectors(dev);
}

extern "C" fn pci_irq_vector(dev: *mut LinuxPciDev, nr: u32) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    // SAFETY: dev points at a caller-owned Linux struct pci_dev.
    unsafe {
        if (*dev).irq_vectors <= 0 || nr >= (*dev).irq_vectors as u32 { return -LINUX_EINVAL; }
        (*dev).irq_vector_base.wrapping_add(nr) as i32
    }
}

extern "C" fn pci_read_config_byte(dev: *mut LinuxPciDev, pos: i32, val: *mut u8) -> i32 {
    if val.is_null() { return -LINUX_EINVAL; }
    let (dword, shift) = match config_access(dev, pos, PCI_CONFIG_BYTE_BYTES) { Some(v) => v, None => return -LINUX_EINVAL };
    // SAFETY: val is caller-provided writable storage for one byte.
    unsafe { *val = ((dword >> shift) & PCI_CONFIG_BYTE_MASK) as u8; }
    LINUX_OK
}

extern "C" fn pci_read_config_word(dev: *mut LinuxPciDev, pos: i32, val: *mut u16) -> i32 {
    if val.is_null() || (pos as u8 & WORD_ALIGN_MASK) != 0 { return -LINUX_EINVAL; }
    let (dword, shift) = match config_access(dev, pos, PCI_CONFIG_WORD_BYTES) { Some(v) => v, None => return -LINUX_EINVAL };
    // SAFETY: val is caller-provided writable storage for one word.
    unsafe { *val = ((dword >> shift) & PCI_CONFIG_WORD_MASK) as u16; }
    LINUX_OK
}

extern "C" fn pci_read_config_dword(dev: *mut LinuxPciDev, pos: i32, val: *mut u32) -> i32 {
    if val.is_null() || !config_pos_valid(pos, PCI_CONFIG_ALIGN) { return -LINUX_EINVAL; }
    // SAFETY: val is caller-provided writable storage for one dword.
    unsafe { *val = read_config32(dev, pos as u8); }
    LINUX_OK
}

extern "C" fn pci_write_config_byte(dev: *mut LinuxPciDev, pos: i32, val: u8) -> i32 {
    write_config_masked(dev, pos, PCI_CONFIG_BYTE_BYTES, PCI_CONFIG_BYTE_MASK, val as u32)
}

extern "C" fn pci_write_config_word(dev: *mut LinuxPciDev, pos: i32, val: u16) -> i32 {
    if (pos as u8 & WORD_ALIGN_MASK) != 0 { return -LINUX_EINVAL; }
    write_config_masked(dev, pos, PCI_CONFIG_WORD_BYTES, PCI_CONFIG_WORD_MASK, val as u32)
}

extern "C" fn pci_write_config_dword(dev: *mut LinuxPciDev, pos: i32, val: u32) -> i32 {
    if !config_pos_valid(pos, PCI_CONFIG_ALIGN) { return -LINUX_EINVAL; }
    write_config32(dev, pos as u8, val);
    LINUX_OK
}

const PCI_COMMAND_STATUS_OFF: u8 = 0x04;
const PCI_COMMAND_MASK: u32 = 0x0000_ffff;
const PCI_STATUS_MASK: u32 = 0xffff_0000;
const PCI_CONFIG_BYTE_BYTES: u8 = 1;
const PCI_CONFIG_WORD_BYTES: u8 = 2;
const WORD_ALIGN_MASK: u8 = 1;
const PCI_SLOT_MASK: u8 = 0x1f;
const PCI_FUNC_MASK: u8 = 0x07;
const HEX_LOW_NIBBLE_MASK: u8 = 0x0f;
const HEX_DECIMAL_DIGITS: u8 = 10;
const HEX_NIBBLE_SHIFT: u32 = 4;
const PCI_DOMAIN_HEX0: usize = 0;
const PCI_DOMAIN_HEX1: usize = 1;
const PCI_DOMAIN_HEX2: usize = 2;
const PCI_DOMAIN_HEX3: usize = 3;
const PCI_DOMAIN_BUS_SEP: usize = 4;
const PCI_BUS_HEX0: usize = 5;
const PCI_BUS_HEX1: usize = 6;
const PCI_SLOT_SEP: usize = 7;
const PCI_SLOT_HEX0: usize = 8;
const PCI_SLOT_HEX1: usize = 9;
const PCI_FUNC_SEP: usize = 10;
const PCI_FUNC_HEX: usize = 11;

fn bdf(dev: *const LinuxPciDev) -> Bdf {
    // SAFETY: callers validate dev before deriving the BDF.
    unsafe {
        Bdf {
            bus: (*dev).bus,
            device: ((*dev).devfn >> PCI_DEVFN_DEV_SHIFT) & PCI_SLOT_MASK,
            function: (*dev).devfn & PCI_FUNC_MASK,
        }
    }
}

fn update_command(dev: *mut LinuxPciDev, bit: u16, set: bool) {
    let old = read_config32(dev, PCI_COMMAND_STATUS_OFF);
    let mut cmd = old & PCI_COMMAND_MASK;
    if set { cmd |= bit as u32; } else { cmd &= !(bit as u32); }
    write_config32(dev, PCI_COMMAND_STATUS_OFF, (old & PCI_STATUS_MASK) | cmd);
}

fn has_resource(dev: *const LinuxPciDev, flag: u64) -> bool {
    for bar in 0..PCI_STD_NUM_BARS {
        if pci_resource_len(dev, bar as i32) != 0 && (pci_resource_flags(dev, bar as i32) & flag) != 0 {
            return true;
        }
    }
    false
}

fn resource(dev: *const LinuxPciDev, bar: i32) -> Option<LinuxResource> {
    let idx = valid_bar(bar)?;
    if dev.is_null() { return None; }
    // SAFETY: dev points at a caller-owned Linux struct pci_dev.
    Some(unsafe { (*dev).resource[idx] })
}

fn valid_bar(bar: i32) -> Option<usize> {
    if bar < 0 || bar as usize >= PCI_STD_NUM_BARS { None } else { Some(bar as usize) }
}

fn resource_len(r: LinuxResource) -> u64 {
    if r.start == 0 && r.end == 0 { 0 }
    else if r.end < r.start { 0 }
    else { r.end.saturating_sub(r.start).saturating_add(1) }
}

fn bounded_resource_len(r: LinuxResource, maxlen: usize) -> u64 {
    let len = resource_len(r);
    if maxlen == 0 { len } else { len.min(maxlen as u64) }
}

fn claim_region(dev: *mut LinuxPciDev, bar: usize, res: LinuxResource) -> i32 {
    let mut g = REGIONS.lock();
    if g.iter().flatten().any(|r| overlaps(r.start, r.end, res.start, res.end)) {
        return -LINUX_EBUSY;
    }
    if let Some(slot) = g.iter_mut().find(|r| r.is_none()) {
        *slot = Some(RegionClaim { dev: dev as usize, bar, start: res.start, end: res.end });
        LINUX_OK
    } else { -LINUX_ENOMEM }
}

fn release_region(dev: *mut LinuxPciDev, bar: usize) {
    let mut g = REGIONS.lock();
    if let Some(slot) = g.iter_mut().find(|r| r.is_some_and(|v| v.dev == dev as usize && v.bar == bar)) {
        *slot = None;
    }
}

fn overlaps(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start <= b_end && b_start <= a_end
}

fn config_access(dev: *mut LinuxPciDev, pos: i32, width: u8) -> Option<(u32, u32)> {
    if !config_pos_valid(pos, width) { return None; }
    let off = (pos as u8) & !(PCI_CONFIG_ALIGN - 1);
    let shift = ((pos as u8 - off) as u32) * u8::BITS;
    Some((read_config32(dev, off), shift))
}

fn config_pos_valid(pos: i32, width: u8) -> bool {
    pos >= 0 && (pos as u16).saturating_add(width as u16) <= PCI_CONFIG_SPACE_BYTES
}

fn write_config_masked(dev: *mut LinuxPciDev, pos: i32, width: u8, mask: u32, val: u32) -> i32 {
    if !config_pos_valid(pos, width) { return -LINUX_EINVAL; }
    let off = (pos as u8) & !(PCI_CONFIG_ALIGN - 1);
    let shift = ((pos as u8 - off) as u32) * u8::BITS;
    let old = read_config32(dev, off);
    write_config32(dev, off, (old & !(mask << shift)) | ((val & mask) << shift));
    LINUX_OK
}

fn read_config32(dev: *mut LinuxPciDev, off: u8) -> u32 {
    if dev.is_null() { return u32::MAX; }
    if let Some(v) = hw_read32(bdf(dev), off) { return v; }
    // SAFETY: dev points at a caller-owned Linux struct pci_dev.
    unsafe { (*dev).config_space[(off / PCI_CONFIG_ALIGN) as usize] }
}

fn write_config32(dev: *mut LinuxPciDev, off: u8, val: u32) {
    if dev.is_null() { return; }
    hw_write32(bdf(dev), off, val);
    // SAFETY: dev points at a caller-owned Linux struct pci_dev.
    unsafe { (*dev).config_space[(off / PCI_CONFIG_ALIGN) as usize] = val; }
}

fn populate_name(dev: *mut LinuxPciDev) {
    if dev.is_null() { return; }
    // SAFETY: dev points at a caller-owned Linux struct pci_dev.
    unsafe {
        if (*dev).name[0] != 0 { return; }
        let b = (*dev).bus;
        let slot = ((*dev).devfn >> PCI_DEVFN_DEV_SHIFT) & PCI_SLOT_MASK;
        let func = (*dev).devfn & PCI_FUNC_MASK;
        (*dev).name = [0; PCI_NAME_LEN];
        put_hex(&mut (*dev).name, PCI_DOMAIN_HEX0, 0);
        put_hex(&mut (*dev).name, PCI_DOMAIN_HEX1, 0);
        (*dev).name[PCI_DOMAIN_HEX2] = b'0' as c_char;
        (*dev).name[PCI_DOMAIN_HEX3] = b'0' as c_char;
        (*dev).name[PCI_DOMAIN_BUS_SEP] = b':' as c_char;
        put_hex(&mut (*dev).name, PCI_BUS_HEX0, b >> HEX_NIBBLE_SHIFT);
        put_hex(&mut (*dev).name, PCI_BUS_HEX1, b);
        (*dev).name[PCI_SLOT_SEP] = b':' as c_char;
        put_hex(&mut (*dev).name, PCI_SLOT_HEX0, slot >> HEX_NIBBLE_SHIFT);
        put_hex(&mut (*dev).name, PCI_SLOT_HEX1, slot);
        (*dev).name[PCI_FUNC_SEP] = b'.' as c_char;
        put_hex(&mut (*dev).name, PCI_FUNC_HEX, func);
    }
}

fn put_hex(buf: &mut [c_char; PCI_NAME_LEN], idx: usize, v: u8) {
    let n = v & HEX_LOW_NIBBLE_MASK;
    buf[idx] = if n < HEX_DECIMAL_DIGITS { (b'0' + n) as c_char } else { (b'a' + (n - HEX_DECIMAL_DIGITS)) as c_char };
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn hw_read32(bdf: Bdf, off: u8) -> Option<u32> {
    hal_x86_64::pci::EcamPci::from_published().map(|r| pci::ConfigSpaceReader::read32(&r, bdf, off))
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn hw_read32(bdf: Bdf, off: u8) -> Option<u32> {
    hal_aarch64::pci::EcamPci::from_published().map(|r| pci::ConfigSpaceReader::read32(&r, bdf, off))
}

#[cfg(not(all(target_os = "oxide-kernel", any(target_arch = "x86_64", target_arch = "aarch64"))))]
fn hw_read32(_bdf: Bdf, _off: u8) -> Option<u32> { None }

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn hw_write32(bdf: Bdf, off: u8, val: u32) {
    if let Some(r) = hal_x86_64::pci::EcamPci::from_published() {
        pci::ConfigSpaceReader::write32(&r, bdf, off, val);
    }
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn hw_write32(bdf: Bdf, off: u8, val: u32) {
    if let Some(r) = hal_aarch64::pci::EcamPci::from_published() {
        pci::ConfigSpaceReader::write32(&r, bdf, off, val);
    }
}

#[cfg(not(all(target_os = "oxide-kernel", any(target_arch = "x86_64", target_arch = "aarch64"))))]
fn hw_write32(_bdf: Bdf, _off: u8, _val: u32) {}

#[cfg(test)]
mod tests;
