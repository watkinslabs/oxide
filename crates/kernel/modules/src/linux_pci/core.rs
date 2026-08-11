use super::types::*;
use super::config::{bdf, read32 as read_config32, write32 as write_config32};
use super::regions;
use crate::linux_device::devres;
use core::ffi::{c_char, c_void};
use core::ptr::null_mut;
use pci::{
    COMMAND_BUS_MASTER, COMMAND_IO, COMMAND_MEMORY, IORESOURCE_IO, IORESOURCE_MEM,
};
const PCI_RESOURCE_EMPTY: u64 = 0;
const INVALID_RESOURCE: usize = usize::MAX;

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
        ("pci_select_bars",            regions::pci_select_bars as *const () as usize),
        ("pci_request_selected_regions", regions::pci_request_selected_regions as *const () as usize),
        ("pci_release_selected_regions", regions::pci_release_selected_regions as *const () as usize),
        ("pcim_request_all_regions",  pcim_request_all_regions  as *const () as usize),
        ("pcim_release_all_regions",  pcim_release_all_regions  as *const () as usize),
        ("pci_iomap",                 pci_iomap                 as *const () as usize),
        ("pcim_iomap",                pcim_iomap                as *const () as usize),
        ("pcim_iomap_region",         pcim_iomap_region         as *const () as usize),
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
        ("pci_read_config_byte",      super::config::pci_read_config_byte      as *const () as usize),
        ("pci_read_config_word",      super::config::pci_read_config_word      as *const () as usize),
        ("pci_read_config_dword",     super::config::pci_read_config_dword     as *const () as usize),
        ("pci_write_config_byte",     super::config::pci_write_config_byte     as *const () as usize),
        ("pci_write_config_word",     super::config::pci_write_config_word     as *const () as usize),
        ("pci_write_config_dword",    super::config::pci_write_config_dword    as *const () as usize),
        ("pci_device_is_present",     super::config::pci_device_is_present     as *const () as usize),
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
    if !pci::bus_master_admitted(bdf(dev)) { return; }
    update_command(dev, COMMAND_BUS_MASTER, true);
}

extern "C" fn pci_clear_master(dev: *mut LinuxPciDev) {
    if dev.is_null() { return; }
    update_command(dev, COMMAND_BUS_MASTER, false);
}

extern "C" fn pci_set_drvdata(dev: *mut LinuxPciDev, data: *mut c_void) {
    if dev.is_null() { return; }
    // SAFETY: dev points at a caller-owned Linux struct pci_dev.
    unsafe { (*dev).dev.driver_data = data; }
}

extern "C" fn pci_get_drvdata(dev: *const LinuxPciDev) -> *mut c_void {
    if dev.is_null() { null_mut() } else {
        // SAFETY: dev points at a caller-owned Linux struct pci_dev.
        unsafe { (*dev).dev.driver_data }
    }
}

extern "C" fn pci_name(dev: *const LinuxPciDev) -> *const c_char {
    if dev.is_null() { return core::ptr::null(); }
    // SAFETY: dev points at a caller-owned Linux struct pci_dev.
    unsafe { (*dev).dev.kobj.name }
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
    regions::claim_region(dev, idx, res)
}

extern "C" fn pci_release_region(dev: *mut LinuxPciDev, bar: i32) {
    if dev.is_null() { return; }
    if let Some(idx) = valid_bar(bar) { regions::release_region(dev, idx); }
}

extern "C" fn pci_request_regions(dev: *mut LinuxPciDev, name: *const c_char) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    let mut claimed = [INVALID_RESOURCE; PCI_STD_NUM_BARS];
    let mut n = 0usize;
    for bar in 0..PCI_STD_NUM_BARS {
        if pci_resource_len(dev, bar as i32) == 0 { continue; }
        let rc = pci_request_region(dev, bar as i32, name);
        if rc != LINUX_OK {
            for old in claimed.iter().take(n) { regions::release_region(dev, *old); }
            return rc;
        }
        claimed[n] = bar;
        n += 1;
    }
    LINUX_OK
}

extern "C" fn pci_release_regions(dev: *mut LinuxPciDev) {
    if dev.is_null() { return; }
    for bar in 0..PCI_STD_NUM_BARS { regions::release_region(dev, bar); }
}

extern "C" fn pcim_request_all_regions(dev: *mut LinuxPciDev, name: *const c_char) -> i32 { pci_request_regions(dev, name) }

extern "C" fn pcim_release_all_regions(dev: *mut LinuxPciDev) { pci_release_regions(dev); }

extern "C" fn pci_iomap(dev: *mut LinuxPciDev, bar: i32, maxlen: usize) -> *mut c_void {
    let res = match resource(dev, bar) { Some(v) => v, None => return null_mut() };
    let len = bounded_resource_len(res, maxlen);
    if len == 0 { return null_mut(); }
    super::maps::iomap_resource(res, len).unwrap_or(null_mut())
}

extern "C" fn pcim_iomap(dev: *mut LinuxPciDev, bar: i32, maxlen: usize) -> *mut c_void {
    pcim_map(dev, bar, maxlen, false)
}

extern "C" fn pcim_iomap_region(dev: *mut LinuxPciDev, bar: i32, name: *const c_char) -> *mut c_void {
    if dev.is_null() { return null_mut(); }
    let idx = match valid_bar(bar) { Some(v) => v, None => return null_mut() };
    if pci_request_region(dev, bar, name) != LINUX_OK { return null_mut(); }
    let ptr = pcim_map(dev, bar, 0, true);
    if ptr.is_null() { regions::release_region(dev, idx); }
    ptr
}

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

fn pcim_map(dev: *mut LinuxPciDev, bar: i32, maxlen: usize, release_region: bool) -> *mut c_void {
    if dev.is_null() { return null_mut(); }
    let res = match resource(dev, bar) { Some(v) => v, None => return null_mut() };
    let len = bounded_resource_len(res, maxlen);
    if len == 0 { return null_mut(); }
    let ptr = match super::maps::iomap_managed(dev, bar, res, len, release_region) { Some(v) => v, None => return null_mut() };
    // SAFETY: LinuxPciDev embeds LinuxDevice as its first repr(C) field.
    let base = unsafe { core::ptr::addr_of_mut!((*dev).dev) };
    if devres::add_action_or_reset(base, Some(pcim_release), dev.cast()) != LINUX_OK { return null_mut(); }
    ptr
}

unsafe extern "C" fn pcim_release(data: *mut c_void) {
    super::maps::release_managed_for(data.cast());
}

extern "C" fn pci_enable_msi(dev: *mut LinuxPciDev) -> i32 {
    match pci_alloc_irq_vectors(dev, 1, 1, PCI_IRQ_MSI) {
        1 => LINUX_OK,
        err => err,
    }
}

extern "C" fn pci_disable_msi(dev: *mut LinuxPciDev) {
    if dev.is_null() { return; }
    let flags = super::registry::irq_vectors(dev).map(|(_, _, flags)| flags).unwrap_or(0);
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
    let Some((base, count, _)) = super::registry::irq_vectors(dev) else { return -LINUX_EINVAL; };
    if count <= 0 || nr >= count as u32 { return -LINUX_EINVAL; }
    base.wrapping_add(nr) as i32
}

const PCI_COMMAND_STATUS_OFF: u8 = 0x04;
const PCI_COMMAND_MASK: u32 = 0x0000_ffff;
const PCI_STATUS_MASK: u32 = 0xffff_0000;
#[cfg(test)]
const PCI_DEVFN_DEV_SHIFT: u8 = 3;
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

pub(super) fn resource(dev: *const LinuxPciDev, bar: i32) -> Option<LinuxResource> {
    let idx = valid_bar(bar)?;
    if dev.is_null() { return None; }
    // SAFETY: dev points at a caller-owned Linux struct pci_dev.
    Some(unsafe { (*dev).resource[idx] })
}

pub(super) fn valid_bar(bar: i32) -> Option<usize> {
    if bar < 0 || bar as usize >= PCI_STD_NUM_BARS { None } else { Some(bar as usize) }
}

pub(super) fn resource_len(r: LinuxResource) -> u64 {
    if r.start == 0 && r.end == 0 { 0 }
    else if r.end < r.start { 0 }
    else { r.end.saturating_sub(r.start).saturating_add(1) }
}

fn bounded_resource_len(r: LinuxResource, maxlen: usize) -> u64 {
    let len = resource_len(r);
    if maxlen == 0 { len } else { len.min(maxlen as u64) }
}

#[cfg(test)]
mod tests;
