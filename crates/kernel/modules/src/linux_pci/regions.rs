use super::core::{resource, resource_len};
use super::types::*;
use core::ffi::c_char;

const BAR_MASK_BITS: usize = core::mem::size_of::<i32>() * u8::BITS as usize;

/// Reserve a PCI BAR for one Linux KPI device. # C: O(N_claims)
pub(super) fn claim_region(dev: *mut LinuxPciDev, _bar: usize, res: LinuxResource) -> i32 {
    let parent = if res.flags & pci::IORESOURCE_IO != 0 { crate::linux_resource::ioport_resource() }
    else if res.flags & pci::IORESOURCE_MEM != 0 { crate::linux_resource::iomem_resource() }
    else { return -LINUX_EBUSY; };
    crate::linux_resource::claim(dev as usize, parent, res.start, res.end, res.name).map(|_| LINUX_OK).unwrap_or(-LINUX_EBUSY)
}

/// Release the BAR claim held by one Linux KPI device. # C: O(N_claims)
pub(super) fn release_region(dev: *mut LinuxPciDev, bar: usize) {
    let Some(res) = resource(dev, bar as i32) else { return; };
    let parent = if res.flags & pci::IORESOURCE_IO != 0 { crate::linux_resource::ioport_resource() }
    else if res.flags & pci::IORESOURCE_MEM != 0 { crate::linux_resource::iomem_resource() }
    else { return; };
    crate::linux_resource::release(dev as usize, parent, res.start, res.end);
}

/// Return the bitmask of standard BARs whose resource flags match `flags`. # C: O(BARs)
pub(super) extern "C" fn pci_select_bars(dev: *mut LinuxPciDev, flags: u64) -> i32 {
    if dev.is_null() { return 0; }
    let mut bars = 0i32;
    for bar in 0..PCI_STD_NUM_BARS.min(BAR_MASK_BITS) {
        if resource(dev, bar as i32).is_some_and(|res| res.flags & flags != 0) { bars |= 1 << bar; }
    }
    bars
}

/// Reserve every BAR selected by the caller's bitmask. # C: O(BARs * claims)
pub(super) extern "C" fn pci_request_selected_regions(dev: *mut LinuxPciDev, bars: i32, _name: *const c_char) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    for bar in 0..PCI_STD_NUM_BARS {
        if bars & (1 << bar) == 0 { continue; }
        let Some(res) = resource(dev, bar as i32) else { rollback(dev, bars, bar); return -LINUX_EBUSY; };
        if resource_len(res) == 0 || claim_region(dev, bar, res) != LINUX_OK { rollback(dev, bars, bar); return -LINUX_EBUSY; }
    }
    LINUX_OK
}

/// Release every BAR selected by the caller's bitmask. # C: O(BARs * claims)
pub(super) extern "C" fn pci_release_selected_regions(dev: *mut LinuxPciDev, bars: i32) {
    if dev.is_null() { return; }
    for bar in 0..PCI_STD_NUM_BARS {
        if bars & (1 << bar) != 0 { release_region(dev, bar); }
    }
}

fn rollback(dev: *mut LinuxPciDev, bars: i32, failed_bar: usize) {
    for bar in 0..failed_bar {
        if bars & (1 << bar) != 0 { release_region(dev, bar); }
    }
}
