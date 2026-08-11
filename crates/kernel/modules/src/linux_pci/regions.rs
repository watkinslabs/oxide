use super::core::{resource, resource_len};
use super::types::*;
use core::ffi::c_char;
use sync::{Modules as ModulesLockClass, Spinlock};

const MAX_REGION_CLAIMS: usize = 64;
const BAR_MASK_BITS: usize = core::mem::size_of::<i32>() * u8::BITS as usize;

#[derive(Copy, Clone)]
struct RegionClaim {
    dev: usize,
    bar: usize,
    start: u64,
    end: u64,
}

static REGIONS: Spinlock<[Option<RegionClaim>; MAX_REGION_CLAIMS], ModulesLockClass> =
    Spinlock::new([None; MAX_REGION_CLAIMS]);

/// Reserve a PCI BAR for one Linux KPI device. # C: O(N_claims)
pub(super) fn claim_region(dev: *mut LinuxPciDev, bar: usize, res: LinuxResource) -> i32 {
    let mut g = REGIONS.lock();
    if g.iter().flatten().any(|r| overlaps(r.start, r.end, res.start, res.end)) { return -LINUX_EBUSY; }
    if let Some(slot) = g.iter_mut().find(|r| r.is_none()) {
        *slot = Some(RegionClaim { dev: dev as usize, bar, start: res.start, end: res.end });
        LINUX_OK
    } else { -LINUX_ENOMEM }
}

/// Release the BAR claim held by one Linux KPI device. # C: O(N_claims)
pub(super) fn release_region(dev: *mut LinuxPciDev, bar: usize) {
    let mut g = REGIONS.lock();
    if let Some(slot) = g.iter_mut().find(|r| r.is_some_and(|v| v.dev == dev as usize && v.bar == bar)) { *slot = None; }
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

fn overlaps(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start <= b_end && b_start <= a_end
}
