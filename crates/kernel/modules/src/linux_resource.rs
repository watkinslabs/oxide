// Module manifest: Linux resource ABI layout, root resources, claim ownership, and managed request exports.

use crate::linux_device::devres;
use crate::linux_device::types::LinuxDevice;
use core::cell::UnsafeCell;
use core::ffi::{c_char, c_void};
use sync::{Modules as ModulesLockClass, Spinlock};

const MAX_RESOURCE_CLAIMS: usize = 64;
const IORESOURCE_IO: u64 = 0x0000_0100;
const IORESOURCE_MEM: u64 = 0x0000_0200;
const IORESOURCE_BUSY: u64 = 0x8000_0000;
const LINUX_OK: i32 = 0;

#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct LinuxResource {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) name: *const c_char,
    pub(crate) flags: u64,
    pub(crate) desc: u64,
    pub(crate) parent: *mut LinuxResource,
    pub(crate) sibling: *mut LinuxResource,
    pub(crate) child: *mut LinuxResource,
}

#[repr(transparent)]
struct ResourceRoot(UnsafeCell<LinuxResource>);

// SAFETY: ResourceRoot is only exposed to C callers as a resource pointer; all Oxide
// claim bookkeeping is serialized by CLAIMS and no Rust reference to its contents escapes.
unsafe impl Sync for ResourceRoot {}

static IOPORT_RESOURCE: ResourceRoot = ResourceRoot(UnsafeCell::new(LinuxResource {
    start: 0, end: u16::MAX as u64, name: c"PCI IO".as_ptr(), flags: IORESOURCE_IO,
    desc: 0, parent: core::ptr::null_mut(), sibling: core::ptr::null_mut(), child: core::ptr::null_mut(),
}));
static IOMEM_RESOURCE: ResourceRoot = ResourceRoot(UnsafeCell::new(LinuxResource {
    start: 0, end: u64::MAX, name: c"PCI mem".as_ptr(), flags: IORESOURCE_MEM,
    desc: 0, parent: core::ptr::null_mut(), sibling: core::ptr::null_mut(), child: core::ptr::null_mut(),
}));

#[derive(Copy, Clone)]
struct ResourceClaim {
    owner: usize,
    parent: usize,
    resource: ResourceRecord,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ResourceRecord {
    start: u64,
    end: u64,
    name: usize,
    flags: u64,
    desc: u64,
    parent: usize,
    sibling: usize,
    child: usize,
}

static CLAIMS: Spinlock<[Option<ResourceClaim>; MAX_RESOURCE_CLAIMS], ModulesLockClass> =
    Spinlock::new([None; MAX_RESOURCE_CLAIMS]);

/// Register Linux resource-tree KPI symbols. # C: O(1)
pub fn export_symbols() {
    use crate::symtab::export;
    export("ioport_resource", ioport_resource() as usize, false);
    export("iomem_resource", iomem_resource() as usize, false);
    for (name, addr) in [
        ("__request_region", __request_region as *const () as usize),
        ("__release_region", __release_region as *const () as usize),
        ("__devm_request_region", __devm_request_region as *const () as usize),
        ("__devm_release_region", __devm_release_region as *const () as usize),
    ] { export(name, addr, false); }
}

/// Return the canonical I/O-port root resource. # C: O(1)
pub(crate) fn ioport_resource() -> *mut LinuxResource { IOPORT_RESOURCE.0.get() }

/// Return the canonical I/O-memory root resource. # C: O(1)
pub(crate) fn iomem_resource() -> *mut LinuxResource { IOMEM_RESOURCE.0.get() }

/// Claim a resource range under its authoritative parent. # C: O(N_claims)
pub(crate) fn claim(owner: usize, parent: *mut LinuxResource, start: u64, end: u64, name: *const c_char) -> Option<*mut LinuxResource> {
    if parent.is_null() || end < start || !contains(parent, start, end) { return None; }
    let mut g = CLAIMS.lock();
    if g.iter().flatten().any(|r| r.parent == parent as usize && overlaps(r.resource.start, r.resource.end, start, end)) { return None; }
    let slot = g.iter_mut().find(|r| r.is_none())?;
    // SAFETY: claim serializes child-list updates and contains validated parent bounds.
    let sibling = unsafe { (*parent).child };
    let resource = ResourceRecord {
        start, end, name: name as usize, flags: parent_flags(parent) | IORESOURCE_BUSY, desc: 0,
        parent: parent as usize, sibling: sibling as usize, child: 0,
    };
    *slot = Some(ResourceClaim { owner, parent: parent as usize, resource });
    match slot {
        Some(rec) => {
            let ptr = core::ptr::addr_of_mut!(rec.resource).cast();
            // SAFETY: ptr is stable inside CLAIMS and the resource lock covers parent linkage.
            unsafe { (*parent).child = ptr; }
            Some(ptr)
        }
        None => None,
    }
}

/// Release a resource claim owned by an exact caller identity. # C: O(N_claims)
pub(crate) fn release(owner: usize, parent: *mut LinuxResource, start: u64, end: u64) {
    let mut g = CLAIMS.lock();
    let Some(idx) = g.iter().position(|r| r.is_some_and(|v| v.owner == owner && v.parent == parent as usize && v.resource.start == start && v.resource.end == end)) else { return; };
    let (ptr, sibling) = match &mut g[idx] {
        Some(rec) => (core::ptr::addr_of_mut!(rec.resource).cast::<LinuxResource>(), rec.resource.sibling),
        None => return,
    };
    // SAFETY: CLAIMS serializes the child list and ptr identifies this still-live claim.
    unsafe {
        if (*parent).child == ptr { (*parent).child = sibling as *mut LinuxResource; }
        else {
            let mut prev = (*parent).child;
            while !prev.is_null() && (*prev).sibling != ptr { prev = (*prev).sibling; }
            if !prev.is_null() { (*prev).sibling = sibling as *mut LinuxResource; }
        }
    }
    g[idx] = None;
}

fn claim_by_pointer(ptr: *mut LinuxResource) -> Option<ResourceClaim> {
    let g = CLAIMS.lock();
    g.iter().flatten().find(|r| core::ptr::eq(core::ptr::addr_of!(r.resource).cast::<LinuxResource>(), ptr)).copied()
}

unsafe extern "C" fn devm_release_action(data: *mut c_void) {
    let Some(rec) = claim_by_pointer(data.cast()) else { return; };
    release(rec.owner, rec.parent as *mut LinuxResource, rec.resource.start, rec.resource.end);
}

extern "C" fn __request_region(parent: *mut LinuxResource, start: u64, n: u64, name: *const c_char, _flags: i32) -> *mut LinuxResource {
    let Some(end) = end_for(start, n) else { return core::ptr::null_mut(); };
    claim(0, parent, start, end, name).unwrap_or(core::ptr::null_mut())
}

extern "C" fn __release_region(parent: *mut LinuxResource, start: u64, n: u64) {
    let Some(end) = end_for(start, n) else { return; };
    release(0, parent, start, end);
}

pub(crate) extern "C" fn __devm_request_region(dev: *mut LinuxDevice, parent: *mut LinuxResource, start: u64, n: u64, name: *const c_char) -> *mut LinuxResource {
    if dev.is_null() { return core::ptr::null_mut(); }
    let Some(end) = end_for(start, n) else { return core::ptr::null_mut(); };
    let Some(resource) = claim(dev as usize, parent, start, end, name) else { return core::ptr::null_mut(); };
    if devres::add_action_or_reset(dev, Some(devm_release_action), resource.cast()) != LINUX_OK { return core::ptr::null_mut(); }
    resource
}

extern "C" fn __devm_release_region(dev: *mut LinuxDevice, parent: *mut LinuxResource, start: u64, n: u64) {
    if dev.is_null() { return; }
    let Some(end) = end_for(start, n) else { return; };
    let ptr: Option<*mut LinuxResource> = {
        let g = CLAIMS.lock();
        g.iter().flatten().find(|r| r.owner == dev as usize && r.parent == parent as usize && r.resource.start == start && r.resource.end == end).map(|r| core::ptr::addr_of!(r.resource).cast_mut().cast())
    };
    if let Some(ptr) = ptr {
        devres::remove_action(dev, Some(devm_release_action), ptr.cast());
        release(dev as usize, parent, start, end);
    }
}

fn end_for(start: u64, n: u64) -> Option<u64> { n.checked_sub(1).and_then(|v| start.checked_add(v)) }

fn contains(parent: *mut LinuxResource, start: u64, end: u64) -> bool {
    // SAFETY: parent is either a canonical root or a caller-provided live resource descriptor.
    let parent = unsafe { &*parent };
    start >= parent.start && end <= parent.end
}

fn parent_flags(parent: *mut LinuxResource) -> u64 {
    // SAFETY: claim validated parent as a non-null resource descriptor before this read.
    unsafe { (*parent).flags & (IORESOURCE_IO | IORESOURCE_MEM) }
}

fn overlaps(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool { a_start <= b_end && b_start <= a_end }

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_START: u64 = 0x1000_0000;
    const TEST_SIZE: u64 = 0x1000;

    #[test]
    fn managed_claim_excludes_overlap_and_releases_with_device() {
        let _modules = crate::test_serial::claim();
        let mut first = LinuxDevice::new();
        let mut second = LinuxDevice::new();
        let first_claim = __devm_request_region(&mut first, iomem_resource(), TEST_START, TEST_SIZE, c"first".as_ptr());
        assert!(!first_claim.is_null());
        // SAFETY: first_claim is non-null and remains held by first's devres record here.
        assert_eq!(unsafe { (*first_claim).flags }, IORESOURCE_MEM | IORESOURCE_BUSY);
        // SAFETY: the root is live and its child list is updated while the claim is held.
        assert_eq!(unsafe { (*iomem_resource()).child }, first_claim);
        assert!(__devm_request_region(&mut second, iomem_resource(), TEST_START, TEST_SIZE, c"second".as_ptr()).is_null());
        devres::release_device(&mut first);
        // SAFETY: releasing the only claim unlinks it from the root child list.
        assert!((unsafe { (*iomem_resource()).child }).is_null());
        assert!(!__devm_request_region(&mut second, iomem_resource(), TEST_START, TEST_SIZE, c"second".as_ptr()).is_null());
        devres::release_device(&mut second);
    }

    #[test]
    fn export_symbols_registers_resource_surface() {
        let _modules = crate::test_serial::claim();
        export_symbols();
        for name in ["ioport_resource", "iomem_resource", "__request_region", "__release_region", "__devm_request_region", "__devm_release_region"] {
            assert!(crate::symtab::resolve(name, true).is_ok(), "{name}");
        }
    }
}
