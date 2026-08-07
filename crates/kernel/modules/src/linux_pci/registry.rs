extern crate alloc;

use super::types::*;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::linux_device::types::{LinuxDevice, LinuxKobject, DEVICE_NAME_LEN};
use core::ffi::c_char;
use core::mem::MaybeUninit;
use core::ptr::null_mut;
use drv::{Device, Driver};
use pci::Bdf;
use sync::{Modules as ModulesLockClass, Spinlock};

const MAX_PCI_DRIVERS: usize = 32;
const MAX_PCI_ID_TABLE: usize = 128;
const PCI_ANY_ID: u32 = u32::MAX;
const PCI_SLOT_SHIFT: u8 = 3;
const PCI_SLOT_MASK: u8 = 0x1f;
const PCI_FUNC_MASK: u8 = 0x07;
const PCI_CSTR_MAX: usize = 64;

struct PciModelDriver { slot: usize }

#[derive(Clone)]
struct DriverRecord {
    ptr: usize,
    name: &'static str,
    model: &'static PciModelDriver,
}

#[derive(Clone)]
struct BindingRecord {
    driver: usize,
    model: Arc<Device>,
    dev: usize,
    #[allow(dead_code)]
    id: usize,
}

static DRIVERS: Spinlock<Vec<DriverRecord>, ModulesLockClass> = Spinlock::new(Vec::new());
static BINDINGS: Spinlock<Vec<BindingRecord>, ModulesLockClass> = Spinlock::new(Vec::new());

impl Driver for PciModelDriver {
    fn bus(&self) -> &'static str { "pci" }
    fn name(&self) -> &'static str { driver_name(self.slot).unwrap_or("linux-pci") }
    fn matches(&self, dev: &Device) -> bool {
        let Some(driver) = driver_ptr(self.slot) else { return false; };
        match_id(driver as *mut LinuxPciDriver, dev).is_some()
    }
    fn probe(&self, dev: &Arc<Device>) -> drv::KResult<()> {
        bind_model_device(self.slot, dev)
    }
    fn remove(&self, dev: &Device) {
        unbind_model_device(self.slot, dev);
    }
}

pub(super) fn register_driver(driver: *mut LinuxPciDriver) -> i32 {
    if driver.is_null() { return -LINUX_EINVAL; }
    if driver_name_ptr(driver).is_null() { return -LINUX_EINVAL; }
    // SAFETY: the line above returned early unless driver_name_ptr(driver) is non-NULL, and that
    // pointer is the module's own static name string, so it is NUL-terminated and readable.
    let name = unsafe { copy_driver_name(driver_name_ptr(driver)) };
    let mut g = DRIVERS.lock();
    if g.iter().any(|r| r.ptr == driver as usize) { return -LINUX_EBUSY; }
    if g.iter().any(|r| r.name == name) { return -LINUX_EBUSY; }
    if g.len() >= MAX_PCI_DRIVERS { return -LINUX_ENOMEM; }
    let slot = first_free_slot(&g);
    let name = Box::leak(name.into_boxed_str());
    let model = Box::leak(Box::new(PciModelDriver { slot }));
    g.push(DriverRecord { ptr: driver as usize, name, model });
    drop(g);
    drv::register_driver(model);
    LINUX_OK
}

pub(super) fn unregister_driver(driver: *mut LinuxPciDriver) {
    if driver.is_null() { return; }
    let model = {
        let g = DRIVERS.lock();
        g.iter().find(|r| r.ptr == driver as usize).map(|r| r.model)
    };
    if let Some(model) = model {
        let _ = drv::unregister_driver(model);
    }
    DRIVERS.lock().retain(|r| r.ptr != driver as usize);
    BINDINGS.lock().retain(|r| r.driver != driver as usize);
}

fn bind_model_device(slot: usize, model: &Arc<Device>) -> drv::KResult<()> {
    let driver = driver_ptr(slot).ok_or(drv::Error::NotFound)? as *mut LinuxPciDriver;
    let id = match_id(driver, model).ok_or(drv::Error::NoMatch)?;
    let mut dev = Box::new(make_pci_dev(driver, model));
    let dev_ptr = dev.as_mut() as *mut LinuxPciDev;
    dev.dev.dma_mask = &mut dev.dma_mask;
    if insert_binding(driver as usize, model, dev_ptr as usize, id as usize).is_err() {
        return Err(drv::Error::Busy);
    }
    // SAFETY: driver came from driver_ptr(slot), i.e. a DriverRecord register_driver installed and
    // unregister_driver has not removed, so the struct pci_driver is live; id points into that
    // driver's own id_table (match_id returned it); dev_ptr is the Box allocated above, kept alive
    // for the whole call and only leaked into the binding table once probe succeeds.
    let rc = unsafe {
        match (*driver).probe { Some(probe) => probe(dev_ptr, id), None => LINUX_OK }
    };
    if rc == LINUX_OK {
        let _ = Box::into_raw(dev);
        Ok(())
    } else {
        remove_binding(model, driver as usize);
        Err(drv::Error::ProbeFailed)
    }
}

fn unbind_model_device(slot: usize, model: &Device) {
    let Some(driver) = driver_ptr(slot) else { return; };
    let Some(rec) = remove_binding_by_model(model, driver) else { return; };
    let dev = rec.dev as *mut LinuxPciDev;
    // SAFETY: remove_binding_by_model just took the BindingRecord out of BINDINGS under its lock,
    // so this path uniquely owns rec.dev — the Box::into_raw'd LinuxPciDev from bind_model_device
    // — and no concurrent unbind can also free it; driver is the still-registered pci_driver whose
    // slot the record was filed under, so its remove hook and the Box layout both match.
    unsafe {
        if let Some(remove) = (*(driver as *mut LinuxPciDriver)).remove { remove(dev); }
        (*dev).dev.driver = null_mut();
        (*dev).driver_data = null_mut();
        drop(Box::from_raw(dev));
    }
}

fn make_pci_dev(driver: *mut LinuxPciDriver, model: &Device) -> LinuxPciDev {
    let bdf = pci::parse_bdf_addr(&model.addr).unwrap_or(Bdf { bus: 0, device: 0, function: 0 });
    // SAFETY: every field of LinuxPciDev is valid all-zero — raw pointers (null), integers, bools
    // (false), c_char/u32 arrays, and the Option<extern fn> hooks in its nested LinuxDevice /
    // LinuxKobject / LinuxDevPmInfo (None) — so the zeroed pattern is an inhabited value, not
    // uninitialised memory; the fields that need non-zero defaults are assigned below.
    let mut dev: LinuxPciDev = unsafe {
        MaybeUninit::zeroed().assume_init()
    };
    dev.dev = LinuxDevice {
        dma_mask: null_mut(),
        coherent_dma_mask: model.coherent_dma_mask(),
        driver_data: null_mut(),
        parent: null_mut(),
        bus: null_mut(),
        class: null_mut(),
        // SAFETY: driver is the pci_driver from driver_ptr(slot) (register_driver installed it and
        // unregister_driver has not run), so its embedded struct device_driver is live for at
        // least as long as this pci_dev; the borrow is immediately coerced to the *mut stored in
        // dev.driver and never kept as a reference.
        driver: unsafe {
            &mut (*driver).driver
        },
        init_name: core::ptr::null(),
        name: [0; DEVICE_NAME_LEN],
        kobj: LinuxKobject::new(),
        release: None,
        of_node: null_mut(),
        acpi_node: null_mut(),
        power: crate::linux_pm::types::LinuxDevPmInfo::new(),
    };
    dev.dma_mask = model.dma_mask();
    dev.vendor = model.vendor_id;
    dev.device = model.device_id;
    dev.subsystem_vendor = 0;
    dev.subsystem_device = 0;
    dev.class = model.class;
    dev.bus = bdf.bus;
    dev.devfn = ((bdf.device & PCI_SLOT_MASK) << PCI_SLOT_SHIFT) | (bdf.function & PCI_FUNC_MASK);
    dev.irq = 0;
    for r in model.resources.iter() {
        let idx = r.bar as usize;
        if idx < PCI_STD_NUM_BARS {
            dev.resource[idx] = LinuxResource { start: r.start, end: r.end, name: core::ptr::null(), flags: r.flags };
        }
    }
    dev.current_state = PCI_D0;
    dev.driver_data = null_mut();
    fill_device_name(&mut dev, &model.addr);
    dev
}

fn match_id(driver: *mut LinuxPciDriver, model: &Device) -> Option<*const LinuxPciDeviceId> {
    if driver.is_null() || model.bus != "pci" { return None; }
    // SAFETY: driver was checked non-null above and every caller obtains it from driver_ptr, i.e.
    // a DriverRecord still present in DRIVERS, so the struct pci_driver is live and its id_table
    // field is readable.
    let mut cur = unsafe {
        (*driver).id_table
    };
    if cur.is_null() { return None; }
    for _ in 0..MAX_PCI_ID_TABLE {
        // SAFETY: pci_driver's KPI contract is that id_table is an array terminated by an
        // all-zero sentinel; cur starts at that array and only advances past entries
        // id_is_sentinel rejected, so it addresses a real entry here.
        let id = unsafe {
            &*cur
        };
        if id_is_sentinel(id) { return None; }
        if id_matches(id, model) { return Some(cur); }
        // SAFETY: the entry at cur was just proven non-sentinel, so the table has at least one
        // more element; the MAX_PCI_ID_TABLE loop bound also stops a missing sentinel from
        // walking off the end indefinitely.
        cur = unsafe {
            cur.add(1)
        };
    }
    None
}

fn id_matches(id: &LinuxPciDeviceId, model: &Device) -> bool {
    id_field_matches(id.vendor, model.vendor_id as u32)
        && id_field_matches(id.device, model.device_id as u32)
        && id_field_matches(id.subvendor, PCI_ANY_ID)
        && id_field_matches(id.subdevice, PCI_ANY_ID)
        && ((model.class & id.class_mask) == (id.class & id.class_mask))
}

fn id_field_matches(id: u32, value: u32) -> bool {
    id == PCI_ANY_ID || id == value
}

fn id_is_sentinel(id: &LinuxPciDeviceId) -> bool {
    id.vendor == 0 && id.device == 0 && id.subvendor == 0 && id.subdevice == 0
        && id.class == 0 && id.class_mask == 0 && id.driver_data == 0
}

fn insert_binding(driver: usize, model: &Arc<Device>, dev: usize, id: usize) -> Result<(), ()> {
    let mut g = BINDINGS.lock();
    if g.iter().any(|r| r.driver == driver && Arc::ptr_eq(&r.model, model)) { return Err(()); }
    g.push(BindingRecord { driver, model: Arc::clone(model), dev, id });
    Ok(())
}

fn remove_binding(model: &Arc<Device>, driver: usize) {
    let mut g = BINDINGS.lock();
    if let Some(pos) = g.iter().position(|r| r.driver == driver && Arc::ptr_eq(&r.model, model)) {
        // Drop the record only. Ownership of rec.dev is still with bind_model_device's local Box
        // on the failed-probe path (Box::into_raw runs only when probe succeeds), so freeing it
        // here would double-free it when that Box goes out of scope.
        let _ = g.swap_remove(pos);
    }
}

fn remove_binding_by_model(model: &Device, driver: usize) -> Option<BindingRecord> {
    let mut g = BINDINGS.lock();
    let pos = g.iter().position(|r| r.driver == driver && core::ptr::eq(&*r.model, model))?;
    Some(g.swap_remove(pos))
}

/// Reflect a successful module DMA-mask update into the canonical model.
/// # C: O(N_bindings)
pub(crate) fn sync_dma_masks(dev: *mut crate::linux_dma::LinuxDevice, streaming: Option<u64>, coherent: Option<u64>) {
    let model = BINDINGS.lock().iter()
        .find(|rec| rec.dev == dev as usize)
        .map(|rec| Arc::clone(&rec.model));
    let Some(model) = model else { return; };
    if let Some(mask) = streaming { model.set_dma_mask(mask); }
    if let Some(mask) = coherent { model.set_coherent_dma_mask(mask); }
}

fn driver_ptr(slot: usize) -> Option<usize> {
    DRIVERS.lock().iter().find(|r| r.model.slot == slot).map(|r| r.ptr)
}

fn driver_name(slot: usize) -> Option<&'static str> {
    DRIVERS.lock().iter().find(|r| r.model.slot == slot).map(|r| r.name)
}

fn first_free_slot(g: &[DriverRecord]) -> usize {
    let mut slot = 0usize;
    while g.iter().any(|r| r.model.slot == slot) { slot += 1; }
    slot
}

fn driver_name_ptr(driver: *mut LinuxPciDriver) -> *const c_char {
    if driver.is_null() { return core::ptr::null(); }
    // SAFETY: pci_register_driver's KPI contract is that the module keeps its struct pci_driver
    // alive for the whole registration; driver was checked non-null on the line above, and only
    // the name / driver.name pointer fields are read here, never dereferenced.
    unsafe {
        if !(*driver).name.is_null() { (*driver).name } else { (*driver).driver.name }
    }
}

// Precondition: ptr is non-NULL and points at a C string that either terminates within
// PCI_CSTR_MAX bytes or is readable for at least PCI_CSTR_MAX bytes (Linux driver names are
// static string literals, so both hold).
unsafe fn copy_driver_name(ptr: *const c_char) -> String {
    let mut s = String::new();
    let mut i = 0usize;
    while i < PCI_CSTR_MAX {
        // SAFETY: the caller's precondition makes ptr readable up to the NUL or PCI_CSTR_MAX
        // bytes, and the loop condition keeps i below that bound.
        let b = unsafe {
            *ptr.add(i) as u8
        };
        if b == 0 { break; }
        s.push(if b.is_ascii() { b as char } else { '?' });
        i += 1;
    }
    if s.is_empty() { s.push_str("linux-pci"); }
    s
}

fn fill_device_name(dev: &mut LinuxPciDev, name: &str) {
    fill_cstr(&mut dev.name, name);
    fill_cstr(&mut dev.dev.name, name);
}

fn fill_cstr<const N: usize>(dst: &mut [c_char; N], src: &str) {
    if N == 0 { return; }
    let bytes = src.as_bytes();
    let len = core::cmp::min(bytes.len(), N - 1);
    for i in 0..len {
        dst[i] = bytes[i] as c_char;
    }
    dst[len] = 0;
}

#[cfg(test)]
pub(super) fn binding_count() -> usize { BINDINGS.lock().len() }

#[cfg(test)]
pub(super) fn bound_id_driver_data(model: &Arc<Device>) -> Option<usize> {
    let g = BINDINGS.lock();
    let rec = g.iter().find(|r| Arc::ptr_eq(&r.model, model))?;
    // SAFETY: rec.id is the id_table entry match_id returned when this still-present binding was
    // made, so it points into the test driver's 'static id_table array, which outlives the probe.
    unsafe {
        Some((*(rec.id as *const LinuxPciDeviceId)).driver_data)
    }
}
