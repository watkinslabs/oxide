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
    let name = copy_driver_name(driver_name_ptr(driver));
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
    if insert_binding(driver as usize, model, dev_ptr as usize, id as usize).is_err() {
        return Err(drv::Error::Busy);
    }
    let rc = unsafe {
        // SAFETY: driver/id/dev_ptr are live Linux PCI ABI objects for this probe call.
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
    unsafe {
        // SAFETY: binding table owns dev until this remove path drops the Box.
        if let Some(remove) = (*(driver as *mut LinuxPciDriver)).remove { remove(dev); }
        (*dev).dev.driver = null_mut();
        (*dev).driver_data = null_mut();
        drop(Box::from_raw(dev));
    }
}

fn make_pci_dev(driver: *mut LinuxPciDriver, model: &Device) -> LinuxPciDev {
    let bdf = pci::parse_bdf_addr(&model.addr).unwrap_or(Bdf { bus: 0, device: 0, function: 0 });
    let mut dev: LinuxPciDev = unsafe {
        // SAFETY: repr(C) PCI device state is initialized immediately below before publication.
        MaybeUninit::zeroed().assume_init()
    };
    dev.dev = LinuxDevice {
        dma_mask: null_mut(),
        coherent_dma_mask: u64::MAX,
        driver_data: null_mut(),
        parent: null_mut(),
        bus: null_mut(),
        class: null_mut(),
        driver: unsafe {
            // SAFETY: driver is validated by register/probe path.
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
    let mut cur = unsafe {
        // SAFETY: driver is validated by register/probe path.
        (*driver).id_table
    };
    if cur.is_null() { return None; }
    for _ in 0..MAX_PCI_ID_TABLE {
        let id = unsafe {
            // SAFETY: bounded walk over Linux sentinel-terminated PCI ID table.
            &*cur
        };
        if id_is_sentinel(id) { return None; }
        if id_matches(id, model) { return Some(cur); }
        cur = unsafe {
            // SAFETY: bounded walk advances within the caller-provided ID table.
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
        let rec = g.swap_remove(pos);
        unsafe {
            // SAFETY: binding table owns dev when probe fails before publication.
            drop(Box::from_raw(rec.dev as *mut LinuxPciDev));
        }
    }
}

fn remove_binding_by_model(model: &Device, driver: usize) -> Option<BindingRecord> {
    let mut g = BINDINGS.lock();
    let pos = g.iter().position(|r| r.driver == driver && core::ptr::eq(&*r.model, model))?;
    Some(g.swap_remove(pos))
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
    unsafe {
        // SAFETY: driver is a caller-owned Linux struct pci_driver.
        if !(*driver).name.is_null() { (*driver).name } else { (*driver).driver.name }
    }
}

fn copy_driver_name(ptr: *const c_char) -> String {
    let mut s = String::new();
    let mut i = 0usize;
    while i < PCI_CSTR_MAX {
        let b = unsafe {
            // SAFETY: ptr is a Linux C string; scan is bounded.
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
    unsafe {
        // SAFETY: test reads the ID entry pointer recorded with the live binding.
        Some((*(rec.id as *const LinuxPciDeviceId)).driver_data)
    }
}
