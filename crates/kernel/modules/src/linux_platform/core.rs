extern crate alloc;

use super::types::*;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::{c_char, c_void};
use core::ptr::{null, null_mut};
use sync::{Modules as ModulesLockClass, Spinlock};

const LINUX_ENXIO: i32 = 6;
const RESOURCE_EMPTY: u64 = 0;

static DRIVERS: Spinlock<Vec<usize>, ModulesLockClass> = Spinlock::new(Vec::new());
static DEVICES: Spinlock<Vec<usize>, ModulesLockClass> = Spinlock::new(Vec::new());
static ALLOCATED: Spinlock<Vec<usize>, ModulesLockClass> = Spinlock::new(Vec::new());

/// Register Linux platform/ACPI/OF KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("__platform_driver_register",            __platform_driver_register            as *const () as usize),
        ("platform_driver_unregister",            platform_driver_unregister            as *const () as usize),
        ("platform_device_alloc",                 platform_device_alloc                 as *const () as usize),
        ("platform_device_add",                   platform_device_add                   as *const () as usize),
        ("platform_device_del",                   platform_device_del                   as *const () as usize),
        ("platform_device_put",                   platform_device_put                   as *const () as usize),
        ("platform_device_register",              platform_device_register              as *const () as usize),
        ("platform_device_unregister",            platform_device_unregister            as *const () as usize),
        ("platform_get_resource",                 platform_get_resource                 as *const () as usize),
        ("platform_get_resource_byname",          platform_get_resource_byname          as *const () as usize),
        ("platform_get_irq",                      platform_get_irq                      as *const () as usize),
        ("platform_get_irq_optional",             platform_get_irq_optional             as *const () as usize),
        ("devm_platform_ioremap_resource",        devm_platform_ioremap_resource        as *const () as usize),
        ("devm_platform_get_and_ioremap_resource", devm_platform_get_and_ioremap_resource as *const () as usize),
        ("acpi_match_device",                     acpi_match_device                     as *const () as usize),
        ("acpi_dev_get_first_match_dev",          acpi_dev_get_first_match_dev          as *const () as usize),
        ("acpi_dev_put",                          acpi_dev_put                          as *const () as usize),
        ("of_match_device",                       of_match_device                       as *const () as usize),
        ("of_property_read_u32",                  of_property_read_u32                  as *const () as usize),
        ("of_property_read_bool",                 of_property_read_bool                 as *const () as usize),
    ] { export(name, addr, false); }
}

pub(crate) extern "C" fn device_match_data(dev: *mut crate::linux_device::types::LinuxDevice) -> *const c_void {
    if dev.is_null() { return null(); }
    // SAFETY: dev is a caller-owned Linux struct device.
    unsafe {
        let drv = (*dev).driver;
        if drv.is_null() { return null(); }
        let of_id = of_match_device((*drv).of_match_table as *const OfDeviceId, dev as *const _);
        if !of_id.is_null() { return (*of_id).data; }
        let acpi_id = acpi_match_device((*drv).acpi_match_table as *const AcpiDeviceId, dev as *const _);
        if !acpi_id.is_null() { return (*acpi_id).driver_data as *const c_void; }
    }
    null()
}

extern "C" fn __platform_driver_register(driver: *mut PlatformDriver, owner: *mut c_void) -> i32 {
    if driver.is_null() { return -LINUX_EINVAL; }
    // SAFETY: driver points at a caller-owned Linux struct platform_driver.
    unsafe { (*driver).driver.owner = owner; }
    {
        let mut g = DRIVERS.lock();
        if g.iter().any(|p| *p == driver as usize) { return -LINUX_EBUSY; }
        g.push(driver as usize);
    }
    let devices = DEVICES.lock().clone();
    for p in devices { bind_driver_to_device(driver, p as *mut PlatformDevice); }
    LINUX_OK
}

extern "C" fn platform_driver_unregister(driver: *mut PlatformDriver) {
    if driver.is_null() { return; }
    DRIVERS.lock().retain(|p| *p != driver as usize);
    let devices = DEVICES.lock().clone();
    for p in devices {
        let dev = p as *mut PlatformDevice;
        // SAFETY: dev is stored only after platform_device_add validation.
        if unsafe { (*dev).driver == driver } { unbind_device(dev); }
    }
}

extern "C" fn platform_device_alloc(name: *const c_char, id: i32) -> *mut PlatformDevice {
    if name.is_null() { return null_mut(); }
    let p = Box::into_raw(Box::new(PlatformDevice {
        name,
        id,
        dev: crate::linux_device::types::LinuxDevice {
            dma_mask: null_mut(),
            coherent_dma_mask: u64::MAX,
            driver_data: null_mut(),
            parent: null_mut(),
            bus: null_mut(),
            class: null_mut(),
            driver: null_mut(),
            init_name: name,
            name: [0; crate::linux_device::types::DEVICE_NAME_LEN],
            kobj: crate::linux_device::types::LinuxKobject::new(),
            release: None,
            of_node: null_mut(),
            acpi_node: null_mut(),
            power: crate::linux_pm::types::LinuxDevPmInfo::new(),
        },
        num_resources: 0,
        resource: null_mut(),
        driver_data: null_mut(),
        driver: null_mut(),
        id_entry: null(),
        registered: 0,
    }));
    ALLOCATED.lock().push(p as usize);
    p
}

extern "C" fn platform_device_add(dev: *mut PlatformDevice) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    {
        let mut g = DEVICES.lock();
        if g.iter().any(|p| *p == dev as usize) { return -LINUX_EBUSY; }
        g.push(dev as usize);
    }
    // SAFETY: dev points at a caller-owned Linux struct platform_device.
    unsafe {
        (*dev).registered = PLATFORM_DEVICE_REGISTERED;
        (*dev).dev.init_name = (*dev).name;
    }
    bind_device(dev);
    LINUX_OK
}

extern "C" fn platform_device_del(dev: *mut PlatformDevice) {
    if dev.is_null() { return; }
    unbind_device(dev);
    DEVICES.lock().retain(|p| *p != dev as usize);
    // SAFETY: dev points at a caller-owned Linux struct platform_device.
    unsafe { (*dev).registered = 0; }
}

extern "C" fn platform_device_put(dev: *mut PlatformDevice) {
    if dev.is_null() { return; }
    let owned = {
        let mut g = ALLOCATED.lock();
        match g.iter().position(|p| *p == dev as usize) {
            Some(i) => { g.swap_remove(i); true },
            None => false,
        }
    };
    if owned {
        // SAFETY: ALLOCATED tracks only Box allocations from platform_device_alloc.
        unsafe { drop(Box::from_raw(dev)); }
    }
}

extern "C" fn platform_device_register(dev: *mut PlatformDevice) -> i32 {
    platform_device_add(dev)
}

extern "C" fn platform_device_unregister(dev: *mut PlatformDevice) {
    platform_device_del(dev);
    platform_device_put(dev);
}

extern "C" fn platform_get_resource(dev: *mut PlatformDevice, ty: u32, num: u32) -> *mut LinuxResource {
    if dev.is_null() { return null_mut(); }
    let mut seen = 0u32;
    // SAFETY: dev resource array has num_resources entries by Linux ABI contract.
    unsafe {
        for idx in 0..(*dev).num_resources as usize {
            let res = (*dev).resource.add(idx);
            if ((*res).flags & IORESOURCE_TYPE_BITS) == ty as u64 {
                if seen == num { return res; }
                seen = seen.saturating_add(1);
            }
        }
    }
    null_mut()
}

extern "C" fn platform_get_resource_byname(dev: *mut PlatformDevice, ty: u32, name: *const c_char) -> *mut LinuxResource {
    if name.is_null() { return null_mut(); }
    if dev.is_null() { return null_mut(); }
    // SAFETY: dev resource array has num_resources entries by Linux ABI contract.
    unsafe {
        for idx in 0..(*dev).num_resources as usize {
            let res = (*dev).resource.add(idx);
            if ((*res).flags & IORESOURCE_TYPE_BITS) == ty as u64 && cstr_eq((*res).name, name) { return res; }
        }
    }
    null_mut()
}

extern "C" fn platform_get_irq(dev: *mut PlatformDevice, num: u32) -> i32 {
    platform_get_irq_optional(dev, num)
}

extern "C" fn platform_get_irq_optional(dev: *mut PlatformDevice, num: u32) -> i32 {
    let res = platform_get_resource(dev, IORESOURCE_IRQ as u32, num);
    if res.is_null() { return -LINUX_ENXIO; }
    // SAFETY: res is returned from the device resource array.
    unsafe {
        if (*res).start > i32::MAX as u64 { -LINUX_EINVAL } else { (*res).start as i32 }
    }
}

extern "C" fn devm_platform_ioremap_resource(dev: *mut PlatformDevice, index: u32) -> *mut c_void {
    devm_platform_get_and_ioremap_resource(dev, index, null_mut())
}

extern "C" fn devm_platform_get_and_ioremap_resource(
    dev: *mut PlatformDevice,
    index: u32,
    out: *mut *mut LinuxResource,
) -> *mut c_void {
    let res = platform_get_resource(dev, IORESOURCE_MEM as u32, index);
    if !out.is_null() {
        // SAFETY: out is caller-provided writable storage for one resource pointer.
        unsafe { *out = res; }
    }
    if res.is_null() { return null_mut(); }
    // SAFETY: res is returned from the device resource array.
    let r = unsafe { *res };
    let len = resource_len(r);
    if len == RESOURCE_EMPTY { return null_mut(); }
    super::maps::iomap_resource(r, len).unwrap_or(null_mut())
}

extern "C" fn acpi_match_device(ids: *const AcpiDeviceId, dev: *const crate::linux_device::types::LinuxDevice) -> *const AcpiDeviceId {
    if ids.is_null() || dev.is_null() { return null(); }
    // SAFETY: dev points at a Linux device; acpi_node is either null or an acpi_device.
    let acpi = unsafe { (*dev).acpi_node as *const AcpiDevice };
    if acpi.is_null() { return null(); }
    let mut cur = ids;
    loop {
        // SAFETY: ids is a Linux sentinel-terminated ACPI match table.
        let id = unsafe { &*cur };
        if id.id[0] == 0 { return null(); }
        // SAFETY: acpi was tested non-null above and is the device's ACPI companion; hid is an inline [c_char; ACPI_ID_LEN] array, exactly the ACPI_ID_LEN bytes fixed_id_eq reads.
        if fixed_id_eq(id.id.as_ptr(), unsafe { (*acpi).hid.as_ptr() }) { return cur; }
        // SAFETY: advancing within caller-provided sentinel-terminated table.
        cur = unsafe { cur.add(1) };
    }
}

extern "C" fn acpi_dev_get_first_match_dev(hid: *const c_char, uid: *const c_char, _hrv: i64) -> *mut AcpiDevice {
    if hid.is_null() { return null_mut(); }
    let devices = DEVICES.lock().clone();
    for p in devices {
        // SAFETY: stored platform devices remain valid while registered.
        let acpi = unsafe { (*(p as *mut PlatformDevice)).dev.acpi_node as *mut AcpiDevice };
        if acpi.is_null() { continue; }
        // SAFETY: acpi points at a Linux ACPI companion installed by the caller.
        let hid_match = fixed_len_cstr_eq(unsafe { (*acpi).hid.as_ptr() }, ACPI_ID_LEN, hid);
        // SAFETY: the `continue` above skipped a null acpi; uid is an inline [c_char; ACPI_ID_LEN] array, so the ACPI_ID_LEN bound handed to fixed_len_cstr_eq matches its real extent.
        let uid_match = uid.is_null() || fixed_len_cstr_eq(unsafe { (*acpi).uid.as_ptr() }, ACPI_ID_LEN, uid);
        if hid_match && uid_match { return acpi; }
    }
    null_mut()
}

extern "C" fn acpi_dev_put(_adev: *mut AcpiDevice) {}

extern "C" fn of_match_device(ids: *const OfDeviceId, dev: *const crate::linux_device::types::LinuxDevice) -> *const OfDeviceId {
    if ids.is_null() || dev.is_null() { return null(); }
    // SAFETY: dev points at a Linux device; of_node is either null or a device_node.
    let node = unsafe { (*dev).of_node as *const DeviceNode };
    if node.is_null() { return null(); }
    let mut cur = ids;
    loop {
        // SAFETY: ids is a Linux sentinel-terminated OF match table.
        let id = unsafe { &*cur };
        if id.name.is_null() && id.ty.is_null() && id.compatible.is_null() { return null(); }
        if of_entry_matches(id, node) { return cur; }
        // SAFETY: advancing within caller-provided sentinel-terminated table.
        cur = unsafe { cur.add(1) };
    }
}

extern "C" fn of_property_read_u32(_np: *const DeviceNode, _propname: *const c_char, _out_value: *mut u32) -> i32 {
    -LINUX_ENOENT
}

extern "C" fn of_property_read_bool(_np: *const DeviceNode, _propname: *const c_char) -> bool {
    false
}

fn bind_device(dev: *mut PlatformDevice) {
    let drivers = DRIVERS.lock().clone();
    for p in drivers {
        if bind_driver_to_device(p as *mut PlatformDriver, dev) { return; }
    }
}

fn bind_driver_to_device(driver: *mut PlatformDriver, dev: *mut PlatformDevice) -> bool {
    if driver.is_null() || dev.is_null() { return false; }
    // SAFETY: dev was tested non-null on the line above; it reached here either straight from platform_device_add or out of DEVICES, which platform_device_del empties before the device may be freed, so the struct is still live.
    if unsafe { !(*dev).driver.is_null() } { return false; }
    let id = match platform_match(driver, dev) { Some(v) => v, None => return false };
    // SAFETY: driver and dev are caller-owned Linux platform structs.
    unsafe {
        (*dev).driver = driver;
        (*dev).id_entry = id;
        (*dev).dev.driver = &mut (*driver).driver;
    }
    // SAFETY: driver was tested non-null above and comes from DRIVERS, which platform_driver_unregister clears before the module may drop the struct platform_driver.
    if let Some(probe) = unsafe { (*driver).probe } {
        // SAFETY: probe is the module's own extern "C" fn(*mut platform_device) -> int, and the binding fields it expects (driver, id_entry, dev.driver) were installed immediately above.
        let rc = unsafe { probe(dev) };
        if rc != LINUX_OK {
            // SAFETY: binding fields were installed just above and are being unwound.
            unsafe {
                (*dev).driver = null_mut();
                (*dev).id_entry = null();
                (*dev).dev.driver = null_mut();
            }
            return false;
        }
    }
    true
}

fn unbind_device(dev: *mut PlatformDevice) {
    if dev.is_null() { return; }
    // SAFETY: dev points at a caller-owned Linux struct platform_device.
    let driver = unsafe { (*dev).driver };
    if driver.is_null() { return; }
    // SAFETY: driver is the pointer read out of (*dev).driver and returned early when null; only bind_driver_to_device stores it there, and it stores a live DRIVERS entry.
    if let Some(remove) = unsafe { (*driver).remove } {
        // SAFETY: remove is the module's own extern "C" fn(*mut platform_device), invoked while dev is still bound to this driver, mirroring the Linux unbind order.
        let _ = unsafe { remove(dev) };
    }
    // SAFETY: dev is exclusively unbound by platform registry mutation.
    unsafe {
        (*dev).driver = null_mut();
        (*dev).id_entry = null();
        (*dev).dev.driver = null_mut();
    }
}

fn platform_match(driver: *mut PlatformDriver, dev: *mut PlatformDevice) -> Option<*const PlatformDeviceId> {
    // SAFETY: driver/dev are validated before matching.
    unsafe {
        if !of_match_device((*driver).driver.of_match_table as *const OfDeviceId, &(*dev).dev).is_null() {
            return Some(null());
        }
        if !acpi_match_device((*driver).driver.acpi_match_table as *const AcpiDeviceId, &(*dev).dev).is_null() {
            return Some(null());
        }
        let id = platform_match_id((*driver).id_table, dev);
        if !id.is_null() { return Some(id); }
        if !(*driver).driver.name.is_null() && cstr_eq((*driver).driver.name, (*dev).name) {
            return Some(null());
        }
    }
    None
}

fn platform_match_id(ids: *const PlatformDeviceId, dev: *mut PlatformDevice) -> *const PlatformDeviceId {
    if ids.is_null() || dev.is_null() { return null(); }
    let mut cur = ids;
    loop {
        // SAFETY: ids is a Linux sentinel-terminated platform match table.
        let id = unsafe { &*cur };
        if id.name[0] == 0 { return null(); }
        // SAFETY: dev was tested non-null at fn entry; name is the NUL-terminated string platform_device_alloc rejected as null, and PLATFORM_NAME_SIZE is the true extent of id.name, not of dev.name.
        if fixed_len_cstr_eq(id.name.as_ptr(), PLATFORM_NAME_SIZE, unsafe { (*dev).name }) { return cur; }
        // SAFETY: advancing within caller-provided sentinel-terminated table.
        cur = unsafe { cur.add(1) };
    }
}

fn of_entry_matches(id: &OfDeviceId, node: *const DeviceNode) -> bool {
    // SAFETY: node is validated by of_match_device.
    unsafe {
        (id.compatible.is_null() || cstr_eq(id.compatible, (*node).compatible)) &&
        (id.name.is_null() || cstr_eq(id.name, (*node).name)) &&
        (id.ty.is_null() || cstr_eq(id.ty, (*node).ty))
    }
}

fn resource_len(r: LinuxResource) -> u64 {
    if r.start == 0 && r.end == 0 { RESOURCE_EMPTY }
    else if r.end < r.start { RESOURCE_EMPTY }
    else { r.end.saturating_sub(r.start).saturating_add(1) }
}

fn cstr_eq(a: *const c_char, b: *const c_char) -> bool {
    if a.is_null() || b.is_null() { return false; }
    let mut i = 0usize;
    loop {
        // SAFETY: callers pass valid NUL-terminated Linux strings.
        let av = unsafe { *a.add(i) };
        // SAFETY: callers pass valid NUL-terminated Linux strings.
        let bv = unsafe { *b.add(i) };
        if av != bv { return false; }
        if av == 0 { return true; }
        i = i.saturating_add(1);
    }
}

fn fixed_len_cstr_eq(fixed: *const c_char, len: usize, s: *const c_char) -> bool {
    if fixed.is_null() || s.is_null() { return false; }
    let mut i = 0usize;
    loop {
        if i == len {
            // SAFETY: s points at a NUL-terminated Linux string.
            return unsafe { *s.add(i) == 0 };
        }
        // SAFETY: fixed points at a Linux fixed-size name/id field.
        let fv = unsafe { *fixed.add(i) };
        // SAFETY: s points at a NUL-terminated Linux string.
        let sv = unsafe { *s.add(i) };
        if fv == 0 { return sv == 0; }
        if fv != sv { return false; }
        i = i.saturating_add(1);
    }
}

fn fixed_id_eq(id: *const u8, fixed: *const c_char) -> bool {
    if id.is_null() || fixed.is_null() { return false; }
    for i in 0..ACPI_ID_LEN {
        // SAFETY: id points at ACPI_ID_LEN bytes in an ACPI match entry.
        let iv = unsafe { *id.add(i) };
        // SAFETY: fixed points at ACPI_ID_LEN bytes in an ACPI companion.
        let fv = unsafe { *fixed.add(i) as u8 };
        if iv == 0 { return fv == 0; }
        if iv != fv { return false; }
    }
    true
}

#[cfg(test)]
mod tests;
