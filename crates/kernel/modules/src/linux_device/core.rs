use super::allocs;
use super::devres;
use super::format::{copy_cstr, format_into};
use super::registry;
use super::types::{
    DevresAction, LinuxBusType, LinuxClass, LinuxDevice, LinuxDeviceAttribute, LinuxDeviceDriver,
    DEVICE_NAME_LEN, GFP_ZERO, LINUX_EINVAL, LINUX_OK,
};
use core::ffi::{c_char, c_void, VaList};
use core::ptr::null_mut;

const SYSFS_PAGE_SIZE: usize = crate::linux_alloc::PAGE_SIZE;
static EMPTY_DEVICE_DRIVER_NAME: [u8; 1] = [0];

/// Register Linux device-core KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    super::kobject::export_symbols();
    for (name, addr) in [
        ("device_initialize",       device_initialize       as *const () as usize),
        ("device_add",              device_add              as *const () as usize),
        ("device_del",              device_del              as *const () as usize),
        ("device_register",         device_register         as *const () as usize),
        ("device_unregister",       device_unregister       as *const () as usize),
        ("get_device",              get_device              as *const () as usize),
        ("put_device",              put_device              as *const () as usize),
        ("dev_set_drvdata",         dev_set_drvdata         as *const () as usize),
        ("dev_get_drvdata",         dev_get_drvdata         as *const () as usize),
        ("dev_name",                dev_name                as *const () as usize),
        ("dev_driver_string",       dev_driver_string       as *const () as usize),
        ("dev_err_probe",           dev_err_probe           as *const () as usize),
        ("device_get_match_data",   device_get_match_data   as *const () as usize),
        ("dev_set_name",            dev_set_name            as *const () as usize),
        ("root_device_register",    root_device_register    as *const () as usize),
        ("root_device_unregister",  root_device_unregister  as *const () as usize),
        ("__class_create",          __class_create          as *const () as usize),
        ("class_register",          class_register          as *const () as usize),
        ("class_unregister",        class_unregister        as *const () as usize),
        ("class_destroy",           class_destroy           as *const () as usize),
        ("bus_register",            bus_register            as *const () as usize),
        ("bus_unregister",          bus_unregister          as *const () as usize),
        ("driver_register",         driver_register         as *const () as usize),
        ("driver_unregister",       driver_unregister       as *const () as usize),
        ("device_create",           device_create           as *const () as usize),
        ("device_destroy",          device_destroy          as *const () as usize),
        ("device_create_file",      device_create_file      as *const () as usize),
        ("device_remove_file",      device_remove_file      as *const () as usize),
        ("sysfs_emit",              sysfs_emit              as *const () as usize),
        ("sysfs_emit_at",           sysfs_emit_at           as *const () as usize),
        ("devm_kmalloc",            devm_kmalloc            as *const () as usize),
        ("devm_kzalloc",            devm_kzalloc            as *const () as usize),
        ("devm_kfree",              devm_kfree              as *const () as usize),
        ("devm_clk_get_optional_enabled", devm_clk_get_optional_enabled as *const () as usize),
        ("devm_add_action_or_reset", devm_add_action_or_reset as *const () as usize),
        ("devm_remove_action",      devm_remove_action      as *const () as usize),
        ("_dev_err",                _dev_err                as *const () as usize),
        ("_dev_warn",               _dev_warn               as *const () as usize),
        ("_dev_info",               _dev_info               as *const () as usize),
        ("_dev_dbg",                _dev_dbg                as *const () as usize),
        ("__dynamic_dev_dbg",       dynamic_dev_dbg         as *const () as usize),
    ] { export(name, addr, false); }
}

/// # C: O(1)
extern "C" fn devm_clk_get_optional_enabled(_dev: *mut LinuxDevice, _id: *const c_char) -> *mut c_void { null_mut() }

extern "C" fn device_initialize(dev: *mut LinuxDevice) {
    if dev.is_null() { return; }
    // SAFETY: dev points at a caller-owned Linux struct device.
    unsafe {
        (*dev).driver_data = null_mut();
        (*dev).kobj = super::types::LinuxKobject::new();
        (*dev).kobj.kref = 1;
        (*dev).kobj.state = 1;
        (*dev).driver = null_mut();
    }
    registry::initialize_kobject(unsafe { &mut (*dev).kobj as *mut _ as usize });
    registry::initialize_device(dev as usize);
}

/// # C: O(1)
pub(crate) fn initialize_embedded(dev: *mut LinuxDevice) { device_initialize(dev); }

/// # C: O(1)
pub(crate) fn release_embedded(dev: *mut LinuxDevice) {
    if dev.is_null() { return; }
    // SAFETY: dev is an embedded device whose owner is tearing down its containing allocation.
    unsafe { registry::remove_kobject(&mut (*dev).kobj as *mut _ as usize); }
}

pub(crate) extern "C" fn device_add(dev: *mut LinuxDevice) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    // SAFETY: dev points at caller-owned storage; a zero kref means it has not entered device core.
    if unsafe { (*dev).kobj.kref == 0 } { device_initialize(dev); }
    populate_device_name(dev);
    // SAFETY: dev points at a caller-owned Linux struct device.
    let class = unsafe { (*dev).class as usize };
    registry::add_device(dev as usize, class, 0, false)
}

pub(crate) extern "C" fn device_del(dev: *mut LinuxDevice) {
    if dev.is_null() { return; }
    registry::remove_device(dev as usize);
}

/// Send a change event from an already-published embedded device.
/// # C: O(name depth)
pub(crate) unsafe fn device_change_uevent(dev: *mut LinuxDevice, envp: *mut *mut c_char) {
    // SAFETY: caller supplies a live embedded device and a NULL-terminated Linux uevent environment vector.
    let _ = unsafe { super::kobject::kobject_uevent_env(&mut (*dev).kobj, super::kobject::KOBJ_CHANGE, envp) };
}

#[cfg(test)]
pub(crate) fn uevent_sequence(dev: *mut LinuxDevice) -> u64 {
    if dev.is_null() { return 0; }
    // SAFETY: dev is null-checked and the test owns its initialized embedded kobject.
    registry::kobject_uevent_sequence(unsafe { &mut (*dev).kobj as *mut _ as usize })
}

extern "C" fn device_register(dev: *mut LinuxDevice) -> i32 {
    device_initialize(dev);
    device_add(dev)
}

extern "C" fn device_unregister(dev: *mut LinuxDevice) {
    if dev.is_null() { return; }
    device_del(dev);
    put_device(dev);
}

extern "C" fn get_device(dev: *mut LinuxDevice) -> *mut LinuxDevice {
    if dev.is_null() { return null_mut(); }
    if registry::get_device(dev as usize) { dev } else { null_mut() }
}

extern "C" fn put_device(dev: *mut LinuxDevice) {
    if dev.is_null() { return; }
    let Some(owned) = registry::put_device(dev as usize) else { return; };
    devres::release_device(dev);
    // SAFETY: release is a caller-installed Linux device release callback.
    unsafe {
        if let Some(release) = (*dev).release { release(dev); }
    }
    if owned { allocs::free_device(dev); }
}

extern "C" fn dev_set_drvdata(dev: *mut LinuxDevice, data: *mut c_void) {
    if dev.is_null() { return; }
    // SAFETY: dev points at a caller-owned Linux struct device.
    unsafe { (*dev).driver_data = data; }
}

extern "C" fn dev_get_drvdata(dev: *const LinuxDevice) -> *mut c_void {
    if dev.is_null() { null_mut() } else {
        // SAFETY: dev points at a Linux struct device prefix.
        unsafe { (*dev).driver_data }
    }
}

extern "C" fn dev_name(dev: *const LinuxDevice) -> *const c_char {
    if dev.is_null() { return core::ptr::null(); }
    // SAFETY: dev points at a Linux struct device.
    unsafe { if !(*dev).kobj.name.is_null() { (*dev).kobj.name } else { (*dev).init_name } }
}

extern "C" fn device_get_match_data(dev: *const LinuxDevice) -> *const c_void {
    crate::linux_platform::device_match_data(dev as *mut LinuxDevice)
}

unsafe extern "C" fn dev_set_name(dev: *mut LinuxDevice, fmt: *const c_char, mut ap: ...) -> i32 {
    if dev.is_null() || fmt.is_null() { return -LINUX_EINVAL; }
    // SAFETY: fmt and ap follow Linux printf-style varargs contract.
    unsafe { set_formatted_name(dev, fmt, &mut ap); }
    LINUX_OK
}

extern "C" fn root_device_register(name: *const c_char) -> *mut LinuxDevice {
    let dev = allocs::alloc_device();
    if dev.is_null() { return null_mut(); }
    device_initialize(dev);
    // SAFETY: dev was allocated with LinuxDevice layout.
    unsafe { (*dev).init_name = name; }
    if device_add(dev) != LINUX_OK {
        allocs::free_device(dev);
        return null_mut();
    }
    registry::mark_owned(dev as usize);
    dev
}

/// Register a device-core child owned by a compatibility subsystem.
/// # C: O(1)
pub(crate) fn register_child(parent: *mut LinuxDevice, name: *const c_char) -> *mut LinuxDevice {
    let dev = allocs::alloc_device();
    if dev.is_null() { return null_mut(); }
    // SAFETY: alloc_device returned uniquely-owned LinuxDevice storage before publication.
    unsafe { (*dev).parent = parent; (*dev).init_name = name; }
    if device_register(dev) != LINUX_OK {
        allocs::free_device(dev);
        return null_mut();
    }
    registry::mark_owned(dev as usize);
    dev
}

/// Withdraw a compatibility child created by register_child.
/// # C: O(1)
pub(crate) fn unregister_child(dev: *mut LinuxDevice) { device_unregister(dev); }

extern "C" fn root_device_unregister(dev: *mut LinuxDevice) {
    device_unregister(dev);
}

extern "C" fn __class_create(owner: *mut c_void, name: *const c_char) -> *mut LinuxClass {
    if name.is_null() { return null_mut(); }
    let class = allocs::alloc_class();
    if class.is_null() { return null_mut(); }
    // SAFETY: class was allocated with LinuxClass layout.
    unsafe {
        (*class).name = name;
        (*class).owner = owner;
        (*class).private = null_mut();
    }
    if class_register(class) != LINUX_OK {
        allocs::free_class(class);
        return null_mut();
    }
    class
}

extern "C" fn class_register(class: *mut LinuxClass) -> i32 {
    if class.is_null() { return -LINUX_EINVAL; }
    registry::insert_class(class as usize)
}

extern "C" fn class_unregister(class: *mut LinuxClass) {
    if class.is_null() { return; }
    registry::remove_class(class as usize);
}

extern "C" fn class_destroy(class: *mut LinuxClass) {
    class_unregister(class);
    allocs::free_class(class);
}

extern "C" fn bus_register(bus: *mut LinuxBusType) -> i32 {
    if bus.is_null() { return -LINUX_EINVAL; }
    registry::insert_bus(bus as usize)
}

extern "C" fn bus_unregister(bus: *mut LinuxBusType) {
    if bus.is_null() { return; }
    registry::remove_bus(bus as usize);
}

extern "C" fn driver_register(driver: *mut LinuxDeviceDriver) -> i32 {
    if driver.is_null() { return -LINUX_EINVAL; }
    registry::insert_driver(driver as usize)
}

extern "C" fn driver_unregister(driver: *mut LinuxDeviceDriver) {
    if driver.is_null() { return; }
    registry::remove_driver(driver as usize);
}

unsafe extern "C" fn device_create(
    class: *mut LinuxClass,
    parent: *mut LinuxDevice,
    devt: u32,
    drvdata: *mut c_void,
    fmt: *const c_char,
    mut ap: ...
) -> *mut LinuxDevice {
    if class.is_null() || fmt.is_null() { return null_mut(); }
    let dev = allocs::alloc_device();
    if dev.is_null() { return null_mut(); }
    device_initialize(dev);
    // SAFETY: dev was allocated with LinuxDevice layout and fmt/ap follow Linux varargs.
    unsafe {
        (*dev).class = class;
        (*dev).parent = parent;
        (*dev).driver_data = drvdata;
        set_formatted_name(dev, fmt, &mut ap);
    }
    if registry::add_device(dev as usize, class as usize, devt, true) != LINUX_OK {
        allocs::free_device(dev);
        return null_mut();
    }
    dev
}

extern "C" fn device_destroy(class: *mut LinuxClass, devt: u32) {
    if class.is_null() { return; }
    if let Some(dev) = registry::find_class_devt(class as usize, devt) {
        device_unregister(dev as *mut LinuxDevice);
    }
}

extern "C" fn device_create_file(dev: *mut LinuxDevice, attr: *const LinuxDeviceAttribute) -> i32 {
    if dev.is_null() || attr.is_null() { -LINUX_EINVAL } else { registry::add_attr(dev as usize, attr as usize) }
}

extern "C" fn device_remove_file(dev: *mut LinuxDevice, attr: *const LinuxDeviceAttribute) {
    if dev.is_null() || attr.is_null() { return; }
    registry::remove_attr(dev as usize, attr as usize);
}

unsafe extern "C" fn sysfs_emit(buf: *mut c_char, fmt: *const c_char, mut ap: ...) -> i32 {
    // SAFETY: sysfs show callbacks pass a PAGE_SIZE output buffer and matching varargs.
    unsafe { crate::linux_string::vscnprintf(buf as *mut u8, SYSFS_PAGE_SIZE, fmt as *const u8, &mut ap) }
}

unsafe extern "C" fn sysfs_emit_at(buf: *mut c_char, at: i32, fmt: *const c_char, mut ap: ...) -> i32 {
    if at < 0 || at as usize >= SYSFS_PAGE_SIZE { return 0; }
    let off = at as usize;
    // SAFETY: off is within the sysfs PAGE_SIZE buffer and varargs match fmt.
    unsafe { crate::linux_string::vscnprintf(buf.add(off) as *mut u8, SYSFS_PAGE_SIZE - off, fmt as *const u8, &mut ap) }
}

extern "C" fn devm_kmalloc(dev: *mut LinuxDevice, size: usize, flags: u32) -> *mut c_void {
    devres::alloc_devres(dev, size, flags & GFP_ZERO != 0)
}

extern "C" fn devm_kzalloc(dev: *mut LinuxDevice, size: usize, _flags: u32) -> *mut c_void {
    devres::alloc_devres(dev, size, true)
}

extern "C" fn devm_kfree(dev: *mut LinuxDevice, ptr: *mut c_void) {
    devres::free_devres_for(dev, ptr);
}

extern "C" fn devm_add_action_or_reset(dev: *mut LinuxDevice, action: Option<DevresAction>, data: *mut c_void) -> i32 {
    devres::add_action_or_reset(dev, action, data)
}

extern "C" fn devm_remove_action(dev: *mut LinuxDevice, action: Option<DevresAction>, data: *mut c_void) {
    devres::remove_action(dev, action, data);
}

unsafe extern "C" fn _dev_err(dev: *const LinuxDevice, fmt: *const c_char, mut ap: ...) {
    // SAFETY: dev diagnostics accept Linux printf-compatible varargs.
    unsafe { dev_log(b"err", dev, fmt, &mut ap); }
}

/// # C: O(1)
unsafe extern "C" fn dev_driver_string(dev: *const LinuxDevice) -> *const c_char {
    if dev.is_null() { return EMPTY_DEVICE_DRIVER_NAME.as_ptr() as *const c_char; }
    // SAFETY: dev is non-NULL and driver/bus fields are stable for this diagnostic lookup.
    unsafe {
        if !(*dev).driver.is_null() && !(*(*dev).driver).name.is_null() { return (*(*dev).driver).name; }
        if !(*dev).bus.is_null() && !(*(*dev).bus).name.is_null() { return (*(*dev).bus).name; }
    }
    EMPTY_DEVICE_DRIVER_NAME.as_ptr() as *const c_char
}

/// # C: O(formatted diagnostic)
unsafe extern "C" fn dev_err_probe(dev: *const LinuxDevice, err: i32, fmt: *const c_char,
    mut ap: ...) -> i32 {
    // SAFETY: caller supplies the printf-compatible varargs promised by the KPI.
    unsafe { dev_log(b"err", dev, fmt, &mut ap); }
    err
}

unsafe extern "C" fn _dev_warn(dev: *const LinuxDevice, fmt: *const c_char, mut ap: ...) {
    // SAFETY: dev diagnostics accept Linux printf-compatible varargs.
    unsafe { dev_log(b"warn", dev, fmt, &mut ap); }
}

unsafe extern "C" fn _dev_info(dev: *const LinuxDevice, fmt: *const c_char, mut ap: ...) {
    // SAFETY: dev diagnostics accept Linux printf-compatible varargs.
    unsafe { dev_log(b"info", dev, fmt, &mut ap); }
}

unsafe extern "C" fn _dev_dbg(dev: *const LinuxDevice, fmt: *const c_char, mut ap: ...) {
    // SAFETY: dev diagnostics accept Linux printf-compatible varargs.
    unsafe { dev_log(b"debug", dev, fmt, &mut ap); }
}

unsafe extern "C" fn dynamic_dev_dbg(desc: *mut c_void, dev: *const LinuxDevice, fmt: *const c_char, mut ap: ...) {
    let _ = desc;
    // SAFETY: dynamic dev debug callers pass a descriptor/device and printf-compatible varargs.
    unsafe { dev_log(b"debug", dev, fmt, &mut ap); }
}

fn populate_device_name(dev: *mut LinuxDevice) {
    // SAFETY: dev points at a Linux struct device.
    unsafe {
        if (*dev).kobj.name.is_null() && !(*dev).init_name.is_null() {
            set_name_from_cstr(dev, (*dev).init_name);
        }
    }
}

/// # C: O(n), n is the bounded C-string length.
pub(crate) unsafe fn set_name_from_cstr(dev: *mut LinuxDevice, name: *const c_char) {
    if dev.is_null() || name.is_null() { return; }
    let mut buf = [0; DEVICE_NAME_LEN];
    // SAFETY: name is a caller-provided C string and buf bounds the copy.
    unsafe { copy_cstr(buf.as_mut_ptr(), buf.len(), name); }
    // SAFETY: device_initialize establishes the kobject registry entry before naming.
    unsafe { (*dev).kobj.name = registry::replace_kobject_name(&mut (*dev).kobj as *mut _ as usize, buf); }
}

unsafe fn set_formatted_name(dev: *mut LinuxDevice, fmt: *const c_char, ap: &mut VaList) {
    let mut buf = [0; DEVICE_NAME_LEN];
    // SAFETY: caller validated the Linux printf varargs contract.
    unsafe { format_into(buf.as_mut_ptr(), buf.len(), fmt, ap); }
    // SAFETY: device name storage belongs to the embedded initialized kobject.
    unsafe { (*dev).kobj.name = registry::replace_kobject_name(&mut (*dev).kobj as *mut _ as usize, buf); }
}

unsafe fn dev_log(level: &[u8], dev: *const LinuxDevice, fmt: *const c_char, ap: &mut VaList) {
    let mut buf = [0u8; 256];
    // SAFETY: caller guarantees fmt/ap follow the Linux printf varargs ABI.
    let n = unsafe { crate::linux_string::vscnprintf(buf.as_mut_ptr(), buf.len(), fmt as *const u8, ap) };
    klog::write_raw(b"linux-dev ");
    klog::write_raw(level);
    if !dev.is_null() {
        let name = dev_name(dev);
        if !name.is_null() {
            klog::write_raw(b" ");
            write_cstr(name, DEVICE_NAME_LEN);
        }
    }
    klog::write_raw(b": ");
    if n > 0 {
        let len = (n as usize).min(buf.len().saturating_sub(1));
        klog::write_raw(&buf[..len]);
    }
    klog::write_raw(b"\n");
}

fn write_cstr(ptr: *const c_char, max: usize) {
    let mut i = 0usize;
    while i < max {
        // SAFETY: caller gives a C string pointer; max bounds the scan.
        let b = unsafe { *ptr.add(i) as u8 };
        if b == 0 { break; }
        klog::write_raw(&[b]);
        i += 1;
    }
}

#[cfg(test)]
mod tests;
