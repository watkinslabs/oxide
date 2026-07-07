use super::allocs;
use super::devres;
use super::format::{consume_format, copy_cstr, format_into};
use super::registry;
use super::types::{
    DevresAction, LinuxBusType, LinuxClass, LinuxDevice, LinuxDeviceAttribute, LinuxDeviceDriver,
    DEVICE_NAME_LEN, GFP_ZERO, LINUX_EINVAL, LINUX_OK,
};
use core::ffi::{c_char, c_void};
use core::ptr::null_mut;

/// Register Linux device-core KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
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
        ("devm_kmalloc",            devm_kmalloc            as *const () as usize),
        ("devm_kzalloc",            devm_kzalloc            as *const () as usize),
        ("devm_kfree",              devm_kfree              as *const () as usize),
        ("devm_add_action_or_reset", devm_add_action_or_reset as *const () as usize),
        ("devm_remove_action",      devm_remove_action      as *const () as usize),
        ("_dev_err",                _dev_err                as *const () as usize),
        ("_dev_warn",               _dev_warn               as *const () as usize),
        ("_dev_info",               _dev_info               as *const () as usize),
        ("_dev_dbg",                _dev_dbg                as *const () as usize),
    ] { export(name, addr, false); }
}

extern "C" fn device_initialize(dev: *mut LinuxDevice) {
    if dev.is_null() { return; }
    // SAFETY: dev points at a caller-owned Linux struct device.
    unsafe {
        (*dev).driver_data = null_mut();
        (*dev).name = [0; DEVICE_NAME_LEN];
    }
}

extern "C" fn device_add(dev: *mut LinuxDevice) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    populate_device_name(dev);
    registry::insert_device(dev as usize)
}

extern "C" fn device_del(dev: *mut LinuxDevice) {
    if dev.is_null() { return; }
    registry::remove_device(dev as usize);
    devres::release_device(dev);
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
    dev
}

extern "C" fn put_device(dev: *mut LinuxDevice) {
    if dev.is_null() { return; }
    // SAFETY: release is a caller-installed Linux device release callback.
    unsafe {
        if let Some(release) = (*dev).release { release(dev); }
    }
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
    unsafe {
        if (*dev).name[0] != 0 { (*dev).name.as_ptr() }
        else { (*dev).init_name }
    }
}

extern "C" fn device_get_match_data(dev: *const LinuxDevice) -> *const c_void {
    crate::linux_platform::device_match_data(dev as *mut LinuxDevice)
}

unsafe extern "C" fn dev_set_name(dev: *mut LinuxDevice, fmt: *const c_char, mut ap: ...) -> i32 {
    if dev.is_null() || fmt.is_null() { return -LINUX_EINVAL; }
    // SAFETY: fmt and ap follow Linux printf-style varargs contract.
    unsafe { format_into((*dev).name.as_mut_ptr(), DEVICE_NAME_LEN, fmt, &mut ap); }
    LINUX_OK
}

extern "C" fn root_device_register(name: *const c_char) -> *mut LinuxDevice {
    let dev = allocs::alloc_device();
    if dev.is_null() { return null_mut(); }
    // SAFETY: dev was allocated with LinuxDevice layout.
    unsafe { (*dev).init_name = name; }
    if device_add(dev) != LINUX_OK {
        allocs::free_device(dev);
        return null_mut();
    }
    dev
}

extern "C" fn root_device_unregister(dev: *mut LinuxDevice) {
    device_unregister(dev);
    allocs::free_device(dev);
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
    let _ = devt;
    if class.is_null() || fmt.is_null() { return null_mut(); }
    let dev = allocs::alloc_device();
    if dev.is_null() { return null_mut(); }
    // SAFETY: dev was allocated with LinuxDevice layout and fmt/ap follow Linux varargs.
    unsafe {
        (*dev).class = class;
        (*dev).parent = parent;
        (*dev).driver_data = drvdata;
        format_into((*dev).name.as_mut_ptr(), DEVICE_NAME_LEN, fmt, &mut ap);
    }
    if device_add(dev) != LINUX_OK {
        allocs::free_device(dev);
        return null_mut();
    }
    dev
}

extern "C" fn device_destroy(class: *mut LinuxClass, devt: u32) {
    let _ = devt;
    if class.is_null() { return; }
}

extern "C" fn device_create_file(dev: *mut LinuxDevice, attr: *const LinuxDeviceAttribute) -> i32 {
    if dev.is_null() || attr.is_null() { -LINUX_EINVAL } else { LINUX_OK }
}

extern "C" fn device_remove_file(_dev: *mut LinuxDevice, _attr: *const LinuxDeviceAttribute) {}

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
    let _ = dev;
    // SAFETY: diagnostic-only formatting validates the caller's C varargs.
    unsafe { consume_format(fmt, &mut ap); }
}

unsafe extern "C" fn _dev_warn(dev: *const LinuxDevice, fmt: *const c_char, mut ap: ...) {
    let _ = dev;
    // SAFETY: diagnostic-only formatting validates the caller's C varargs.
    unsafe { consume_format(fmt, &mut ap); }
}

unsafe extern "C" fn _dev_info(dev: *const LinuxDevice, fmt: *const c_char, mut ap: ...) {
    let _ = dev;
    // SAFETY: diagnostic-only formatting validates the caller's C varargs.
    unsafe { consume_format(fmt, &mut ap); }
}

unsafe extern "C" fn _dev_dbg(dev: *const LinuxDevice, fmt: *const c_char, mut ap: ...) {
    let _ = dev;
    // SAFETY: diagnostic-only formatting validates the caller's C varargs.
    unsafe { consume_format(fmt, &mut ap); }
}

fn populate_device_name(dev: *mut LinuxDevice) {
    // SAFETY: dev points at a Linux struct device.
    unsafe {
        if (*dev).name[0] == 0 && !(*dev).init_name.is_null() {
            copy_cstr((*dev).name.as_mut_ptr(), DEVICE_NAME_LEN, (*dev).init_name);
        }
    }
}

#[cfg(test)]
mod tests;
