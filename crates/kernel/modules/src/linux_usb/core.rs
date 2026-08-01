extern crate alloc;

use super::types::*;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::{c_char, c_void};
use core::ptr::{null, null_mut};
use sync::{Modules as ModulesLockClass, Spinlock};

const NO_USB_TRANSPORT: UsbTransport = UsbTransport {
    control: None,
    bulk: None,
    interrupt: None,
    submit: None,
};

static DRIVERS: Spinlock<Vec<usize>, ModulesLockClass> = Spinlock::new(Vec::new());
static INTERFACES: Spinlock<Vec<usize>, ModulesLockClass> = Spinlock::new(Vec::new());
static TRANSPORT: Spinlock<UsbTransport, ModulesLockClass> = Spinlock::new(NO_USB_TRANSPORT);

/// Register Linux USB KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("__usb_register_driver",   __usb_register_driver  as *const () as usize),
        ("usb_register_driver",    usb_register_driver    as *const () as usize),
        ("usb_deregister",         usb_deregister         as *const () as usize),
        ("usb_alloc_urb",          usb_alloc_urb          as *const () as usize),
        ("usb_free_urb",           usb_free_urb           as *const () as usize),
        ("usb_submit_urb",         usb_submit_urb         as *const () as usize),
        ("usb_kill_urb",           usb_kill_urb           as *const () as usize),
        ("usb_unlink_urb",         usb_unlink_urb         as *const () as usize),
        ("usb_control_msg",        usb_control_msg        as *const () as usize),
        ("usb_bulk_msg",           usb_bulk_msg           as *const () as usize),
        ("usb_interrupt_msg",      usb_interrupt_msg      as *const () as usize),
        ("usb_alloc_coherent",     usb_alloc_coherent     as *const () as usize),
        ("usb_free_coherent",      usb_free_coherent      as *const () as usize),
        ("usb_buffer_alloc",       usb_alloc_coherent     as *const () as usize),
        ("usb_buffer_free",        usb_free_coherent      as *const () as usize),
        ("usb_set_intfdata",       usb_set_intfdata       as *const () as usize),
        ("usb_get_intfdata",       usb_get_intfdata       as *const () as usize),
        ("usb_get_dev",            usb_get_dev            as *const () as usize),
        ("usb_put_dev",            usb_put_dev            as *const () as usize),
        ("usb_get_intf",           usb_get_intf           as *const () as usize),
        ("usb_put_intf",           usb_put_intf           as *const () as usize),
        ("usb_match_id",           usb_match_id           as *const () as usize),
        ("usb_find_interface",     usb_find_interface     as *const () as usize),
    ] { export(name, addr, false); }
}

/// Install USB transport callbacks for a real host-controller backend.
/// # C: O(1)
#[allow(dead_code)]
pub fn set_transport(t: UsbTransport) {
    *TRANSPORT.lock() = t;
}

/// Clear USB transport callbacks.
/// # C: O(1)
#[allow(dead_code)]
pub fn clear_transport() {
    *TRANSPORT.lock() = NO_USB_TRANSPORT;
}

/// Register an observed USB interface with the compatibility core.
/// # C: O(N drivers)
#[allow(dead_code)]
pub unsafe fn install_interface(intf: *mut UsbInterface) -> i32 {
    if intf.is_null() { return -LINUX_EINVAL; }
    {
        let mut g = INTERFACES.lock();
        if g.iter().any(|p| *p == intf as usize) { return -LINUX_EBUSY; }
        g.push(intf as usize);
    }
    // SAFETY: intf was null-checked and install_interface's contract makes it a live UsbInterface owned by the caller until uninstall_interface.
    unsafe { (*intf).registered = 1; }
    // SAFETY: same live intf; the INTERFACES lock was released above so bind_interface can take it without deadlocking.
    unsafe { bind_interface(intf); }
    LINUX_OK
}

/// Remove a USB interface from the compatibility core.
/// # C: O(N interfaces)
#[allow(dead_code)]
pub unsafe fn uninstall_interface(intf: *mut UsbInterface) {
    if intf.is_null() { return; }
    INTERFACES.lock().retain(|p| *p != intf as usize);
    // SAFETY: intf was null-checked and uninstall_interface's contract makes it a live UsbInterface the caller still owns.
    let driver = unsafe { (*intf).driver };
    if !driver.is_null() {
        // SAFETY: driver was null-checked and only ever set by bind_driver_to_interface from a driver still in DRIVERS.
        if let Some(disconnect) = unsafe { (*driver).disconnect } {
            // SAFETY: Linux's disconnect contract takes the interface it was probed with, and intf is that live interface.
            unsafe { disconnect(intf); }
        }
    }
    // SAFETY: intf is still the caller's live UsbInterface; clearing both fields after disconnect matches Linux's teardown order.
    unsafe {
        (*intf).driver = null_mut();
        (*intf).registered = 0;
    }
}

extern "C" fn __usb_register_driver(
    driver: *mut UsbDriver,
    _owner: *mut c_void,
    _mod_name: *const c_char,
) -> i32 {
    usb_register_driver(driver)
}

extern "C" fn usb_register_driver(driver: *mut UsbDriver) -> i32 {
    if driver.is_null() { return -LINUX_EINVAL; }
    // SAFETY: driver was null-checked; usb_register_driver's KPI contract is a live usb_driver the module keeps alive until usb_deregister.
    if unsafe { (*driver).name.is_null() || (*driver).id_table.is_null() } { return -LINUX_EINVAL; }
    {
        let mut g = DRIVERS.lock();
        if g.iter().any(|p| *p == driver as usize) { return -LINUX_EBUSY; }
        g.push(driver as usize);
    }
    let intfs = INTERFACES.lock().clone();
    for p in intfs {
        // SAFETY: every entry in INTERFACES was installed by install_interface and is removed on uninstall, so p is a live UsbInterface; the lock was dropped by the clone.
        unsafe { bind_driver_to_interface(driver, p as *mut UsbInterface); }
    }
    LINUX_OK
}

extern "C" fn usb_deregister(driver: *mut UsbDriver) {
    if driver.is_null() { return; }
    DRIVERS.lock().retain(|p| *p != driver as usize);
    let intfs = INTERFACES.lock().clone();
    for p in intfs {
        let intf = p as *mut UsbInterface;
        // SAFETY: INTERFACES only holds interfaces install_interface registered and uninstall_interface has not removed, so intf is live.
        if unsafe { (*intf).driver == driver } {
            // SAFETY: driver was null-checked and the caller owns it for the duration of usb_deregister.
            if let Some(disconnect) = unsafe { (*driver).disconnect } {
                // SAFETY: intf is the live interface this driver was probed against, which is what Linux's disconnect expects.
                unsafe { disconnect(intf); }
            }
            // SAFETY: intf is still live and the driver it pointed at is being deregistered, so the back-pointer must be cleared.
            unsafe { (*intf).driver = null_mut(); }
        }
    }
}

extern "C" fn usb_alloc_urb(iso_packets: i32, _mem_flags: u32) -> *mut UsbUrb {
    if iso_packets < 0 { return null_mut(); }
    Box::into_raw(Box::new(UsbUrb {
        dev: null_mut(),
        pipe: 0,
        status: 0,
        transfer_flags: 0,
        transfer_buffer: null_mut(),
        transfer_buffer_length: 0,
        actual_length: 0,
        setup_packet: null_mut(),
        context: null_mut(),
        complete: None,
        interval: 0,
        number_of_packets: iso_packets,
    }))
}

unsafe extern "C" fn usb_free_urb(urb: *mut UsbUrb) {
    if urb.is_null() { return; }
    // SAFETY: urb was null-checked and usb_free_urb's contract is that it came from usb_alloc_urb, i.e. a Box::into_raw of the same layout.
    unsafe { drop(Box::from_raw(urb)); }
}

unsafe extern "C" fn usb_submit_urb(urb: *mut UsbUrb, _mem_flags: u32) -> i32 {
    if urb.is_null() { return -LINUX_EINVAL; }
    // SAFETY: urb was null-checked and usb_submit_urb's contract is a live urb from usb_alloc_urb that the caller does not free until completion.
    unsafe {
        (*urb).actual_length = 0;
        (*urb).status = -LINUX_ENODEV;
    }
    let submit = TRANSPORT.lock().submit;
    let rc = match submit {
        Some(f) => f(urb),
        None => -LINUX_ENODEV,
    };
    // SAFETY: the transport hook returns rather than freeing the urb, so it is still the live allocation checked above.
    unsafe { (*urb).status = rc; }
    if rc == LINUX_OK {
        // SAFETY: same live urb; a successful transport transfers the whole requested length in this compatibility core.
        unsafe { (*urb).actual_length = (*urb).transfer_buffer_length; }
    }
    // SAFETY: same live urb; complete is a module-supplied callback stored in it before submission.
    if let Some(complete) = unsafe { (*urb).complete } {
        // SAFETY: Linux's completion contract hands the callback the urb it was registered on, and the callback owns it from here.
        unsafe { complete(urb); }
    }
    rc
}

unsafe extern "C" fn usb_kill_urb(urb: *mut UsbUrb) {
    if urb.is_null() { return; }
    // SAFETY: urb was null-checked and usb_kill_urb's contract is a live urb from usb_alloc_urb owned by the calling module.
    unsafe { (*urb).status = -LINUX_ENOENT; }
}

unsafe extern "C" fn usb_unlink_urb(urb: *mut UsbUrb) -> i32 {
    if urb.is_null() { return -LINUX_EINVAL; }
    // SAFETY: urb was null-checked and usb_unlink_urb's contract is a live urb from usb_alloc_urb owned by the calling module.
    unsafe { (*urb).status = -LINUX_ENOENT; }
    LINUX_OK
}

extern "C" fn usb_control_msg(
    dev: *mut UsbDevice,
    pipe: u32,
    request: u8,
    requesttype: u8,
    value: u16,
    index: u16,
    data: *mut c_void,
    size: u16,
    timeout: i32,
) -> i32 {
    if dev.is_null() { return -LINUX_ENODEV; }
    match TRANSPORT.lock().control {
        Some(f) => f(dev, pipe, request, requesttype, value, index, data, size, timeout),
        None => -LINUX_ENODEV,
    }
}

extern "C" fn usb_bulk_msg(dev: *mut UsbDevice, pipe: u32, data: *mut c_void, len: i32, actual: *mut i32, timeout: i32) -> i32 {
    transfer_msg(dev, pipe, data, len, actual, timeout, TRANSPORT.lock().bulk)
}

extern "C" fn usb_interrupt_msg(dev: *mut UsbDevice, pipe: u32, data: *mut c_void, len: i32, actual: *mut i32, timeout: i32) -> i32 {
    transfer_msg(dev, pipe, data, len, actual, timeout, TRANSPORT.lock().interrupt)
}

extern "C" fn usb_alloc_coherent(dev: *mut UsbDevice, size: usize, _mem_flags: u32, dma: *mut u64) -> *mut c_void {
    let _ = dev;
    if size == 0 || dma.is_null() { return null_mut(); }
    let Some(order) = order_for_size(size) else { return null_mut(); };
    let Some((pa, va)) = crate::linux_alloc::page_run_alloc(order, true) else { return null_mut(); };
    // SAFETY: dma was null-checked above and usb_alloc_coherent's contract makes it aligned, writable dma_addr_t storage.
    unsafe { *dma = pa; }
    va as *mut c_void
}

extern "C" fn usb_free_coherent(dev: *mut UsbDevice, size: usize, addr: *mut c_void, dma: u64) {
    let _ = dev;
    if size == 0 || addr.is_null() || dma == 0 { return; }
    if let Some(order) = order_for_size(size) {
        crate::linux_alloc::page_run_free_pa(dma, order);
    }
}

unsafe extern "C" fn usb_set_intfdata(intf: *mut UsbInterface, data: *mut c_void) {
    if intf.is_null() { return; }
    // SAFETY: intf was null-checked; usb_set_intfdata is only legal on an interface the caller was probed with, which stays live across the call.
    unsafe { (*intf).intfdata = data; }
}

unsafe extern "C" fn usb_get_intfdata(intf: *mut UsbInterface) -> *mut c_void {
    if intf.is_null() { return null_mut(); }
    // SAFETY: intf was null-checked; usb_get_intfdata is only legal on an interface the caller was probed with, which stays live across the call.
    unsafe { (*intf).intfdata }
}

unsafe extern "C" fn usb_get_dev(dev: *mut UsbDevice) -> *mut UsbDevice {
    // SAFETY: dev was null-checked and usb_get_dev's contract is a device the caller already holds a reference to, so it cannot be freed here.
    if !dev.is_null() { unsafe { (*dev).refcnt = (*dev).refcnt.saturating_add(1); } }
    dev
}

unsafe extern "C" fn usb_put_dev(dev: *mut UsbDevice) {
    // SAFETY: dev was null-checked and usb_put_dev's contract is a reference the caller took with usb_get_dev, so the device is still live.
    if !dev.is_null() { unsafe { (*dev).refcnt = (*dev).refcnt.saturating_sub(1); } }
}

extern "C" fn usb_get_intf(intf: *mut UsbInterface) -> *mut UsbInterface {
    intf
}

extern "C" fn usb_put_intf(_intf: *mut UsbInterface) {}

unsafe extern "C" fn usb_match_id(intf: *mut UsbInterface, ids: *const UsbDeviceId) -> *const UsbDeviceId {
    if intf.is_null() || ids.is_null() { return null(); }
    // SAFETY: both pointers were null-checked; usb_match_id's contract is a probed interface plus the module's zero-terminated id table, match_id's preconditions.
    unsafe { match_id(intf, ids).unwrap_or(null()) }
}

extern "C" fn usb_find_interface(driver: *mut UsbDriver, minor: i32) -> *mut UsbInterface {
    if driver.is_null() { return null_mut(); }
    for p in INTERFACES.lock().iter().copied() {
        let intf = p as *mut UsbInterface;
        // SAFETY: INTERFACES only holds interfaces install_interface registered and uninstall_interface has not removed, so intf is live under the lock.
        if unsafe { (*intf).driver == driver && (*intf).registered as i32 == minor } {
            return intf;
        }
    }
    null_mut()
}

fn transfer_msg(
    dev: *mut UsbDevice,
    pipe: u32,
    data: *mut c_void,
    len: i32,
    actual: *mut i32,
    timeout: i32,
    hook: Option<fn(*mut UsbDevice, u32, *mut c_void, i32, *mut i32, i32) -> i32>,
) -> i32 {
    if dev.is_null() || len < 0 { return -LINUX_EINVAL; }
    // SAFETY: actual was null-checked and usb_bulk_msg/usb_interrupt_msg promise it is aligned, writable int storage when non-null.
    if !actual.is_null() { unsafe { *actual = 0; } }
    match hook {
        Some(f) => f(dev, pipe, data, len, actual, timeout),
        None => -LINUX_ENODEV,
    }
}

// Precondition: `intf` is a live UsbInterface currently registered in INTERFACES.
unsafe fn bind_interface(intf: *mut UsbInterface) {
    let drivers = DRIVERS.lock().clone();
    for p in drivers {
        // SAFETY: DRIVERS only holds drivers usb_register_driver added and usb_deregister has not removed, so p is live; intf is the caller's live interface.
        if unsafe { bind_driver_to_interface(p as *mut UsbDriver, intf) } { break; }
    }
}

// Precondition: `driver` and `intf` are null or live entries of DRIVERS / INTERFACES.
unsafe fn bind_driver_to_interface(driver: *mut UsbDriver, intf: *mut UsbInterface) -> bool {
    // SAFETY: both pointers were null-checked; an already-bound interface is skipped so no driver is probed twice.
    if driver.is_null() || intf.is_null() || unsafe { !(*intf).driver.is_null() } { return false; }
    // SAFETY: usb_register_driver rejected a null id_table, and Linux requires it to be a zero-terminated usb_device_id array.
    let id = unsafe { match_id(intf, (*driver).id_table) };
    let Some(id) = id else { return false; };
    // SAFETY: driver is a live entry of DRIVERS, so reading its probe hook is in bounds.
    let rc = match unsafe { (*driver).probe } {
        // SAFETY: Linux's probe contract takes the interface being bound plus the matching id entry, and id points into the driver's own table.
        Some(probe) => unsafe { probe(intf, id) },
        None => LINUX_OK,
    };
    if rc == LINUX_OK {
        // SAFETY: intf is still the live interface probe accepted, so recording the owning driver is in bounds.
        unsafe { (*intf).driver = driver; }
        true
    } else {
        false
    }
}

unsafe fn match_id(intf: *mut UsbInterface, ids: *const UsbDeviceId) -> Option<*const UsbDeviceId> {
    if ids.is_null() { return None; }
    let mut off = 0usize;
    loop {
        // SAFETY: MODULE_DEVICE_TABLE requires a zero-terminated usb_device_id array, and the terminator check below stops the walk before off leaves it.
        let id = unsafe { ids.add(off) };
        // SAFETY: id is inside the driver's id table because every earlier entry was a non-terminator; an all-zero entry ends the walk.
        if unsafe { (*id).match_flags == 0 && (*id).driver_info == 0 } { return None; }
        // SAFETY: id is a live non-terminator table entry and intf is the caller's live interface, which are id_matches' preconditions.
        if unsafe { id_matches(intf, &*id) } { return Some(id); }
        off += 1;
    }
}

// Precondition: `intf` is a live UsbInterface whose cur_altsetting and usb_dev are null or live.
unsafe fn id_matches(intf: *mut UsbInterface, id: &UsbDeviceId) -> bool {
    // SAFETY: intf is a live interface registered through install_interface, so its altsetting pointer is readable.
    let alt = unsafe { (*intf).cur_altsetting };
    if alt.is_null() { return false; }
    // SAFETY: alt was null-checked and points at the host-supplied altsetting that stays live while the interface is registered.
    let desc = unsafe { (*alt).desc };
    // SAFETY: intf is live, so reading its owning-device back-pointer is in bounds.
    let dev = unsafe { (*intf).usb_dev };
    // SAFETY: dev was null-checked and its descriptor is an inline field of the live usb_device, so the borrow lasts only for the match.
    if !dev.is_null() && !device_id_matches(unsafe { &(*dev).descriptor }, id) { return false; }
    interface_id_matches(&desc, id)
}

fn device_id_matches(desc: &UsbDeviceDescriptor, id: &UsbDeviceId) -> bool {
    let f = id.match_flags;
    if (f & USB_DEVICE_ID_MATCH_VENDOR) != 0 && desc.id_vendor != id.id_vendor { return false; }
    if (f & USB_DEVICE_ID_MATCH_PRODUCT) != 0 && desc.id_product != id.id_product { return false; }
    if (f & USB_DEVICE_ID_MATCH_DEV_LO) != 0 && desc.bcd_device < id.bcd_device_lo { return false; }
    if (f & USB_DEVICE_ID_MATCH_DEV_HI) != 0 && desc.bcd_device > id.bcd_device_hi { return false; }
    if (f & USB_DEVICE_ID_MATCH_DEV_CLASS) != 0 && desc.b_device_class != id.b_device_class { return false; }
    if (f & USB_DEVICE_ID_MATCH_DEV_SUBCLASS) != 0 && desc.b_device_sub_class != id.b_device_sub_class { return false; }
    if (f & USB_DEVICE_ID_MATCH_DEV_PROTOCOL) != 0 && desc.b_device_protocol != id.b_device_protocol { return false; }
    true
}

fn interface_id_matches(desc: &UsbInterfaceDescriptor, id: &UsbDeviceId) -> bool {
    let f = id.match_flags;
    if (f & USB_DEVICE_ID_MATCH_INT_CLASS) != 0 && desc.b_interface_class != id.b_interface_class { return false; }
    if (f & USB_DEVICE_ID_MATCH_INT_SUBCLASS) != 0 && desc.b_interface_sub_class != id.b_interface_sub_class { return false; }
    if (f & USB_DEVICE_ID_MATCH_INT_PROTOCOL) != 0 && desc.b_interface_protocol != id.b_interface_protocol { return false; }
    true
}

fn order_for_size(size: usize) -> Option<u32> {
    let bytes = size.checked_next_power_of_two()?;
    let pages = bytes.max(PAGE_SIZE) / PAGE_SIZE;
    Some(pages.trailing_zeros())
}

#[cfg(test)]
mod tests;
