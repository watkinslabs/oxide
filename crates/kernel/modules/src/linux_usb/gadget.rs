extern crate alloc;

use super::types::*;
use alloc::boxed::Box;
use core::ffi::{c_char, c_void};
use core::ptr::null_mut;
use sync::{Modules as ModulesLockClass, Spinlock};

const USB_SPEED_UNKNOWN: i32 = 0;
const USB_SPEED_LOW: i32 = 1;
const USB_SPEED_FULL: i32 = 2;
const USB_SPEED_HIGH: i32 = 3;
const USB_SPEED_SUPER: i32 = 4;
const USB_SPEED_SUPER_PLUS: i32 = 5;

static GADGET_DRIVER: Spinlock<Option<usize>, ModulesLockClass> = Spinlock::new(None);

static SPEED_UNKNOWN: &[u8] = b"UNKNOWN\0";
static SPEED_LOW: &[u8] = b"low-speed\0";
static SPEED_FULL: &[u8] = b"full-speed\0";
static SPEED_HIGH: &[u8] = b"high-speed\0";
static SPEED_SUPER: &[u8] = b"super-speed\0";
static SPEED_SUPER_PLUS: &[u8] = b"super-speed-plus\0";

/// Register Linux USB gadget KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("usb_ep_alloc_request",              usb_ep_alloc_request              as *const () as usize),
        ("usb_ep_free_request",               usb_ep_free_request               as *const () as usize),
        ("usb_ep_queue",                      usb_ep_queue                      as *const () as usize),
        ("usb_ep_dequeue",                    usb_ep_dequeue                    as *const () as usize),
        ("usb_gadget_register_driver_owner",  usb_gadget_register_driver_owner  as *const () as usize),
        ("usb_gadget_unregister_driver",      usb_gadget_unregister_driver      as *const () as usize),
        ("usb_gadget_activate",               usb_gadget_activate               as *const () as usize),
        ("usb_gadget_deactivate",             usb_gadget_deactivate             as *const () as usize),
        ("usb_gadget_set_selfpowered",        usb_gadget_set_selfpowered        as *const () as usize),
        ("usb_gadget_clear_selfpowered",      usb_gadget_clear_selfpowered      as *const () as usize),
        ("usb_gadget_set_remote_wakeup",      usb_gadget_set_remote_wakeup      as *const () as usize),
        ("usb_gadget_vbus_draw",              usb_gadget_vbus_draw              as *const () as usize),
        ("usb_gadget_set_state",              usb_gadget_set_state              as *const () as usize),
        ("usb_gadget_check_config",           usb_gadget_check_config           as *const () as usize),
        ("usb_gadget_ep_match_desc",          usb_gadget_ep_match_desc          as *const () as usize),
        ("usb_speed_string",                  usb_speed_string                  as *const () as usize),
    ] { export(name, addr, false); }
}

unsafe extern "C" fn usb_ep_alloc_request(ep: *mut UsbEndpoint, gfp_flags: u32) -> *mut UsbRequest {
    if ep.is_null() { return null_mut(); }
    // SAFETY: ep was null-checked and usb_ep_alloc_request's KPI contract is an ep from the UDC's gadget->ep_list, live until the UDC unregisters.
    if !unsafe { (*ep).ops }.is_null() {
        // SAFETY: ops was just found non-null and a UDC publishes a 'static usb_ep_ops table, so reading its alloc_request slot is in bounds.
        if let Some(alloc) = unsafe { (*(*ep).ops).alloc_request } {
            // SAFETY: alloc came out of this ep's own ops table, so it has the UsbEpAllocRequestFn signature and expects exactly this ep.
            return unsafe { alloc(ep, gfp_flags) };
        }
    }
    Box::into_raw(Box::new(UsbRequest {
        buf: null_mut(), dma: 0, length: 0, actual: 0, status: 0,
        zero: 0, short_not_ok: 0, no_interrupt: 0, complete: None,
        context: null_mut(), list: ListHead::default(),
    }))
}

unsafe extern "C" fn usb_ep_free_request(ep: *mut UsbEndpoint, req: *mut UsbRequest) {
    if req.is_null() { return; }
    // SAFETY: the USB gadget KPI requires a live endpoint with an ops table and free_request hook matching the allocator that produced req.
    let free = unsafe { (*(*ep).ops).free_request.unwrap_unchecked() };
    // SAFETY: free is the endpoint's paired request deallocator; req is unqueued and no longer used after this call by the KPI contract.
    unsafe { free(ep, req); }
}

unsafe extern "C" fn usb_ep_queue(ep: *mut UsbEndpoint, req: *mut UsbRequest, gfp_flags: u32) -> i32 {
    if ep.is_null() || req.is_null() { return -LINUX_EINVAL; }
    // SAFETY: ep was null-checked and usb_ep_queue's KPI contract is an enabled ep from the UDC's ep_list, live for the duration of the call.
    if !unsafe { (*ep).ops }.is_null() {
        // SAFETY: ops was just found non-null and is the UDC's 'static usb_ep_ops table, so its queue slot is readable.
        if let Some(queue) = unsafe { (*(*ep).ops).queue } {
            // SAFETY: queue is this ep's own submit hook; Linux's contract hands ownership of req to the UDC until the completion callback runs.
            return unsafe { queue(ep, req, gfp_flags) };
        }
    }
    // SAFETY: req was null-checked and, with no UDC to take ownership, it is still the caller's live usb_request; actual/status are plain fields of it.
    unsafe {
        (*req).actual = 0;
        (*req).status = -LINUX_ENODEV;
    }
    -LINUX_ENODEV
}

unsafe extern "C" fn usb_ep_dequeue(ep: *mut UsbEndpoint, req: *mut UsbRequest) -> i32 {
    if ep.is_null() || req.is_null() { return -LINUX_EINVAL; }
    // SAFETY: ep was null-checked and usb_ep_dequeue's KPI contract is the same live UDC endpoint the request was queued on.
    if !unsafe { (*ep).ops }.is_null() {
        // SAFETY: ops was just found non-null and is the UDC's 'static usb_ep_ops table, so its dequeue slot is readable.
        if let Some(dequeue) = unsafe { (*(*ep).ops).dequeue } {
            // SAFETY: dequeue is this ep's own cancel hook and req is the request the caller queued on it, which is what it expects.
            return unsafe { dequeue(ep, req) };
        }
    }
    // SAFETY: req was null-checked and no UDC ever took it, so it is still the caller's live usb_request and status is a plain field of it.
    unsafe { (*req).status = -LINUX_ENOENT; }
    LINUX_OK
}

extern "C" fn usb_gadget_register_driver_owner(driver: *mut UsbGadgetDriver, _owner: *mut c_void) -> i32 {
    if driver.is_null() { return -LINUX_EINVAL; }
    let mut g = GADGET_DRIVER.lock();
    if g.is_some() { return -LINUX_EBUSY; }
    *g = Some(driver as usize);
    LINUX_OK
}

extern "C" fn usb_gadget_unregister_driver(driver: *mut UsbGadgetDriver) {
    let mut g = GADGET_DRIVER.lock();
    if g.map(|p| p == driver as usize).unwrap_or(false) { *g = None; }
}

extern "C" fn usb_gadget_activate(gadget: *mut UsbGadget) -> i32 {
    if gadget.is_null() { return -LINUX_EINVAL; }
    // SAFETY: gadget was null-checked; usb_gadget_activate is called by a bound function driver on the usb_gadget its UDC registered, so it
    // outlives the call, and deactivated/connected are plain u8 fields of that #[repr(C)] struct.
    unsafe {
        (*gadget).deactivated = 0;
        (*gadget).connected = 1;
    }
    LINUX_OK
}

extern "C" fn usb_gadget_deactivate(gadget: *mut UsbGadget) -> i32 {
    if gadget.is_null() { return -LINUX_EINVAL; }
    // SAFETY: gadget was null-checked; usb_gadget_deactivate is the activate counterpart and takes the same UDC-owned usb_gadget, which the
    // caller keeps alive across the call; deactivated/connected are plain u8 fields of that #[repr(C)] struct.
    unsafe {
        (*gadget).deactivated = 1;
        (*gadget).connected = 0;
    }
    LINUX_OK
}

extern "C" fn usb_gadget_set_selfpowered(gadget: *mut UsbGadget) -> i32 {
    if gadget.is_null() { return -LINUX_EINVAL; }
    // SAFETY: gadget was null-checked; the KPI contract of usb_gadget_set_selfpowered is a live UDC-registered usb_gadget, and is_selfpowered is a plain u8 field of it.
    unsafe { (*gadget).is_selfpowered = 1; }
    LINUX_OK
}

extern "C" fn usb_gadget_clear_selfpowered(gadget: *mut UsbGadget) -> i32 {
    if gadget.is_null() { return -LINUX_EINVAL; }
    // SAFETY: gadget was null-checked; usb_gadget_clear_selfpowered clears the same is_selfpowered u8 on the same live UDC-registered usb_gadget its setter wrote.
    unsafe { (*gadget).is_selfpowered = 0; }
    LINUX_OK
}

extern "C" fn usb_gadget_set_remote_wakeup(gadget: *mut UsbGadget, enabled: i32) -> i32 {
    if gadget.is_null() { return -LINUX_EINVAL; }
    // SAFETY: gadget was null-checked; usb_gadget_set_remote_wakeup takes a live UDC-registered usb_gadget, and remote_wakeup is a plain u8 field written with a 0/1 bool cast.
    unsafe { (*gadget).remote_wakeup = (enabled != 0) as u8; }
    LINUX_OK
}

extern "C" fn usb_gadget_vbus_draw(gadget: *mut UsbGadget, ma: u32) -> i32 {
    if gadget.is_null() { return -LINUX_EINVAL; }
    // SAFETY: gadget was null-checked; usb_gadget_vbus_draw is called by the bound function driver on its live usb_gadget, and vbus_draw_ma is a plain u32 field taking any value of ma.
    unsafe { (*gadget).vbus_draw_ma = ma; }
    LINUX_OK
}

extern "C" fn usb_gadget_set_state(gadget: *mut UsbGadget, state: i32) {
    if gadget.is_null() { return; }
    // SAFETY: gadget was null-checked; usb_gadget_set_state takes the live UDC-registered usb_gadget, and state is a plain i32 field that accepts any usb_device_state value.
    unsafe { (*gadget).state = state; }
}

extern "C" fn usb_gadget_check_config(gadget: *mut UsbGadget) -> i32 {
    if gadget.is_null() { return -LINUX_EINVAL; }
    // SAFETY: gadget was null-checked; usb_gadget_check_config is invoked from a config bind on the live UDC-registered usb_gadget, and max_speed is a plain i32 field this only reads.
    let speed = unsafe { (*gadget).max_speed };
    if speed < USB_SPEED_UNKNOWN || speed > USB_SPEED_SUPER_PLUS { return -LINUX_EINVAL; }
    LINUX_OK
}

extern "C" fn usb_gadget_ep_match_desc(
    gadget: *mut UsbGadget,
    ep: *mut UsbEndpoint,
    desc: *const UsbEndpointDescriptor,
    _ep_comp: *const c_void,
) -> i32 {
    if gadget.is_null() || ep.is_null() || desc.is_null() { return 0; }
    // SAFETY: desc was null-checked and Linux's ep-match contract passes the function driver's own usb_endpoint_descriptor, which outlives this call; the borrow is read-only and ends here.
    let d = unsafe { &*desc };
    // SAFETY: ep was null-checked and is an entry of gadget->ep_list walked by usb_ep_autoconfig while the config is being bound, so it is live and not concurrently mutated; only caps/maxpacket are read.
    let e = unsafe { &*ep };
    let xfer = d.bm_attributes & USB_ENDPOINT_XFERTYPE_MASK;
    if xfer == USB_ENDPOINT_XFER_BULK && e.caps.type_bulk == 0 { return 0; }
    if xfer == USB_ENDPOINT_XFER_INT && e.caps.type_int == 0 { return 0; }
    if (d.b_endpoint_address & USB_DIR_IN) != 0 && e.caps.dir_in == 0 { return 0; }
    if (d.b_endpoint_address & USB_DIR_IN) == 0 && e.caps.dir_out == 0 { return 0; }
    let limit = if e.maxpacket_limit == 0 { e.maxpacket } else { e.maxpacket_limit };
    if limit != 0 && d.w_max_packet_size > limit { return 0; }
    1
}

extern "C" fn usb_speed_string(speed: i32) -> *const c_char {
    match speed {
        USB_SPEED_LOW => SPEED_LOW.as_ptr() as *const c_char,
        USB_SPEED_FULL => SPEED_FULL.as_ptr() as *const c_char,
        USB_SPEED_HIGH => SPEED_HIGH.as_ptr() as *const c_char,
        USB_SPEED_SUPER => SPEED_SUPER.as_ptr() as *const c_char,
        USB_SPEED_SUPER_PLUS => SPEED_SUPER_PLUS.as_ptr() as *const c_char,
        _ => SPEED_UNKNOWN.as_ptr() as *const c_char,
    }
}

#[cfg(test)]
#[path = "gadget/tests.rs"]
mod tests;
