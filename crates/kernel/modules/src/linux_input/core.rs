extern crate alloc;

use super::{convert::*, types::*};
use alloc::boxed::Box;
use core::ffi::c_void;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU32, Ordering};
use input::MAX_INPUT_DEVICES;
use input::VirtioChildDeviceKey;

static NEXT_SYNTHETIC_KEY: AtomicU32 = AtomicU32::new(1);

#[repr(C)]
struct InputOwned {
    dev: LinuxInputDev,
    evdev_id: u32,
    oxide_key: u32,
    registered: bool,
}

unsafe fn owned(dev: *mut LinuxInputDev) -> *mut InputOwned { dev.cast() }

unsafe fn free_absinfo(dev: *mut LinuxInputDev) {
    // SAFETY: input_allocate_device owns this optional absinfo allocation until device release.
    unsafe {
        if !(*dev).absinfo.is_null() {
            drop(Box::from_raw((*dev).absinfo as *mut [LinuxInputAbsInfo; ABS_CNT]));
            (*dev).absinfo = null_mut();
        }
    }
}

#[cfg(test)]
mod test_constants;

/// Register Linux input KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    export("input_allocate_device",  input_allocate_device  as *const () as usize, false);
    export("input_free_device",      input_free_device      as *const () as usize, false);
    export("input_register_device",  input_register_device  as *const () as usize, false);
    export("input_unregister_device", input_unregister_device as *const () as usize, false);
    export("input_set_capability",   input_set_capability   as *const () as usize, false);
    export("input_set_abs_params",   input_set_abs_params   as *const () as usize, false);
    export("input_event",            input_event            as *const () as usize, false);
    export("input_report_key",       input_report_key       as *const () as usize, false);
    export("input_report_abs",       input_report_abs       as *const () as usize, false);
    export("input_report_rel",       input_report_rel       as *const () as usize, false);
    export("input_sync",             input_sync             as *const () as usize, false);
    export("input_set_drvdata",      input_set_drvdata      as *const () as usize, false);
    export("input_get_drvdata",      input_get_drvdata      as *const () as usize, false);
}

extern "C" fn input_allocate_device() -> *mut LinuxInputDev {
    let dev = {
        // SAFETY: LinuxInputDev is a C POD mirror; zero initialization matches kzalloc.
        let linux_dev = unsafe { core::mem::zeroed() };
        InputOwned { dev: linux_dev, evdev_id: MAX_INPUT_DEVICES as u32, oxide_key: 0, registered: false }
    };
    let owned = Box::into_raw(Box::new(dev));
    // SAFETY: InputOwned is repr(C) with LinuxInputDev as its first member.
    unsafe { &mut (*owned).dev }
}

unsafe extern "C" fn input_free_device(dev: *mut LinuxInputDev) {
    if dev.is_null() { return; }
    // SAFETY: dev was just null-checked, and this KPI entry's contract is that it is an input_allocate_device result the module has not yet freed; registered is an inline u32 of that allocation.
    if unsafe { (*owned(dev)).registered } {
        // SAFETY: unregister_live's precondition is a device that completed input_register_device, which is the only writer of registered != 0 and sets oxide_key/evdev_id before doing so.
        unsafe { unregister_live(dev); }
    }
    // SAFETY: dev was allocated by input_allocate_device and is no longer registered.
    // SAFETY: this releases the owned wrapper allocated by input_allocate_device.
    unsafe { free_absinfo(dev); drop(Box::from_raw(owned(dev))); }
}

unsafe extern "C" fn input_register_device(dev: *mut LinuxInputDev) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    // SAFETY: dev was null-checked on the previous line; registering a device the module has already freed is outside this KPI's contract, so the allocation is live and registered readable.
    if unsafe { (*owned(dev)).registered } { return -LINUX_EBUSY; }
    // This KPI does not yet expose input_ff_create()/ff_device callbacks.
    // Reject an incomplete FF device instead of publishing capabilities that
    // EVIOCSFF cannot service.
    // SAFETY: input_register_device validated dev is a live LinuxInputDev pointer.
    if unsafe { test_bit(&(*dev).evbit, EV_FF) } {
        return -LINUX_EINVAL;
    }
    let key = next_device_key();
    // SAFETY: input_register_device exclusively initializes the unregistered device.
    unsafe {
        (*owned(dev)).oxide_key = key.raw();
    }
    // SAFETY: input_to_model requires a live LinuxInputDev plus name/phys/uniq that are either null or NUL-terminated; the null test above covers the former and the input KPI requires the module's identity strings to outlive registration. It only copies out of dev, so the &mut aliasing below is unaffected.
    let model = unsafe { input_to_model(dev, (*owned(dev)).oxide_key) };
    let Some((_input_id, evdev_id)) = input::install(model) else {
        // SAFETY: registration still owns the live unregistered LinuxInputDev.
        unsafe { (*owned(dev)).oxide_key = 0; }
        return -LINUX_ENOSPC;
    };
    // SAFETY: successful canonical install assigned this device's evdev identity.
    unsafe { (*owned(dev)).evdev_id = evdev_id; }
    if !input::publish_evdev(evdev_id) {
        let _ = input::remove_device(key);
        // SAFETY: publication failed before the device became registered, so the private wrapper remains caller-owned.
        unsafe { (*owned(dev)).evdev_id = MAX_INPUT_DEVICES as u32; (*owned(dev)).oxide_key = 0; }
        return -LINUX_ENOMEM;
    }
    // SAFETY: dev is the same live allocation validated at fn entry, and install plus publish_evdev have both succeeded, so flipping registered last matches the state unregister_live expects to find.
    unsafe { (*owned(dev)).registered = true; }
    LINUX_OK
}

unsafe extern "C" fn input_unregister_device(dev: *mut LinuxInputDev) {
    if dev.is_null() { return; }
    // SAFETY: dev was just null-checked; per the Linux input KPI it is the input_allocate_device result the module registered, still owned by the module at unregister time.
    if unsafe { (*owned(dev)).registered } {
        // SAFETY: registered != 0 is written only by a completed input_register_device, so the oxide_key and evdev_id that unregister_live tears down are the ones install/publish_evdev handed out.
        unsafe { unregister_live(dev); }
    }
    // SAFETY: Linux input unregister consumes the final device reference from input_allocate_device.
    // SAFETY: this releases the owned wrapper allocated by input_allocate_device.
    unsafe { free_absinfo(dev); drop(Box::from_raw(owned(dev))); }
}

unsafe extern "C" fn input_set_capability(dev: *mut LinuxInputDev, ev_type: u32, code: u32) {
    if dev.is_null() { return; }
    // SAFETY: dev was null-checked above; the &mut lives only for this call and the input KPI gives the module exclusive ownership of the device until input_register_device, so no other reference to the capability maps exists. set_capability itself range-checks ev_type/code.
    unsafe { set_capability(&mut *dev, ev_type, code); }
}

unsafe extern "C" fn input_set_abs_params(
    dev: *mut LinuxInputDev,
    axis: u16,
    min: i32,
    max: i32,
    fuzz: i32,
    flat: i32,
) {
    if dev.is_null() || axis as usize >= ABS_CNT { return; }
    // SAFETY: dev is non-null per the guard above and input_set_abs_params owns the optional ABS_CNT element allocation.
    unsafe {
        set_capability(&mut *dev, u32::from(EV_ABS), u32::from(axis));
        if (*dev).absinfo.is_null() {
            (*dev).absinfo = Box::into_raw(Box::new([LinuxInputAbsInfo::default(); ABS_CNT])) as *mut LinuxInputAbsInfo;
        }
        (*dev).absinfo.add(axis as usize).write(LinuxInputAbsInfo {
            value: 0,
            minimum: min,
            maximum: max,
            fuzz,
            flat,
            resolution: 0,
        });
    }
}

unsafe extern "C" fn input_event(dev: *mut LinuxInputDev, ev_type: u16, code: u16, value: i32) {
    if dev.is_null() { return; }
    // SAFETY: dev was null-checked on the previous line; input_event's KPI contract is that the module reports events only on a device it still owns.
    if !unsafe { (*owned(dev)).registered } {
        // SAFETY: same non-null dev; the unregistered branch means no evdev model exists yet, so this &mut to the local state bitmaps is the only live reference. update_state consults the capability bits before touching any array.
        unsafe { update_state(&mut *dev, ev_type, code, value); }
        return;
    }
    // SAFETY: registered != 0, so input_register_device stored the evdev_id that install returned into this still-live device.
    let id = unsafe { (*owned(dev)).evdev_id };
    let _ = input::push_evdev_event(id, ev_type, code, value);
}

unsafe extern "C" fn input_report_key(dev: *mut LinuxInputDev, code: u16, value: i32) {
    // SAFETY: input_event's precondition on dev is identical to input_report_key's own, so the caller of this KPI entry has already established it; input_event re-checks for null itself.
    unsafe { input_event(dev, EV_KEY, code, i32::from(value != 0)); }
}

unsafe extern "C" fn input_report_abs(dev: *mut LinuxInputDev, code: u16, value: i32) {
    // SAFETY: forwarding the caller's own dev unchanged to input_event, whose precondition on it is the same one input_report_abs imposes; the null case is handled inside input_event.
    unsafe { input_event(dev, EV_ABS, code, value); }
}

unsafe extern "C" fn input_report_rel(dev: *mut LinuxInputDev, code: u16, value: i32) {
    // SAFETY: forwarding the caller's own dev unchanged to input_event, whose precondition on it is the same one input_report_rel imposes; the null case is handled inside input_event.
    unsafe { input_event(dev, EV_REL, code, value); }
}

unsafe extern "C" fn input_sync(dev: *mut LinuxInputDev) {
    // SAFETY: forwarding the caller's own dev unchanged to input_event, whose precondition on it is the same one input_sync imposes; the null case is handled inside input_event.
    unsafe { input_event(dev, EV_SYN, SYN_REPORT, 0); }
}

unsafe extern "C" fn input_set_drvdata(dev: *mut LinuxInputDev, data: *mut c_void) {
    if dev.is_null() { return; }
    // SAFETY: dev was null-checked above; driver_data is the device-core opaque cookie slot.
    unsafe { (*dev).dev.driver_data = data; }
}

unsafe extern "C" fn input_get_drvdata(dev: *const LinuxInputDev) -> *mut c_void {
    if dev.is_null() { return null_mut(); }
    // SAFETY: dev was null-checked above; the read returns the opaque cookie by value without dereferencing it, so only the LinuxInputDev allocation itself must be live, which the KPI contract gives.
    unsafe { (*dev).dev.driver_data }
}

// Precondition: dev is a live LinuxInputDev whose registered field is non-zero, i.e. input_register_device
// completed and stored the oxide_key/evdev_id read below. No null check here — the two callers do it.
unsafe fn unregister_live(dev: *mut LinuxInputDev) {
    // SAFETY: the precondition above makes dev live and registered, so oxide_key holds the key next_device_key minted for the install that is being torn down.
    let key = VirtioChildDeviceKey::from_raw(unsafe { (*owned(dev)).oxide_key });
    // SAFETY: same live registered device; evdev_id is the identity publish_evdev consumed, so unpublish here undoes exactly that publish.
    let _ = input::unpublish_evdev(unsafe { (*owned(dev)).evdev_id });
    let _ = input::remove_device(key);
    // SAFETY: dev is still the caller's live allocation — remove_device only dropped the canonical input model, not this KPI mirror — so resetting it to the unregistered state is a plain field write.
    unsafe {
        (*owned(dev)).registered = false;
        (*owned(dev)).evdev_id = MAX_INPUT_DEVICES as u32;
        (*owned(dev)).oxide_key = 0;
    }
}

fn next_device_key() -> VirtioChildDeviceKey {
    let seq = NEXT_SYNTHETIC_KEY.fetch_add(1, Ordering::Relaxed) & SYNTHETIC_DEVICE_KEY_MASK;
    VirtioChildDeviceKey::from_raw(SYNTHETIC_DEVICE_KEY_BASE | seq)
}

fn capability_code_count(ev_type: u32) -> Option<usize> {
    match ev_type {
        ty if ty == u32::from(EV_KEY) => Some(KEY_CNT),
        ty if ty == u32::from(EV_REL) => Some(REL_CNT),
        ty if ty == u32::from(EV_ABS) => Some(ABS_CNT),
        ty if ty == u32::from(EV_MSC) => Some(MSC_CNT),
        ty if ty == u32::from(EV_SW) => Some(SW_CNT),
        ty if ty == u32::from(EV_LED) => Some(LED_CNT),
        ty if ty == u32::from(EV_SND) => Some(SND_CNT),
        ty if ty == u32::from(EV_FF) => Some(FF_CNT),
        _ => None,
    }
}

fn set_capability(dev: &mut LinuxInputDev, ev_type: u32, code: u32) {
    // Validate type and code before mutating either capability map.
    if ev_type == u32::from(EV_PWR) {
        set_bit(&mut dev.evbit, EV_PWR);
        return;
    }
    let Some(count) = capability_code_count(ev_type) else { return; };
    if code >= count as u32 { return; }
    let ev_type = ev_type as u16;
    let code = code as u16;
    match ev_type {
        EV_KEY => set_bit(&mut dev.keybit, code),
        EV_REL => set_bit(&mut dev.relbit, code),
        EV_ABS => set_bit(&mut dev.absbit, code),
        EV_MSC => set_bit(&mut dev.mscbit, code),
        EV_LED => set_bit(&mut dev.ledbit, code),
        EV_SND => set_bit(&mut dev.sndbit, code),
        EV_FF => set_bit(&mut dev.ffbit, code),
        EV_SW => set_bit(&mut dev.swbit, code),
        _ => return,
    }
    set_bit(&mut dev.evbit, ev_type);
}

fn update_state(dev: &mut LinuxInputDev, ev_type: u16, code: u16, value: i32) {
    let supported = match ev_type {
        EV_KEY => test_bit(&dev.keybit, code),
        EV_ABS => test_bit(&dev.absbit, code),
        EV_SW => test_bit(&dev.swbit, code),
        EV_LED => test_bit(&dev.ledbit, code),
        EV_SND => test_bit(&dev.sndbit, code),
        _ => false,
    };
    if !supported { return; }
    match ev_type {
        EV_KEY if value == 0 => clear_bit(&mut dev.key, code),
        EV_KEY => set_bit(&mut dev.key, code),
        EV_ABS if (code as usize) < ABS_CNT && !dev.absinfo.is_null() => {
            // SAFETY: non-null absinfo points to the ABS_CNT element allocation input_set_abs_params installed.
            unsafe { (*dev.absinfo.add(code as usize)).value = value; }
        }
        EV_SW if value == 0 => clear_bit(&mut dev.sw, code),
        EV_SW => set_bit(&mut dev.sw, code),
        EV_LED if value == 0 => clear_bit(&mut dev.led, code),
        EV_LED => set_bit(&mut dev.led, code),
        EV_SND if value == 0 => clear_bit(&mut dev.snd, code),
        EV_SND => set_bit(&mut dev.snd, code),
        _ => {}
    }
}

#[cfg(test)]
#[path = "core/tests.rs"]
mod tests;
