extern crate alloc;

use super::{convert::*, types::*};
use alloc::boxed::Box;
use core::ffi::c_void;
use core::ptr::{null, null_mut};
use core::sync::atomic::{AtomicU32, Ordering};
use input::MAX_INPUT_DEVICES;
use input::VirtioChildDeviceKey;

static NEXT_SYNTHETIC_KEY: AtomicU32 = AtomicU32::new(1);

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
        LinuxInputDev {
            name: null(),
            phys: null(),
            uniq: null(),
            id: LinuxInputId::default(),
            dev: linux_dev,
            private_data: null_mut(),
            propbit: [0; INPUT_PROP_WORDS],
            evbit: [0; INPUT_EV_WORDS],
            keybit: [0; INPUT_KEY_WORDS],
            relbit: [0; INPUT_REL_WORDS],
            absbit: [0; INPUT_ABS_WORDS],
            ledbit: [0; INPUT_LED_WORDS],
            absinfo: [LinuxInputAbsInfo::default(); ABS_CNT],
            key_state: [0; INPUT_KEY_WORDS],
            led_state: [0; INPUT_LED_WORDS],
            evdev_id: MAX_INPUT_DEVICES as u32,
            registered: 0,
            oxide_key: 0,
        }
    };
    Box::into_raw(Box::new(dev))
}

unsafe extern "C" fn input_free_device(dev: *mut LinuxInputDev) {
    if dev.is_null() { return; }
    if unsafe { (*dev).registered } != 0 {
        unsafe { unregister_live(dev); }
    }
    // SAFETY: dev was allocated by input_allocate_device and is no longer registered.
    unsafe { drop(Box::from_raw(dev)); }
}

unsafe extern "C" fn input_register_device(dev: *mut LinuxInputDev) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    if unsafe { (*dev).registered } != 0 { return -LINUX_EBUSY; }
    let Some(evdev_id) = lowest_free_evdev_id() else { return -LINUX_ENOSPC; };
    let key = next_device_key();
    unsafe {
        (*dev).evdev_id = evdev_id;
        (*dev).oxide_key = key.raw();
    }
    let model = unsafe { input_to_model(dev) };
    input::install(model);
    if !input::publish_evdev(evdev_id, None) {
        let _ = input::remove_device(key);
        return -LINUX_ENOMEM;
    }
    unsafe { (*dev).registered = 1; }
    LINUX_OK
}

unsafe extern "C" fn input_unregister_device(dev: *mut LinuxInputDev) {
    if dev.is_null() { return; }
    if unsafe { (*dev).registered } != 0 {
        unsafe { unregister_live(dev); }
    }
    // SAFETY: Linux input unregister consumes the final device reference from input_allocate_device.
    unsafe { drop(Box::from_raw(dev)); }
}

unsafe extern "C" fn input_set_capability(dev: *mut LinuxInputDev, ev_type: u16, code: u16) {
    if dev.is_null() { return; }
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
    unsafe {
        set_capability(&mut *dev, EV_ABS, axis);
        (*dev).absinfo[axis as usize] = LinuxInputAbsInfo {
            value: 0,
            minimum: min,
            maximum: max,
            fuzz,
            flat,
            resolution: 0,
        };
    }
}

unsafe extern "C" fn input_event(dev: *mut LinuxInputDev, ev_type: u16, code: u16, value: i32) {
    if dev.is_null() { return; }
    unsafe { update_state(&mut *dev, ev_type, code, value); }
    if unsafe { (*dev).registered } == 0 { return; }
    let id = unsafe { (*dev).evdev_id };
    input::push_evdev_event(id, ev_type, code, value);
}

unsafe extern "C" fn input_report_key(dev: *mut LinuxInputDev, code: u16, value: i32) {
    unsafe { input_event(dev, EV_KEY, code, value); }
}

unsafe extern "C" fn input_report_abs(dev: *mut LinuxInputDev, code: u16, value: i32) {
    unsafe { input_event(dev, EV_ABS, code, value); }
}

unsafe extern "C" fn input_report_rel(dev: *mut LinuxInputDev, code: u16, value: i32) {
    unsafe { input_event(dev, EV_REL, code, value); }
}

unsafe extern "C" fn input_sync(dev: *mut LinuxInputDev) {
    unsafe { input_event(dev, EV_SYN, SYN_REPORT, 0); }
}

unsafe extern "C" fn input_set_drvdata(dev: *mut LinuxInputDev, data: *mut c_void) {
    if dev.is_null() { return; }
    unsafe { (*dev).private_data = data; }
}

unsafe extern "C" fn input_get_drvdata(dev: *const LinuxInputDev) -> *mut c_void {
    if dev.is_null() { return null_mut(); }
    unsafe { (*dev).private_data }
}

unsafe fn unregister_live(dev: *mut LinuxInputDev) {
    let key = VirtioChildDeviceKey::from_raw(unsafe { (*dev).oxide_key });
    let _ = input::unpublish_evdev(unsafe { (*dev).evdev_id });
    let _ = input::remove_device(key);
    unsafe {
        (*dev).registered = 0;
        (*dev).evdev_id = MAX_INPUT_DEVICES as u32;
        (*dev).oxide_key = 0;
    }
}

fn lowest_free_evdev_id() -> Option<u32> {
    let devs = input::devices_snapshot();
    for id in 0..MAX_INPUT_DEVICES as u32 {
        if devs.iter().all(|d| d.evdev_id != id) {
            return Some(id);
        }
    }
    None
}

fn next_device_key() -> VirtioChildDeviceKey {
    let seq = NEXT_SYNTHETIC_KEY.fetch_add(1, Ordering::Relaxed) & SYNTHETIC_DEVICE_KEY_MASK;
    VirtioChildDeviceKey::from_raw(SYNTHETIC_DEVICE_KEY_BASE | seq)
}

fn set_capability(dev: &mut LinuxInputDev, ev_type: u16, code: u16) {
    set_bit(&mut dev.evbit, ev_type);
    match ev_type {
        EV_KEY => set_bit(&mut dev.keybit, code),
        EV_REL => set_bit(&mut dev.relbit, code),
        EV_ABS => set_bit(&mut dev.absbit, code),
        EV_LED => set_bit(&mut dev.ledbit, code),
        _ => {}
    }
}

fn update_state(dev: &mut LinuxInputDev, ev_type: u16, code: u16, value: i32) {
    match ev_type {
        EV_KEY if value == 0 => clear_bit(&mut dev.key_state, code),
        EV_KEY => set_bit(&mut dev.key_state, code),
        EV_ABS if (code as usize) < ABS_CNT => dev.absinfo[code as usize].value = value,
        EV_LED if value == 0 => clear_bit(&mut dev.led_state, code),
        EV_LED => set_bit(&mut dev.led_state, code),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_char;

    const KEY_A: u16 = 30;
    const ABS_X: u16 = 0;
    const LED_NUML: u16 = 0;
    static NAME: &[u8] = b"kpi-input\0";

    #[test]
    fn input_event_abi_is_linux_compatible() {
        assert_eq!(core::mem::size_of::<LinuxInputEvent>(), INPUT_EVENT_BYTES);
    }

    #[test]
    fn register_exports_capabilities_to_evdev_model() {
        let dev = input_allocate_device();
        assert!(!dev.is_null());
        unsafe {
            (*dev).name = NAME.as_ptr() as *const c_char;
            (*dev).id.bustype = 6;
            (*dev).id.vendor = input::VIRTIO_PCI_VENDOR_ID;
            (*dev).id.product = 0x1045;
            input_set_capability(dev, EV_KEY, KEY_A);
            input_set_capability(dev, EV_LED, LED_NUML);
            input_set_abs_params(dev, ABS_X, -10, 10, 1, 2);
            assert_eq!(input_register_device(dev), LINUX_OK);
            let id = (*dev).evdev_id;
            let model = input::device(id).expect("registered input model");
            assert_eq!(model.name_len, NAME.len() - 1);
            assert_eq!(&model.name[..model.name_len], &NAME[..NAME.len() - 1]);
            assert!(model.is_pointer);
            assert_ne!(model.key_bits.bits[(KEY_A / 8) as usize] & (1u8 << (KEY_A % 8)), 0);
            assert_ne!(model.led_bits.bits[(LED_NUML / 8) as usize] & (1u8 << (LED_NUML % 8)), 0);
            assert!(model.abs_info[ABS_X as usize].is_some());
            input_report_key(dev, KEY_A, 1);
            assert!(test_bit(&(*dev).key_state, KEY_A));
            input_event(dev, EV_LED, LED_NUML, 1);
            assert!(test_bit(&(*dev).led_state, LED_NUML));
            input_unregister_device(dev);
            assert!(input::device(id).is_none());
        }
    }
}
