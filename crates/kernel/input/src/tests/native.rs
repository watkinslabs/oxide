use super::*;
use core::sync::atomic::{AtomicU32, Ordering};

static NATIVE_EVENTS: AtomicU32 = AtomicU32::new(0);
static NATIVE_REL: AtomicU32 = AtomicU32::new(0);

fn record_native(key: u16, pressed: bool, repeat: bool) -> bool {
    let value = ((key as u32) << 16) | ((pressed as u32) << 1) | repeat as u32;
    NATIVE_EVENTS.store(value, Ordering::Release);
    true
}

fn record_rel(code: u16, value: i32) -> bool {
    NATIVE_REL.store(((code as u32) << 16) | value as u16 as u32, Ordering::Release);
    true
}

#[test]
fn native_key_sink_receives_press_release_and_repeat_state() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    crate::set_native_key_hook(Some(record_native));
    assert!(crate::dispatch_native_key_event(TEST_KEY_CODE, true, false));
    assert_eq!(NATIVE_EVENTS.load(Ordering::Acquire), (TEST_KEY_CODE as u32) << 16 | 2);
    assert!(crate::dispatch_native_key_event(TEST_KEY_CODE, false, true));
    assert_eq!(NATIVE_EVENTS.load(Ordering::Acquire), (TEST_KEY_CODE as u32) << 16 | 1);
    crate::set_native_key_hook(None);
    assert!(!crate::dispatch_native_key_event(TEST_KEY_CODE, true, false));
}

#[test]
fn accepted_physical_keys_reach_native_sink_once_after_state_validation() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    crate::registry::clear_devices_for_tests();
    let mut dev = test_dev(key(0x00c0_0000));
    advertise(&mut dev.ev_bits, crate::EV_KEY);
    let (_, evdev_id) = crate::install(dev).expect("install input device");
    NATIVE_EVENTS.store(0, Ordering::Release);
    crate::set_native_key_hook(Some(record_native));

    assert!(crate::push_evdev_event(evdev_id, crate::EV_KEY, TEST_KEY_CODE, 1));
    assert_eq!(NATIVE_EVENTS.load(Ordering::Acquire), (TEST_KEY_CODE as u32) << 16 | 2);
    assert!(!crate::push_evdev_event(evdev_id, crate::EV_KEY, TEST_KEY_CODE, 1));
    assert_eq!(NATIVE_EVENTS.load(Ordering::Acquire), (TEST_KEY_CODE as u32) << 16 | 2);
    assert!(crate::push_evdev_event(evdev_id, crate::EV_KEY, TEST_KEY_CODE, 0));
    assert_eq!(NATIVE_EVENTS.load(Ordering::Acquire), (TEST_KEY_CODE as u32) << 16);

    crate::set_native_key_hook(None);
    assert_eq!(crate::remove_device(key(0x00c0_0000)), Some(evdev_id));
}

#[test]
fn accepted_relative_motion_reaches_native_sink_after_state_validation() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    crate::registry::clear_devices_for_tests();
    let mut dev = test_dev(key(0x00c0_0001));
    advertise(&mut dev.ev_bits, crate::EV_REL);
    advertise(&mut dev.rel_bits.bits, crate::REL_X);
    let (_, evdev_id) = crate::install(dev).expect("install pointer");
    NATIVE_REL.store(0, Ordering::Release);
    crate::set_native_rel_hook(Some(record_rel));

    assert!(crate::push_evdev_event(evdev_id, crate::EV_REL, crate::REL_X, 12));
    assert_eq!(NATIVE_REL.load(Ordering::Acquire), (crate::REL_X as u32) << 16 | 12);
    assert!(!crate::push_evdev_event(evdev_id, crate::EV_REL, crate::REL_X, 0));
    assert_eq!(NATIVE_REL.load(Ordering::Acquire), (crate::REL_X as u32) << 16 | 12);

    crate::set_native_rel_hook(None);
    assert_eq!(crate::remove_device(key(0x00c0_0001)), Some(evdev_id));
}
