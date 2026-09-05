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
fn xinput_reads_one_canonical_controller_and_invalidates_on_disconnect() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    crate::clear_devices_for_tests();
    let device_key = key(0x00c0_0100);
    let mut dev = VirtioInputDev::empty_boxed(device_key);
    advertise(&mut dev.ev_bits, crate::EV_SYN);
    advertise(&mut dev.ev_bits, crate::EV_ABS);
    for axis in [crate::ABS_Z, crate::ABS_RZ, crate::ABS_X, crate::ABS_Y, crate::ABS_RX, crate::ABS_RY] {
        advertise(&mut dev.abs_bits.bits, axis);
        dev.abs_info[axis as usize] = Some(VirtioInputAbsInfo { min: 0, max: 200, fuzz: 0, flat: 0, res: 1 });
    }
    advertise(&mut dev.ev_bits, crate::EV_KEY);
    advertise(&mut dev.key_bits.bits, crate::BTN_SOUTH);
    let (_, evdev_id) = crate::install(dev).expect("controller model");
    for (axis, value) in [(crate::ABS_Z, 100), (crate::ABS_RZ, 200), (crate::ABS_X, 100),
                           (crate::ABS_Y, 50), (crate::ABS_RX, 200), (crate::ABS_RY, 150)] {
        assert!(crate::push_evdev_event(evdev_id, crate::EV_ABS, axis, value));
    }
    assert!(crate::push_evdev_event(evdev_id, crate::EV_KEY, crate::BTN_SOUTH, 1));
    assert!(crate::push_evdev_event(evdev_id, crate::EV_SYN, crate::SYN_REPORT, 0));
    let state = crate::controller_state(0).expect("connected controller");
    assert_eq!(state.packet_number, 1);
    assert_eq!(state.gamepad.buttons, 0x1000);
    assert_eq!(state.gamepad.left_trigger, 128);
    assert_eq!(state.gamepad.right_trigger, 255);
    assert_eq!(state.gamepad.thumb_lx, 0);
    assert_eq!(state.gamepad.thumb_ly, 16384);
    assert_eq!(crate::controller_state(crate::XINPUT_MAX_CONTROLLERS),
        Err(crate::ControllerError::InvalidIndex));
    assert_eq!(crate::disconnect_device(device_key), Some(evdev_id));
    assert_eq!(crate::controller_state(0), Err(crate::ControllerError::DeviceNotConnected));
    assert_eq!(crate::remove_device(device_key), Some(evdev_id));
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

#[test]
fn raw_queue_preserves_keyboard_and_mouse_classes_from_one_device() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    crate::registry::clear_devices_for_tests();
    let mut dev = test_dev(key(0x00c0_0002));
    advertise(&mut dev.ev_bits, crate::EV_KEY);
    advertise(&mut dev.ev_bits, crate::EV_REL);
    advertise(&mut dev.key_bits.bits, crate::BTN_LEFT);
    advertise(&mut dev.rel_bits.bits, crate::REL_X);
    let (_, evdev_id) = crate::install(dev).expect("install raw input device");

    assert!(crate::push_evdev_event(evdev_id, crate::EV_KEY, TEST_KEY_CODE, 1));
    assert!(crate::push_evdev_event(evdev_id, crate::EV_KEY, crate::BTN_LEFT, 1));
    assert!(crate::push_evdev_event(evdev_id, crate::EV_REL, crate::REL_X, -7));
    let events = crate::take_raw_input(evdev_id, usize::MAX).expect("live device");
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].kind, crate::RawInputKind::Keyboard);
    assert_eq!(events[0].device_id, evdev_id);
    assert_eq!(events[1].kind, crate::RawInputKind::Mouse);
    assert_eq!(events[2].kind, crate::RawInputKind::Mouse);
    assert_eq!(events[2].value, -7);
    assert!(crate::take_raw_input(evdev_id, 1).is_some_and(|events| events.is_empty()));
    assert_eq!(crate::remove_device(key(0x00c0_0002)), Some(evdev_id));
}

#[test]
fn raw_queue_reports_overflow_and_drops_newest_without_corrupting_owner() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    crate::registry::clear_devices_for_tests();
    let mut dev = test_dev(key(0x00c0_0003));
    advertise(&mut dev.ev_bits, crate::EV_REL);
    advertise(&mut dev.rel_bits.bits, crate::REL_X);
    let (_, evdev_id) = crate::install(dev).expect("install raw input device");
    for _ in 0..256 { assert!(crate::push_evdev_event(evdev_id, crate::EV_REL, crate::REL_X, 1)); }
    assert!(crate::push_evdev_event(evdev_id, crate::EV_REL, crate::REL_X, 2));
    assert_eq!(crate::raw_input_dropped(evdev_id), Some(1));
    let events = crate::take_raw_input(evdev_id, usize::MAX).expect("live device");
    assert_eq!(events.len(), 256);
    assert!(events.iter().all(|event| event.value == 1));
    assert_eq!(crate::remove_device(key(0x00c0_0003)), Some(evdev_id));
}

#[test]
fn raw_queue_rejects_invalid_devices_and_is_invalidated_on_disconnect() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    crate::registry::clear_devices_for_tests();
    assert!(crate::take_raw_input(u32::MAX, 1).is_none());
    assert!(crate::raw_input_dropped(u32::MAX).is_none());
    let mut dev = test_dev(key(0x00c0_0004));
    advertise(&mut dev.ev_bits, crate::EV_REL);
    advertise(&mut dev.rel_bits.bits, crate::REL_X);
    let (_, evdev_id) = crate::install(dev).expect("install raw input device");
    assert!(crate::push_evdev_event(evdev_id, crate::EV_REL, crate::REL_X, 4));
    assert_eq!(crate::disconnect_device(key(0x00c0_0004)), Some(evdev_id));
    assert!(crate::take_raw_input(evdev_id, 1).is_some_and(|events| events.is_empty()));
    assert_eq!(crate::remove_device(key(0x00c0_0004)), Some(evdev_id));
    assert!(crate::take_raw_input(evdev_id, 1).is_none());
}
