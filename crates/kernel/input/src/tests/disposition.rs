use super::*;

const INHIBIT_DEVICE_KEY: u32 = 0x0050_0010;
const REPLACEMENT_DEVICE_KEY: u32 = 0x0050_0011;
const DISPOSITION_DEVICE_KEY: u32 = 0x0050_0020;
const KEY_A: u16 = TEST_KEY_CODE;
const KEY_B: u16 = TEST_KEY_CODE + 1;
const MSC_SCAN: u16 = 4;
const LED_CAPSL: u16 = 2;
const SND_TONE: u16 = 3;
const UNSUPPORTED_EVENT_TYPE: u16 = crate::EV_SW + 1;
const INVALID_SYN_CODE: u16 = crate::SYN_MT_REPORT + 1;
const KEY_RELEASED: i32 = 0;
const KEY_PRESSED: i32 = 1;
const KEY_REPEAT: i32 = 2;
const SYNTHETIC_SYNC: i32 = 1;
const REPEAT_DELAY_MS: i32 = 300;

#[test]
fn inhibit_filters_delivery_and_releases_pressed_keys() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    crate::registry::clear_devices_for_tests();
    PUSHED_EVENTS.lock().unwrap_or_else(|err| err.into_inner()).clear();
    crate::set_evdev_hooks(EvdevHooks {
        register: None,
        unregister: None,
        push_packet: Some(record_packet),
    });
    let device_key = key(INHIBIT_DEVICE_KEY);
    let mut dev = test_dev(device_key);
    advertise(&mut dev.ev_bits, crate::EV_KEY);
    let (input_id, evdev_id) = install(dev).expect("install inhibited model");

    assert_eq!(
        crate::inhibited_by_identity(device_key, input_id, evdev_id),
        Some(false),
    );
    assert!(crate::push_evdev_event(evdev_id, crate::EV_KEY, KEY_A, KEY_PRESSED));
    assert!(crate::set_inhibited_by_identity(
        device_key, input_id, evdev_id, true,
    ).is_some());
    assert_eq!(
        PUSHED_EVENTS.lock().unwrap_or_else(|err| err.into_inner()).as_slice(),
        &[
            (evdev_id, crate::EV_KEY, KEY_A, KEY_PRESSED),
            (evdev_id, crate::EV_KEY, KEY_A, KEY_RELEASED),
            (evdev_id, crate::EV_SYN, crate::SYN_REPORT, SYNTHETIC_SYNC),
        ],
    );
    assert!(!crate::push_evdev_event(evdev_id, crate::EV_KEY, KEY_A, KEY_PRESSED));
    assert!(crate::set_inhibited_by_identity(
        device_key, input_id, evdev_id, true,
    ).is_some(), "idempotent inhibit");
    assert_eq!(
        PUSHED_EVENTS.lock().unwrap_or_else(|err| err.into_inner()).len(),
        3,
    );
    assert!(crate::set_inhibited_by_identity(
        device_key, input_id, evdev_id, false,
    ).is_some());
    assert!(crate::push_evdev_event(evdev_id, crate::EV_KEY, KEY_A, KEY_PRESSED));

    assert_eq!(remove_device(device_key), Some(evdev_id));
    assert_eq!(
        &PUSHED_EVENTS.lock().unwrap_or_else(|err| err.into_inner())[4..],
        &[
            (evdev_id, crate::EV_KEY, KEY_A, KEY_RELEASED),
            (evdev_id, crate::EV_SYN, crate::SYN_REPORT, SYNTHETIC_SYNC),
        ],
    );
    let replacement_key = key(REPLACEMENT_DEVICE_KEY);
    let (replacement_input, replacement_evdev) =
        install(test_dev(replacement_key)).expect("replacement model");
    assert_eq!(replacement_evdev, evdev_id);
    assert!(crate::set_inhibited_by_identity(
        device_key, input_id, evdev_id, true,
    ).is_none());
    assert_eq!(
        crate::inhibited_by_identity(replacement_key, replacement_input, replacement_evdev),
        Some(false),
    );
    assert_eq!(remove_device(replacement_key), Some(replacement_evdev));
    crate::registry::clear_devices_for_tests();
}

#[test]
fn event_disposition_validates_capabilities_and_suppresses_unchanged_state() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    crate::registry::clear_devices_for_tests();
    PUSHED_EVENTS.lock().unwrap_or_else(|err| err.into_inner()).clear();
    crate::set_evdev_hooks(EvdevHooks {
        register: None,
        unregister: None,
        push_packet: Some(record_packet),
    });
    let device_key = key(DISPOSITION_DEVICE_KEY);
    let mut dev = test_dev(device_key);
    for ev_type in [
        crate::EV_KEY, crate::EV_REL, crate::EV_ABS, crate::EV_MSC, crate::EV_SW,
        crate::EV_LED, crate::EV_SND, crate::EV_REP, crate::EV_FF, crate::EV_PWR,
    ] {
        advertise(&mut dev.ev_bits, ev_type);
    }
    advertise(&mut dev.rel_bits.bits, 0);
    advertise(&mut dev.abs_bits.bits, 0);
    advertise(&mut dev.msc_bits.bits, MSC_SCAN);
    advertise(&mut dev.sw_bits.bits, 0);
    advertise(&mut dev.led_bits.bits, LED_CAPSL);
    advertise(&mut dev.snd_bits.bits, SND_TONE);
    advertise(&mut dev.ff_bits.bits, 0);
    let (_, evdev_id) = install(dev).expect("disposition model");

    assert!(!crate::push_evdev_event(
        evdev_id, UNSUPPORTED_EVENT_TYPE, 0, KEY_PRESSED,
    ));
    assert!(!crate::push_evdev_event(evdev_id, crate::EV_KEY, KEY_B, KEY_PRESSED));
    assert!(crate::push_evdev_event(evdev_id, crate::EV_KEY, KEY_A, KEY_PRESSED));
    assert!(!crate::push_evdev_event(evdev_id, crate::EV_KEY, KEY_A, KEY_PRESSED));
    assert!(crate::push_evdev_event(evdev_id, crate::EV_KEY, KEY_A, KEY_REPEAT));
    assert!(crate::push_evdev_event(evdev_id, crate::EV_KEY, KEY_A, KEY_RELEASED));
    assert!(!crate::push_evdev_event(evdev_id, crate::EV_KEY, KEY_A, KEY_RELEASED));
    assert!(!crate::push_evdev_event(evdev_id, crate::EV_REL, 0, 0));
    assert!(crate::push_evdev_event(evdev_id, crate::EV_REL, 0, 1));
    assert!(!crate::push_evdev_event(evdev_id, crate::EV_ABS, 1, 1));
    assert!(crate::push_evdev_event(evdev_id, crate::EV_ABS, 0, 1));
    assert!(crate::push_evdev_event(evdev_id, crate::EV_MSC, MSC_SCAN, 1));
    assert!(crate::push_evdev_event(evdev_id, crate::EV_SW, 0, 1));
    assert!(!crate::push_evdev_event(evdev_id, crate::EV_SW, 0, 1));
    assert!(crate::push_evdev_event(evdev_id, crate::EV_SW, 0, 0));
    assert!(crate::push_evdev_event(evdev_id, crate::EV_LED, LED_CAPSL, 1));
    assert!(!crate::push_evdev_event(evdev_id, crate::EV_LED, LED_CAPSL, 1));
    assert!(crate::push_evdev_event(evdev_id, crate::EV_LED, LED_CAPSL, 0));
    assert!(crate::push_evdev_event(evdev_id, crate::EV_SND, SND_TONE, 1));
    assert!(crate::push_evdev_event(evdev_id, crate::EV_SND, SND_TONE, 1));
    assert!(crate::push_evdev_event(
        evdev_id, crate::EV_REP, crate::REP_DELAY, REPEAT_DELAY_MS,
    ));
    assert!(!crate::push_evdev_event(
        evdev_id, crate::EV_REP, crate::REP_DELAY, REPEAT_DELAY_MS,
    ));
    assert!(!crate::push_evdev_event(evdev_id, crate::EV_REP, crate::REP_CNT as u16, 1));
    assert!(crate::push_evdev_event(evdev_id, crate::EV_FF, 0, 1));
    assert!(!crate::push_evdev_event(evdev_id, crate::EV_FF, 0, -1));
    assert!(crate::push_evdev_event(evdev_id, crate::EV_PWR, u16::MAX, 1));
    assert!(crate::push_evdev_event(evdev_id, crate::EV_SYN, crate::SYN_REPORT, 0));
    assert!(!crate::push_evdev_event(
        evdev_id, crate::EV_SYN, INVALID_SYN_CODE, 0,
    ));

    assert_eq!(remove_device(device_key), Some(evdev_id));
    crate::registry::clear_devices_for_tests();
}
