use super::*;

const PACKET_DEVICE_KEY: u32 = 0x00b0_0000;
const ABS_DEVICE_KEY: u32 = 0x00b0_0010;
const MT_DEVICE_KEY: u32 = 0x00b0_0020;
const REPEAT_DEVICE_KEY: u32 = 0x00b0_0030;
const OUTPUT_DEVICE_KEY: u32 = 0x00b0_0040;
const OUTPUT_REPLACEMENT_KEY: u32 = 0x00b0_0041;
const KEY_RELEASED: i32 = 0;
const KEY_PRESSED: i32 = 1;
const KEY_REPEAT: i32 = 2;
const SYNTHETIC_SYNC: i32 = 1;

fn install_hooked(mut dev: alloc::boxed::Box<VirtioInputDev>) -> (u32, u32) {
    advertise(&mut dev.ev_bits, crate::EV_SYN);
    crate::set_evdev_hooks(EvdevHooks {
        register: None,
        unregister: None,
        push_packet: Some(record_packet),
    });
    install(dev).expect("install event model")
}

fn reset_events() {
    crate::registry::clear_devices_for_tests();
    PUSHED_EVENTS.lock().unwrap_or_else(|err| err.into_inner()).clear();
    PACKET_LENGTHS.lock().unwrap_or_else(|err| err.into_inner()).clear();
}

fn pushed() -> std::vec::Vec<(u32, u16, u16, i32)> {
    PUSHED_EVENTS.lock().unwrap_or_else(|err| err.into_inner()).clone()
}

#[test]
fn handlers_receive_only_complete_synchronization_packets() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    reset_events();
    let device_key = key(PACKET_DEVICE_KEY);
    let mut dev = test_dev(device_key);
    advertise(&mut dev.ev_bits, crate::EV_KEY);
    let (_, evdev_id) = install_hooked(dev);

    assert!(crate::push_evdev_event(
        evdev_id, crate::EV_KEY, TEST_KEY_CODE, KEY_PRESSED,
    ));
    assert!(pushed().is_empty(), "partial packet is not visible");
    assert!(crate::push_evdev_event(
        evdev_id, crate::EV_SYN, crate::SYN_REPORT, 0,
    ));
    assert_eq!(
        pushed(),
        std::vec![
            (evdev_id, crate::EV_KEY, TEST_KEY_CODE, KEY_PRESSED),
            (evdev_id, crate::EV_SYN, crate::SYN_REPORT, 0),
        ],
    );
    assert_eq!(
        PACKET_LENGTHS.lock().unwrap_or_else(|err| err.into_inner()).as_slice(),
        &[2],
        "one completed frame is one handler transaction",
    );

    assert_eq!(remove_device(device_key), Some(evdev_id));
}

#[test]
fn absolute_values_are_defuzzed_and_unchanged_values_are_suppressed() {
    const ABS_X: u16 = 0;
    const ABS_MAXIMUM: u32 = 1024;
    const ABS_FUZZ: u32 = 4;
    const ABS_RESOLUTION: u32 = 1;
    const FIRST_VALUE: i32 = 100;
    const WITHIN_FUZZ_VALUE: i32 = 101;

    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    reset_events();
    let device_key = key(ABS_DEVICE_KEY);
    let mut dev = VirtioInputDev::empty_boxed(device_key);
    advertise(&mut dev.ev_bits, crate::EV_ABS);
    advertise(&mut dev.abs_bits.bits, ABS_X);
    dev.abs_info[ABS_X as usize] = Some(VirtioInputAbsInfo {
        min: 0,
        max: ABS_MAXIMUM,
        fuzz: ABS_FUZZ,
        flat: 0,
        res: ABS_RESOLUTION,
    });
    let (_, evdev_id) = install_hooked(dev);

    assert!(crate::push_evdev_event(
        evdev_id, crate::EV_ABS, ABS_X, FIRST_VALUE,
    ));
    assert!(crate::push_evdev_event(
        evdev_id, crate::EV_SYN, crate::SYN_REPORT, 0,
    ));
    assert!(!crate::push_evdev_event(
        evdev_id, crate::EV_ABS, ABS_X, WITHIN_FUZZ_VALUE,
    ));
    assert!(crate::push_evdev_event(
        evdev_id, crate::EV_SYN, crate::SYN_REPORT, 0,
    ));
    assert_eq!(
        pushed().last(),
        Some(&(evdev_id, crate::EV_SYN, crate::SYN_REPORT, 0)),
        "an empty synchronization frame remains observable",
    );
    assert_eq!(
        device(evdev_id).and_then(|model| model.abs_value(ABS_X)),
        Some(FIRST_VALUE),
    );

    assert_eq!(remove_device(device_key), Some(evdev_id));
}

#[test]
fn type_b_multitouch_stages_slots_and_inhibit_releases_contacts() {
    const TRACKING_ID: i32 = 77;
    const SELECTED_SLOT: i32 = 1;
    const LAST_SLOT: u32 = 1;
    const INACTIVE_TRACKING_ID: i32 = -1;

    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    reset_events();
    let device_key = key(MT_DEVICE_KEY);
    let mut dev = VirtioInputDev::empty_boxed(device_key);
    advertise(&mut dev.ev_bits, crate::EV_ABS);
    for code in [crate::ABS_MT_SLOT, crate::ABS_MT_TRACKING_ID] {
        advertise(&mut dev.abs_bits.bits, code);
    }
    dev.abs_info[crate::ABS_MT_SLOT as usize] = Some(VirtioInputAbsInfo {
        min: 0,
        max: LAST_SLOT,
        fuzz: 0,
        flat: 0,
        res: 0,
    });
    dev.abs_info[crate::ABS_MT_TRACKING_ID as usize] = Some(VirtioInputAbsInfo {
        min: u32::MAX,
        max: i32::MAX as u32,
        fuzz: 0,
        flat: 0,
        res: 0,
    });
    let (input_id, evdev_id) = install_hooked(dev);

    assert!(!crate::push_evdev_event(
        evdev_id, crate::EV_ABS, crate::ABS_MT_SLOT, SELECTED_SLOT,
    ));
    assert!(crate::push_evdev_event(
        evdev_id, crate::EV_ABS, crate::ABS_MT_TRACKING_ID, TRACKING_ID,
    ));
    assert!(crate::push_evdev_event(
        evdev_id, crate::EV_SYN, crate::SYN_REPORT, 0,
    ));
    assert_eq!(
        pushed(),
        std::vec![
            (evdev_id, crate::EV_ABS, crate::ABS_MT_SLOT, SELECTED_SLOT),
            (
                evdev_id,
                crate::EV_ABS,
                crate::ABS_MT_TRACKING_ID,
                TRACKING_ID,
            ),
            (evdev_id, crate::EV_SYN, crate::SYN_REPORT, 0),
        ],
    );

    assert!(crate::set_inhibited_by_identity(
        device_key, input_id, evdev_id, true,
    ).is_some());
    assert_eq!(
        &pushed()[3..],
        &[
            (
                evdev_id,
                crate::EV_ABS,
                crate::ABS_MT_TRACKING_ID,
                INACTIVE_TRACKING_ID,
            ),
            (evdev_id, crate::EV_SYN, crate::SYN_REPORT, SYNTHETIC_SYNC),
        ],
    );

    assert_eq!(remove_device(device_key), Some(evdev_id));
}

#[test]
fn software_repeat_arms_on_packet_delivery_and_stops_on_release() {
    const MSEC_NS: u64 = 1_000_000;
    const SECOND_KEY_CODE: u16 = TEST_KEY_CODE + 1;

    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    reset_events();
    crate::repeat::set_now_for_tests(0);
    let device_key = key(REPEAT_DEVICE_KEY);
    let mut dev = test_dev(device_key);
    for ev_type in [crate::EV_KEY, crate::EV_REP] {
        advertise(&mut dev.ev_bits, ev_type);
    }
    advertise(&mut dev.key_bits.bits, SECOND_KEY_CODE);
    let (_, evdev_id) = install_hooked(dev);

    assert!(crate::push_evdev_event(
        evdev_id, crate::EV_KEY, TEST_KEY_CODE, KEY_PRESSED,
    ));
    assert!(crate::push_evdev_event(
        evdev_id, crate::EV_SYN, crate::SYN_REPORT, 0,
    ));
    let delay_ns = u64::from(DEFAULT_REPEAT[crate::REP_DELAY as usize]) * MSEC_NS;
    timer::run_due(delay_ns.saturating_sub(1));
    assert_eq!(pushed().len(), 2);

    crate::repeat::set_now_for_tests(delay_ns);
    timer::run_due(delay_ns);
    assert_eq!(
        &pushed()[2..],
        &[
            (evdev_id, crate::EV_KEY, TEST_KEY_CODE, KEY_REPEAT),
            (evdev_id, crate::EV_SYN, crate::SYN_REPORT, SYNTHETIC_SYNC),
        ],
    );

    assert!(crate::push_evdev_event(
        evdev_id, crate::EV_KEY, SECOND_KEY_CODE, KEY_PRESSED,
    ));
    assert!(crate::push_evdev_event(
        evdev_id, crate::EV_SYN, crate::SYN_REPORT, 0,
    ));
    assert!(crate::push_evdev_event(
        evdev_id, crate::EV_KEY, TEST_KEY_CODE, KEY_RELEASED,
    ));
    assert!(crate::push_evdev_event(
        evdev_id, crate::EV_SYN, crate::SYN_REPORT, 0,
    ));
    let second_deadline = delay_ns.saturating_add(delay_ns);
    crate::repeat::set_now_for_tests(second_deadline);
    timer::run_due(second_deadline);
    let events = pushed();
    assert_eq!(
        &events[events.len() - 2..],
        &[
            (evdev_id, crate::EV_KEY, SECOND_KEY_CODE, KEY_REPEAT),
            (evdev_id, crate::EV_SYN, crate::SYN_REPORT, SYNTHETIC_SYNC),
        ],
        "releasing a different key does not cancel the active repeat key",
    );
    assert!(crate::push_evdev_event(
        evdev_id, crate::EV_KEY, SECOND_KEY_CODE, KEY_RELEASED,
    ));
    assert!(crate::push_evdev_event(
        evdev_id, crate::EV_SYN, crate::SYN_REPORT, 0,
    ));
    let after_release = pushed().len();
    let period_ns = u64::from(DEFAULT_REPEAT[crate::REP_PERIOD as usize]) * MSEC_NS;
    crate::repeat::set_now_for_tests(second_deadline + period_ns);
    timer::run_due(second_deadline + period_ns);
    assert_eq!(pushed().len(), after_release);

    assert_eq!(remove_device(device_key), Some(evdev_id));
}

#[test]
fn exact_identity_snapshots_and_output_reject_recycled_evdev_ids() {
    const ABS_X: u16 = 0;
    const LED_CAPSL: u16 = 1;
    const SND_BELL: u16 = 1;
    const SEEDED_X: i32 = 41;
    const ABS_MINIMUM: i32 = -10;
    const ABS_MAXIMUM: u32 = 100;
    const ABS_FUZZ: u32 = 2;
    const ABS_FLAT: u32 = 1;
    const ABS_RESOLUTION: u32 = 4;
    const UPDATED_REPEAT: crate::RepeatSettings = [400, 40];
    const OUTPUT_REPEAT_DELAY: i32 = 350;

    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    reset_events();
    OUTPUT_BATCHES.lock().unwrap_or_else(|err| err.into_inner()).clear();
    let device_key = key(OUTPUT_DEVICE_KEY);
    let mut dev = VirtioInputDev::empty_boxed(device_key);
    for ev_type in [crate::EV_ABS, crate::EV_LED, crate::EV_SND, crate::EV_REP] {
        advertise(&mut dev.ev_bits, ev_type);
    }
    advertise(&mut dev.abs_bits.bits, ABS_X);
    advertise(&mut dev.led_bits.bits, LED_CAPSL);
    advertise(&mut dev.snd_bits.bits, SND_BELL);
    let parameters = VirtioInputAbsInfo {
        min: ABS_MINIMUM as u32,
        max: ABS_MAXIMUM,
        fuzz: ABS_FUZZ,
        flat: ABS_FLAT,
        res: ABS_RESOLUTION,
    };
    dev.abs_info[ABS_X as usize] = Some(parameters);
    assert!(dev.seed_abs_value(ABS_X, SEEDED_X));
    let (input_id, evdev_id) = install(dev).expect("install exact-identity model");

    assert_eq!(
        crate::abs_snapshot_by_identity(device_key, input_id, evdev_id, ABS_X),
        Some(crate::AbsSnapshot { value: SEEDED_X, parameters }),
    );
    assert!(crate::set_repeat_by_identity(
        device_key, input_id, evdev_id, UPDATED_REPEAT,
    ));
    assert_eq!(
        crate::repeat_by_identity(device_key, input_id, evdev_id),
        Some(UPDATED_REPEAT),
    );

    let requested = crate::OutputBatch {
        events: alloc::vec![
            crate::OutputEvent {
                ev_type: crate::EV_LED,
                code: LED_CAPSL,
                value: KEY_PRESSED,
            },
            crate::OutputEvent {
                ev_type: crate::EV_SND,
                code: SND_BELL,
                value: KEY_PRESSED,
            },
            crate::OutputEvent {
                ev_type: crate::EV_REP,
                code: crate::REP_DELAY,
                value: OUTPUT_REPEAT_DELAY,
            },
            crate::OutputEvent {
                ev_type: crate::EV_KEY,
                code: TEST_KEY_CODE,
                value: KEY_PRESSED,
            },
        ],
    };
    assert_eq!(
        crate::apply_output_by_identity(device_key, input_id, evdev_id, &requested),
        None,
        "canonical output is not committed without a durable transport sink",
    );
    assert_eq!(
        crate::repeat_by_identity(device_key, input_id, evdev_id),
        Some(UPDATED_REPEAT),
    );
    crate::set_output_hook(record_output);
    let accepted = crate::apply_output_by_identity(
        device_key, input_id, evdev_id, &requested,
    ).expect("exact output transaction");
    assert_eq!(accepted.events.len(), 3, "non-output events are not committed");
    assert_eq!(
        crate::repeat_by_identity(device_key, input_id, evdev_id),
        Some([OUTPUT_REPEAT_DELAY as u32, UPDATED_REPEAT[crate::REP_PERIOD as usize]]),
    );
    assert_eq!(
        OUTPUT_BATCHES.lock().unwrap_or_else(|err| err.into_inner()).as_slice(),
        &[(
            device_key.raw(),
            alloc::vec![
                (crate::EV_LED, LED_CAPSL, KEY_PRESSED),
                (crate::EV_SND, SND_BELL, KEY_PRESSED),
                (crate::EV_REP, crate::REP_DELAY, OUTPUT_REPEAT_DELAY),
            ],
        )],
    );
    let inhibited = crate::set_inhibited_by_identity(
        device_key, input_id, evdev_id, true,
    ).expect("inhibit exact output model");
    assert_eq!(
        inhibited.events,
        alloc::vec![
            crate::OutputEvent {
                ev_type: crate::EV_LED,
                code: LED_CAPSL,
                value: 0,
            },
            crate::OutputEvent {
                ev_type: crate::EV_SND,
                code: SND_BELL,
                value: 0,
            },
        ],
        "inhibit explicitly turns every advertised output off",
    );
    let restored = crate::set_inhibited_by_identity(
        device_key, input_id, evdev_id, false,
    ).expect("uninhibit exact output model");
    assert_eq!(
        restored.events,
        alloc::vec![
            crate::OutputEvent {
                ev_type: crate::EV_LED,
                code: LED_CAPSL,
                value: KEY_PRESSED,
            },
            crate::OutputEvent {
                ev_type: crate::EV_SND,
                code: SND_BELL,
                value: KEY_PRESSED,
            },
            crate::OutputEvent {
                ev_type: crate::EV_REP,
                code: crate::REP_PERIOD,
                value: UPDATED_REPEAT[crate::REP_PERIOD as usize] as i32,
            },
            crate::OutputEvent {
                ev_type: crate::EV_REP,
                code: crate::REP_DELAY,
                value: OUTPUT_REPEAT_DELAY,
            },
        ],
        "uninhibit restores canonical output and repeat state",
    );

    assert_eq!(remove_device(device_key), Some(evdev_id));
    let replacement_key = key(OUTPUT_REPLACEMENT_KEY);
    let (replacement_input_id, replacement_evdev_id) =
        install(test_dev(replacement_key)).expect("replacement exact-identity model");
    assert_eq!(replacement_evdev_id, evdev_id);
    assert!(replacement_input_id > input_id);
    assert_eq!(
        crate::repeat_by_identity(device_key, input_id, evdev_id),
        None,
    );
    assert!(!crate::set_repeat_by_identity(
        device_key, input_id, evdev_id, [1, 1],
    ));
    assert_eq!(
        crate::apply_output_by_identity(device_key, input_id, evdev_id, &requested),
        None,
    );
    assert_eq!(remove_device(replacement_key), Some(replacement_evdev_id));
}
