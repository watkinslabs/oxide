use super::*;

const ROUND_TRIP_DEVICE_KEY: u32 = 0x0010_0000;
const KEYBOARD_DEVICE_KEY: u32 = 0x0030_0000;
const POINTER_DEVICE_KEY: u32 = 0x0040_0000;
const REPEAT_DEVICE_KEY: u32 = 0x0050_0000;
const FIRST_DEVICE_KEY: u32 = 0x0070_0000;
const SECOND_DEVICE_KEY: u32 = 0x0070_0001;
const CONCURRENT_DEVICE_KEY_BASE: u32 = 0x0090_0000;
const UPDATED_REPEAT: crate::RepeatSettings = [400, 20];

#[test]
fn install_snapshot_remove_round_trips_device() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    crate::registry::clear_devices_for_tests();
    let device_key = key(ROUND_TRIP_DEVICE_KEY);
    let (_, evdev_id) = install(test_dev(device_key)).expect("install test model");
    assert_eq!(count(), 1);
    assert_eq!(evdev_id_for_device(device_key), Some(evdev_id));
    assert_eq!(device(evdev_id).expect("installed model").name_len, TEST_NAME.len());
    assert_eq!(remove_device(device_key), Some(evdev_id));
    assert_eq!(evdev_id_for_device(device_key), None);
}

#[test]
fn multiple_input_records_remain_independent() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    crate::registry::clear_devices_for_tests();
    let keyboard = key(KEYBOARD_DEVICE_KEY);
    let pointer = key(POINTER_DEVICE_KEY);
    let (_, keyboard_evdev) = install(test_dev(keyboard)).expect("install keyboard");
    let (_, pointer_evdev) = install(test_dev(pointer)).expect("install pointer");
    assert_eq!(count(), 2);
    assert_eq!(evdev_id_for_device(keyboard), Some(keyboard_evdev));
    assert_eq!(evdev_id_for_device(pointer), Some(pointer_evdev));
    assert_eq!(remove_device(keyboard), Some(keyboard_evdev));
    assert_eq!(evdev_id_for_device(pointer), Some(pointer_evdev));
}

#[test]
fn repeat_state_is_keyed_by_exact_input_identity() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    crate::registry::clear_devices_for_tests();
    let device_key = key(REPEAT_DEVICE_KEY);
    let (input_id, evdev_id) = install(test_dev(device_key)).expect("install repeat model");
    assert_eq!(
        crate::repeat_by_identity(device_key, input_id, evdev_id),
        Some(DEFAULT_REPEAT),
    );
    assert!(crate::set_repeat_by_identity(
        device_key, input_id, evdev_id, UPDATED_REPEAT,
    ));
    assert_eq!(
        crate::repeat_by_identity(device_key, input_id, evdev_id),
        Some(UPDATED_REPEAT),
    );
}

#[test]
fn install_rejects_duplicate_key_and_never_recycles_input_identity() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    crate::registry::clear_devices_for_tests();
    let first_key = key(FIRST_DEVICE_KEY);
    let (first_input, first_evdev) = install(test_dev(first_key)).expect("first model");
    assert!(install(test_dev(first_key)).is_none(), "duplicate key is rejected atomically");
    assert_eq!(remove_device(first_key), Some(first_evdev));

    let second_key = key(SECOND_DEVICE_KEY);
    let (second_input, second_evdev) = install(test_dev(second_key)).expect("second model");
    assert!(second_input > first_input, "inputN identity is monotonic");
    assert_eq!(second_evdev, first_evdev, "evdev minor may be reused after removal");
    assert_eq!(remove_device(second_key), Some(second_evdev));
}

#[test]
fn concurrent_installs_allocate_unique_identity_pairs() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    crate::registry::clear_devices_for_tests();
    let mut workers = std::vec::Vec::new();
    for index in 0..crate::MAX_INPUT_DEVICES as u32 {
        workers.push(std::thread::spawn(move || {
            install(test_dev(key(CONCURRENT_DEVICE_KEY_BASE + index))).expect("concurrent install")
        }));
    }
    let mut identities = workers.into_iter()
        .map(|worker| worker.join().expect("install worker"))
        .collect::<std::vec::Vec<_>>();
    identities.sort_unstable();
    assert_eq!(identities.len(), crate::MAX_INPUT_DEVICES);
    for pair in identities.windows(2) {
        assert_ne!(pair[0].0, pair[1].0, "inputN collision");
    }
    let mut evdev = identities.iter().map(|(_, id)| *id).collect::<std::vec::Vec<_>>();
    evdev.sort_unstable();
    evdev.dedup();
    assert_eq!(evdev.len(), crate::MAX_INPUT_DEVICES, "eventN collision");
    crate::registry::clear_devices_for_tests();
}
