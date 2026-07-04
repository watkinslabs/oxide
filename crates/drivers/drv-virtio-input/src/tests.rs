use crate::{
    count, evdev_id_for_device, install, remove_device, repeat, set_repeat, CapBitmap,
    VirtioInputAbsInfo, VirtioInputDev, VirtioInputDevIds, VirtioInputEvent, DEFAULT_REPEAT,
};

fn key(raw: u32) -> virtio::VirtioChildDeviceKey {
    virtio::VirtioChildDeviceKey::from_raw(raw)
}

fn test_dev(device_key: virtio::VirtioChildDeviceKey, evdev_id: u32) -> VirtioInputDev {
    VirtioInputDev {
        device_key,
        evdev_id,
        is_pointer: false,
        name: [0; 128],
        name_len: 0,
        serial: [0; 128],
        serial_len: 0,
        ids: VirtioInputDevIds::default(),
        ev_bits: [0; 32],
        key_bits: CapBitmap::default(),
        rel_bits: CapBitmap::default(),
        abs_bits: CapBitmap::default(),
        led_bits: CapBitmap::default(),
        abs_info: [None; 64],
        prop_bits: [0; 4],
        repeat: DEFAULT_REPEAT,
    }
}

#[test]
fn event_layout() {
    assert_eq!(core::mem::size_of::<VirtioInputEvent>(), 8);
}

#[test]
fn absinfo_layout() {
    assert_eq!(core::mem::size_of::<VirtioInputAbsInfo>(), 20);
}

#[test]
fn devids_layout() {
    assert_eq!(core::mem::size_of::<VirtioInputDevIds>(), 8);
}

#[test]
fn install_count_roundtrip() {
    crate::registry::clear_devices_for_tests();
    assert_eq!(count(), 0);
    install(test_dev(key(0), 0));
    assert_eq!(count(), 1);
    crate::registry::clear_devices_for_tests();
}

#[test]
fn lookup_and_remove_use_typed_child_key() {
    crate::registry::clear_devices_for_tests();
    install(test_dev(key(0x0010_0000), 3));
    install(test_dev(key(0x0020_0000), 4));

    assert_eq!(evdev_id_for_device(key(0x0010_0000)), Some(3));
    assert_eq!(remove_device(key(0x0010_0000)), Some(3));
    assert_eq!(evdev_id_for_device(key(0x0010_0000)), None);
    assert_eq!(evdev_id_for_device(key(0x0020_0000)), Some(4));

    crate::registry::clear_devices_for_tests();
}

#[test]
fn repeat_state_is_keyed_by_evdev_device() {
    crate::registry::clear_devices_for_tests();
    install(test_dev(key(0x0010_0000), 3));
    assert_eq!(repeat(3), Some(DEFAULT_REPEAT));
    assert!(set_repeat(3, [400, 40]));
    assert_eq!(repeat(3), Some([400, 40]));
    assert_eq!(repeat(4), None);
    crate::registry::clear_devices_for_tests();
}
