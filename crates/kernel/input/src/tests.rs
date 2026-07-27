use crate::{
    count, device, evdev_id_for_device, install, remove_device, repeat, set_repeat, CapBitmap,
    InputEvent, VirtioInputAbsInfo, VirtioInputDev, VirtioInputDevIds, VirtioInputEvent,
    DEFAULT_REPEAT,
};

const TEST_NAME: &[u8] = b"oxide-input";
const TEST_SERIAL: &[u8] = b"input-serial";

fn key(raw: u32) -> virtio::VirtioChildDeviceKey {
    virtio::VirtioChildDeviceKey::from_raw(raw)
}

fn test_dev(device_key: virtio::VirtioChildDeviceKey, evdev_id: u32) -> VirtioInputDev {
    let mut dev = VirtioInputDev::empty(device_key, evdev_id);
    dev.is_pointer = true;
    dev.name[..TEST_NAME.len()].copy_from_slice(TEST_NAME);
    dev.name_len = TEST_NAME.len();
    dev.serial[..TEST_SERIAL.len()].copy_from_slice(TEST_SERIAL);
    dev.serial_len = TEST_SERIAL.len();
    dev.key_bits.bits[3] = 0x40;
    dev.repeat = DEFAULT_REPEAT;
    dev
}

// `crate::registry` is a process-global input-device table — a singleton by
// design, exactly as the real kernel has one. Tests that call
// `clear_devices_for_tests()` and then assert `count()` therefore cannot own
// their state; serialising is the only correct option short of inventing a
// per-test registry in the kernel.
static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn virtio_input_event_layout_matches_wire() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(core::mem::size_of::<VirtioInputEvent>(), 8);
}

#[test]
fn virtio_abs_info_layout_matches_wire() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(core::mem::size_of::<VirtioInputAbsInfo>(), 20);
}

#[test]
fn virtio_device_id_layout_matches_wire() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(core::mem::size_of::<VirtioInputDevIds>(), 8);
}

#[test]
fn evdev_input_event_layout_matches_linux_abi() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(core::mem::size_of::<InputEvent>(), 24);
}

#[test]
fn cap_bitmap_default_covers_linux_key_count() {
    let bits = CapBitmap::default();
    assert_eq!(bits.bits.len(), 96);
}

#[test]
fn install_snapshot_remove_round_trips_device() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    crate::registry::clear_devices_for_tests();
    let dev = test_dev(key(0x0010_0000), 3);
    install(dev);
    assert_eq!(count(), 1);
    assert_eq!(evdev_id_for_device(key(0x0010_0000)), Some(3));
    assert_eq!(device(3).unwrap().name_len, TEST_NAME.len());
    assert_eq!(remove_device(key(0x0010_0000)), Some(3));
    assert_eq!(evdev_id_for_device(key(0x0010_0000)), None);
}

#[test]
fn multiple_input_records_remain_independent() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    crate::registry::clear_devices_for_tests();
    let keyboard = key(0x0030_0000);
    let pointer = key(0x0040_0000);
    install(test_dev(keyboard, 0));
    install(test_dev(pointer, 1));
    assert_eq!(count(), 2);
    assert_eq!(evdev_id_for_device(keyboard), Some(0));
    assert_eq!(evdev_id_for_device(pointer), Some(1));
    assert_eq!(remove_device(keyboard), Some(0));
    assert_eq!(evdev_id_for_device(pointer), Some(1));
}

#[test]
fn repeat_state_is_keyed_by_evdev_device() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    crate::registry::clear_devices_for_tests();
    install(test_dev(key(0x0050_0000), 2));
    assert_eq!(repeat(2), Some(DEFAULT_REPEAT));
    assert!(set_repeat(2, [400, 20]));
    assert_eq!(repeat(2), Some([400, 20]));
    assert!(!set_repeat(9, [1, 1]));
}
