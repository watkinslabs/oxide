// Driver unbind/rebind identity and teardown ordering.
//
// The gate these encode: sysfs projection, the input remove uevent, and cached
// `inputN`/`eventN`/class path invalidation are all driven from the driver-core
// remove hook and all read the canonical input record by evdev minor. Dropping
// that record before the driver-model node is torn down makes every one of them
// a silent no-op, which leaves `/sys/class/input/eventN` pointing at the
// previous `inputN` parent and stops udev classifying the rebound device.
//
// The canonical input registry and the devfs slot table are separate process
// globals behind separate test locks; these tests mutate both, so every one of
// them takes both, always in that order.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::{key, FakeInputConfig, TEST_DEVICE_KEY_RAW, TEST_MUTEX};
use super::{TEST_TRANSPORT_VENDOR, TEST_VIRTIO_INPUT_DEVICE_ID};

/// Sentinel for "the remove hook never ran at all".
const NO_OBSERVATION: u32 = u32::MAX;

static HOOK_RAN: AtomicBool = AtomicBool::new(false);
static MODEL_LIVE_AT_REMOVE: AtomicBool = AtomicBool::new(false);
static INPUT_ID_AT_REMOVE: AtomicU32 = AtomicU32::new(NO_OBSERVATION);

fn observe_remove(dev: &drv::Device) {
    if dev.bus != "input" { return; }
    HOOK_RAN.store(true, Ordering::Relaxed);
    let Some((major, minor)) = dev.dev_t else { return; };
    if major != input::INPUT_MAJOR { return; }
    let Some(evdev_id) = minor.checked_sub(input::EVENT_MINOR_BASE) else { return; };
    match input::device(evdev_id) {
        Some(model) => {
            MODEL_LIVE_AT_REMOVE.store(true, Ordering::Relaxed);
            INPUT_ID_AT_REMOVE.store(model.input_id, Ordering::Relaxed);
        }
        None => MODEL_LIVE_AT_REMOVE.store(false, Ordering::Relaxed),
    }
}

fn ignore_remove(_dev: &drv::Device) {}

fn parent_device(addr: &str) -> alloc::sync::Arc<drv::Device> {
    let parent = alloc::sync::Arc::new(drv::Device::new(
        "virtio",
        alloc::string::String::from(addr),
        TEST_TRANSPORT_VENDOR,
        TEST_VIRTIO_INPUT_DEVICE_ID,
        0,
    ));
    drv::try_device_add(alloc::sync::Arc::clone(&parent)).expect("virtio parent registration");
    parent
}

fn bind(parent: &alloc::sync::Arc<drv::Device>) -> u32 {
    let mut cfg = FakeInputConfig::new();
    let evdev_id = crate::registry::prepare_device_with_config_and_parent_for_tests(
        key(TEST_DEVICE_KEY_RAW),
        &mut cfg,
        Some(parent),
    )
    .expect("canonical input preparation");
    assert!(crate::publish_device_node(evdev_id, Some(parent)));
    evdev_id
}

#[test]
fn unbind_tears_the_model_node_down_while_the_canonical_record_is_still_live() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _nodes = crate::devfs::tests::serialize();
    crate::registry::clear_devices_for_tests();
    HOOK_RAN.store(false, Ordering::Relaxed);
    MODEL_LIVE_AT_REMOVE.store(false, Ordering::Relaxed);
    INPUT_ID_AT_REMOVE.store(NO_OBSERVATION, Ordering::Relaxed);
    drv::set_sysfs_remove_hook(observe_remove);

    let parent = parent_device("virtio0");
    let evdev_id = bind(&parent);
    let input_id = input::device(evdev_id).expect("canonical model").input_id;

    assert_eq!(crate::remove_device_with_node(key(TEST_DEVICE_KEY_RAW)), Some(evdev_id));

    drv::set_sysfs_remove_hook(ignore_remove);
    assert!(HOOK_RAN.load(Ordering::Relaxed), "driver-core remove hook never ran");
    assert!(
        MODEL_LIVE_AT_REMOVE.load(Ordering::Relaxed),
        "canonical record was already gone when sysfs teardown ran",
    );
    assert_eq!(INPUT_ID_AT_REMOVE.load(Ordering::Relaxed), input_id);
    assert!(input::device(evdev_id).is_none(), "record outlived removal");

    drv::device_del(&parent);
    crate::registry::clear_devices_for_tests();
}

#[test]
fn rebind_mints_a_new_input_index_and_reuses_the_evdev_minor() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _nodes = crate::devfs::tests::serialize();
    crate::registry::clear_devices_for_tests();
    drv::set_sysfs_remove_hook(ignore_remove);

    let parent = parent_device("virtio0");
    let first_evdev = bind(&parent);
    let first_input = input::device(first_evdev).expect("first model").input_id;

    assert_eq!(crate::remove_device_with_node(key(TEST_DEVICE_KEY_RAW)), Some(first_evdev));

    let second_evdev = bind(&parent);
    let second_input = input::device(second_evdev).expect("second model").input_id;

    // The evdev minor is a bounded lowest-free allocation, so a rebind of the
    // only device reclaims it; the input index is monotonic and never recycled.
    assert_eq!(second_evdev, first_evdev);
    assert!(second_input > first_input, "input index was recycled across rebind");

    assert_eq!(crate::remove_device_with_node(key(TEST_DEVICE_KEY_RAW)), Some(second_evdev));
    drv::device_del(&parent);
    crate::registry::clear_devices_for_tests();
}

#[test]
fn concurrently_installed_devices_never_share_an_identity() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _nodes = crate::devfs::tests::serialize();
    crate::registry::clear_devices_for_tests();

    let first = crate::install(super::test_dev(key(TEST_DEVICE_KEY_RAW)))
        .expect("install first model");
    let second = crate::install(super::test_dev(key(super::SECOND_TEST_DEVICE_KEY_RAW)))
        .expect("install second model");

    assert_ne!(first.0, second.0, "distinct devices shared an input index");
    assert_ne!(first.1, second.1, "distinct devices shared an evdev minor");

    // Reinstalling after the first is gone reuses its minor but not its index.
    assert_eq!(crate::remove_device(key(TEST_DEVICE_KEY_RAW)), Some(first.1));
    let third = crate::install(super::test_dev(key(TEST_DEVICE_KEY_RAW)))
        .expect("reinstall first model");
    assert_eq!(third.1, first.1);
    assert!(third.0 > second.0);

    crate::registry::clear_devices_for_tests();
}

#[test]
fn disconnect_flushes_through_the_live_handler_and_keeps_the_record_installed() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _nodes = crate::devfs::tests::serialize();
    crate::registry::clear_devices_for_tests();

    let (_, evdev_id) = crate::install(super::test_dev(key(TEST_DEVICE_KEY_RAW)))
        .expect("install model");

    assert_eq!(input::disconnect_device(key(TEST_DEVICE_KEY_RAW)), Some(evdev_id));
    assert!(
        input::device(evdev_id).is_some(),
        "disconnect must leave the record projectable for sysfs teardown",
    );
    // Idempotent: the driver runs it once explicitly and `remove_device` again.
    assert_eq!(input::disconnect_device(key(TEST_DEVICE_KEY_RAW)), Some(evdev_id));
    assert_eq!(crate::remove_device(key(TEST_DEVICE_KEY_RAW)), Some(evdev_id));
    assert!(input::device(evdev_id).is_none());
    assert_eq!(input::disconnect_device(key(TEST_DEVICE_KEY_RAW)), None);

    crate::registry::clear_devices_for_tests();
}
