use super::super::*;
use super::support::{key, test_ctrlq, test_device, TEST_LOCK};
use core::sync::atomic::{AtomicU32, AtomicU64};

const FIRST_DEVICE_KEY: u32 = 0x0010_0000;
const FIRST_DEVICE_BDF: u32 = 0x0010_0000;
const SECOND_DEVICE_KEY: u32 = 0x0020_0000;
const SECOND_DEVICE_BDF: u32 = 0x0020_0000;
const DUPLICATE_DEVICE_BDF: u32 = 0x0020_0001;
const MISSING_DEVICE_BDF: u32 = 0x0030_0000;
const ALIASING_DEVICE_KEY: u32 = 0x00aa_0000;
const SECOND_DISPLAY_COUNT: u32 = 2;

#[test]
fn install_and_lookup_roundtrip() {
    let _guard = TEST_LOCK.lock();
    DEVICES.lock().clear();
    assert!(!is_present());
    install(VirtioGpuDev {
        device_key: key(FIRST_DEVICE_KEY),
        bdf: FIRST_DEVICE_BDF,
        card_id: 0,
        cfg_va: 0,
        ctrlq: test_ctrlq(),
        cursorq: test_ctrlq(),
        features_negotiated: 1u64 << VIRTIO_GPU_F_EDID,
        display: DisplayInfo {
            modes: [VirtioGpuDisplayOne::default(); VIRTIO_GPU_MAX_SCANOUTS],
            count_enabled: 1,
        },
        resource_id_alloc: AtomicU32::new(1),
        blob_uuid_alloc: AtomicU64::new(1),
        capset_count: 0,
    }).unwrap();
    install(VirtioGpuDev {
        device_key: key(SECOND_DEVICE_KEY),
        bdf: SECOND_DEVICE_BDF,
        card_id: 1,
        cfg_va: 0,
        ctrlq: test_ctrlq(),
        cursorq: test_ctrlq(),
        features_negotiated: 0,
        display: DisplayInfo {
            modes: [VirtioGpuDisplayOne::default(); VIRTIO_GPU_MAX_SCANOUTS],
            count_enabled: SECOND_DISPLAY_COUNT,
        },
        resource_id_alloc: AtomicU32::new(1),
        blob_uuid_alloc: AtomicU64::new(1),
        capset_count: 0,
    }).unwrap();
    assert!(is_present());
    let first = display_info_for_bdf(FIRST_DEVICE_BDF).unwrap();
    let second = display_info_for_bdf(SECOND_DEVICE_BDF).unwrap();
    assert_eq!(first.count_enabled, 1);
    assert_eq!(second.count_enabled, SECOND_DISPLAY_COUNT);
    assert!(
        negotiated_features_for_bdf(FIRST_DEVICE_BDF).unwrap()
            & (1u64 << VIRTIO_GPU_F_EDID)
            != 0
    );
    assert_eq!(negotiated_features_for_bdf(SECOND_DEVICE_BDF), Some(0));
    assert!(display_info_for_bdf(MISSING_DEVICE_BDF).is_none());
    assert!(negotiated_features_for_bdf(MISSING_DEVICE_BDF).is_none());
    DEVICES.lock().clear();
}

#[test]
fn install_accepts_multiple_keys_and_rejects_duplicate_key() {
    let _guard = TEST_LOCK.lock();
    DEVICES.lock().clear();
    install(test_device(key(FIRST_DEVICE_KEY), FIRST_DEVICE_BDF)).unwrap();
    install(test_device(key(SECOND_DEVICE_KEY), SECOND_DEVICE_BDF)).unwrap();
    assert_eq!(
        install(test_device(key(SECOND_DEVICE_KEY), DUPLICATE_DEVICE_BDF)),
        Err(Error::Busy)
    );
    assert_eq!(DEVICES.lock().len(), 2);
    assert_eq!(uninstall(key(FIRST_DEVICE_KEY)).unwrap().bdf, FIRST_DEVICE_BDF);
    assert!(is_present());
    assert_eq!(
        uninstall(key(SECOND_DEVICE_KEY)).unwrap().bdf,
        SECOND_DEVICE_BDF
    );
    assert!(!is_present());
}

#[test]
fn uninstall_selects_owner_by_child_key_not_raw_bdf() {
    let _guard = TEST_LOCK.lock();
    DEVICES.lock().clear();
    install(test_device(key(ALIASING_DEVICE_KEY), FIRST_DEVICE_BDF)).unwrap();
    install(test_device(key(FIRST_DEVICE_KEY), SECOND_DEVICE_BDF)).unwrap();

    let removed = uninstall(key(ALIASING_DEVICE_KEY)).unwrap();
    assert_eq!(removed.bdf, FIRST_DEVICE_BDF);
    assert_eq!(DEVICES.lock().len(), 1);
    assert_eq!(
        uninstall(key(FIRST_DEVICE_KEY)).unwrap().bdf,
        SECOND_DEVICE_BDF
    );
    assert!(!is_present());
}

#[test]
fn install_with_drm_tracks_each_bdf_card_id() {
    let _guard = TEST_LOCK.lock();
    DEVICES.lock().clear();
    let card_id_1 =
        install_with_drm(test_device(key(FIRST_DEVICE_KEY), FIRST_DEVICE_BDF)).unwrap();
    let card_id_2 =
        install_with_drm(test_device(key(SECOND_DEVICE_KEY), SECOND_DEVICE_BDF)).unwrap();
    {
        let devices = DEVICES.lock();
        assert_eq!(
            devices
                .iter()
                .find(|dev| dev.device_key == key(FIRST_DEVICE_KEY))
                .unwrap()
                .card_id,
            card_id_1
        );
        assert_eq!(
            devices
                .iter()
                .find(|dev| dev.device_key == key(SECOND_DEVICE_KEY))
                .unwrap()
                .card_id,
            card_id_2
        );
    }
    let cards_before_duplicate = drm::card_count();
    let model_devices_before_duplicate = drv::devices()
        .into_iter()
        .filter(|dev| dev.bus == "drm")
        .count();
    assert_eq!(
        install_with_drm(test_device(
            key(SECOND_DEVICE_KEY),
            DUPLICATE_DEVICE_BDF,
        )),
        Err(Error::Busy)
    );
    assert_eq!(drm::card_count(), cards_before_duplicate);
    assert_eq!(
        drv::devices()
            .into_iter()
            .filter(|dev| dev.bus == "drm")
            .count(),
        model_devices_before_duplicate
    );
    assert_eq!(
        uninstall(key(FIRST_DEVICE_KEY)).unwrap().card_id,
        card_id_1
    );
    assert!(is_present());
    assert_eq!(
        uninstall(key(SECOND_DEVICE_KEY)).unwrap().card_id,
        card_id_2
    );
    assert!(!is_present());
}

#[test]
fn shutdown_keeps_device_installed() {
    let _guard = TEST_LOCK.lock();
    DEVICES.lock().clear();
    install(test_device(key(FIRST_DEVICE_KEY), FIRST_DEVICE_BDF)).unwrap();

    assert!(!shutdown(key(SECOND_DEVICE_KEY)));
    assert!(shutdown(key(FIRST_DEVICE_KEY)));
    assert!(is_present());

    DEVICES.lock().clear();
}
