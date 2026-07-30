use super::super::*;
use super::support::{key, test_device, TEST_LOCK};
use alloc::{format, string::String, sync::Arc};

const MODEL_PARENT_VENDOR_ID: u16 = 0x1af4;
const MODEL_PARENT_DEVICE_ID: u16 = 16;
const MODEL_PARENT_KEY: u32 = 3;
const MODEL_PARENT_BDF: u32 = 0x0030_0000;

#[test]
fn install_with_drm_records_model_parent() {
    let _guard = TEST_LOCK.lock();
    DEVICES.lock().clear();
    let parent_addr = String::from("virtio-gpu-parent-test0");
    let parent = drv::try_device_add(Arc::new(drv::Device::new(
        "virtio",
        parent_addr.clone(),
        MODEL_PARENT_VENDOR_ID,
        MODEL_PARENT_DEVICE_ID,
        0,
    ))).expect("model parent registration");
    let card_id = install_with_drm_parent(
        test_device(key(MODEL_PARENT_KEY), MODEL_PARENT_BDF),
        Some(&parent),
    ).unwrap();
    let card_name = format!("card{card_id}");
    let card_path = format!("devices/virtio/{parent_addr}/drm/{card_name}");
    let drm_dev = drv::devices()
        .into_iter()
        .find(|dev| dev.bus == "drm" && dev.addr.as_str() == card_name.as_str())
        .expect("DRM card model device");
    assert_eq!(drm_dev.parent(), Some(("virtio", parent_addr.as_str())));
    assert_eq!(
        drv::device_canon_exact(&drm_dev).as_deref(),
        Some(card_path.as_str()),
    );

    assert_eq!(
        uninstall(key(MODEL_PARENT_KEY)).unwrap().card_id,
        card_id
    );
    drv::device_del(&parent);
    assert!(!is_present());
}
