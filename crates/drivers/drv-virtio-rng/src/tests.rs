use alloc::{string::String, sync::Arc, vec::Vec};

use sync::{Spinlock, TaskList as DriverLockClass};

use crate::registry::{
    active_handle, find_handle, promote_active_locked, publish_hwrng_or_clear_active,
    RngHandle, RngRegistry, RngState, RNGS,
};
use crate::{fill_from_device, uninstall};

static TEST_LOCK: Spinlock<(), DriverLockClass> = Spinlock::new(());

fn key(raw: u32) -> virtio::VirtioChildDeviceKey {
    virtio::VirtioChildDeviceKey::from_raw(raw)
}

fn cleanup_hwrng_devices() {
    let devices = drv::devices();
    for dev in devices.iter().filter(|dev| dev.bus == "misc" && dev.addr == "hwrng") {
        drv::device_del(dev);
    }
}

fn test_queue() -> virtio::VirtQueueResource {
    virtio::VirtQueueResource::new(0, 8, 0x1000, 0x2000, 0x3000, 0x4000, 0)
}

fn test_record(device_key: virtio::VirtioChildDeviceKey, shutdown: bool) -> RngHandle {
    let hwrng_dev = Arc::new(drv::Device::new("misc", String::from("hwrng"), 0, 0, 0));
    Arc::new(Spinlock::new(RngState {
        device_key,
        cfg_va: 0,
        hhdm: 0,
        requestq: test_queue(),
        avail_idx: 0,
        used_idx_seen: 0,
        bounce_pa: 0,
        hwrng_dev,
        shutdown,
    }))
}

fn test_hwrng_device() -> Arc<drv::Device> {
    Arc::new(
        drv::Device::new("misc", String::from("hwrng"), 0, 0, 0)
            .with_devnode("misc", String::from("hwrng"), Some((10, 183)))
            .with_node_factory(Arc::new(|| devfs::misc::make_hwrng_inode())),
    )
}

fn test_record_with_device(
    device_key: virtio::VirtioChildDeviceKey,
    cfg_va: u64,
    hwrng_dev: Arc<drv::Device>,
) -> RngHandle {
    Arc::new(Spinlock::new(RngState {
        device_key,
        cfg_va,
        hhdm: 0,
        requestq: test_queue(),
        avail_idx: 0,
        used_idx_seen: 0,
        bounce_pa: 0,
        hwrng_dev,
        shutdown: false,
    }))
}

fn ready_queue_record(
    device_key: virtio::VirtioChildDeviceKey,
    desc: &mut [u64; 2],
    avail: &mut [u16; 4],
    used: &mut [u16; 6],
    notify: &mut u16,
    bounce: &mut [u8; 32],
) -> RngHandle {
    used[1] = 1;
    used[4] = bounce.len() as u16;
    Arc::new(Spinlock::new(RngState {
        device_key,
        cfg_va: 0,
        hhdm: 0,
        requestq: virtio::VirtQueueResource::new(
            0,
            8,
            desc.as_mut_ptr() as u64,
            avail.as_mut_ptr() as u64,
            used.as_mut_ptr() as u64,
            notify as *mut u16 as u64,
            0,
        ),
        avail_idx: 0,
        used_idx_seen: 0,
        bounce_pa: bounce.as_mut_ptr() as u64,
        hwrng_dev: Arc::new(drv::Device::new("misc", String::from("hwrng"), 0, 0, 0)),
        shutdown: false,
    }))
}

#[test]
fn transport_profile_carries_child_feature_mask() {
    let profile = crate::transport_profile();

    assert_eq!(profile.drv_features, crate::wanted_features());
    assert_eq!(profile.drv_features, virtio::VIRTIO_F_VERSION_1);
    assert!(!profile.child_requirements.needs_device_cfg);
    assert!(profile.child_requirements.required_queues[0]);
    assert!(profile.child_requirements.required_queues[1..].iter().all(|required| !required));
}

#[test]
fn registry_records_are_child_keyed() {
    let _guard = TEST_LOCK.lock();
    let key0 = key(0x0001_0000);
    let key1 = key(0x0002_0000);
    {
        let mut registry = RNGS.lock();
        registry.records.clear();
        registry.records.push(test_record(key0, false));
        registry.records.push(test_record(key1, false));
        registry.active_key = Some(key1);
    }
    assert_eq!(find_handle(key0).unwrap().lock().device_key, key0);
    assert_eq!(find_handle(key1).unwrap().lock().device_key, key1);
    assert!(find_handle(key(0x0003_0000)).is_none());
    assert_eq!(active_handle().unwrap().lock().device_key, key1);
    let mut registry = RNGS.lock();
    registry.records.clear();
    registry.active_key = None;
}

#[test]
fn fill_from_device_uses_requested_child_not_active() {
    let _guard = TEST_LOCK.lock();
    let key0 = key(0x0001_0000);
    let key1 = key(0x0002_0000);
    let mut desc0 = [0u64; 2];
    let mut desc1 = [0u64; 2];
    let mut avail0 = [0u16; 4];
    let mut avail1 = [0u16; 4];
    let mut used0 = [0u16; 6];
    let mut used1 = [0u16; 6];
    let mut notify0 = 0u16;
    let mut notify1 = 0u16;
    let mut bounce0 = [0xa5u8; 32];
    let mut bounce1 = [0x5au8; 32];
    {
        let mut registry = RNGS.lock();
        registry.records.clear();
        registry.records.push(ready_queue_record(key0, &mut desc0, &mut avail0, &mut used0, &mut notify0, &mut bounce0));
        registry.records.push(ready_queue_record(key1, &mut desc1, &mut avail1, &mut used1, &mut notify1, &mut bounce1));
        registry.active_key = Some(key0);
    }

    let mut out = [0u8; 32];
    assert_eq!(fill_from_device(key1, &mut out), 32);
    assert_eq!(out, [0x5au8; 32]);
    assert_eq!(notify0, 0);
    assert_eq!(notify1, 0);
    assert_eq!(avail0[1], 0);
    assert_eq!(avail1[1], 1);
    let mut registry = RNGS.lock();
    registry.records.clear();
    registry.active_key = None;
}

#[test]
fn promotion_uses_explicit_live_key_not_vector_order() {
    let _guard = TEST_LOCK.lock();
    let mut registry = RngRegistry {
        records: alloc::vec![test_record(key(0x0010_0000), true), test_record(key(0x0020_0000), false)],
        active_key: Some(key(0x0010_0000)),
    };

    assert!(promote_active_locked(&mut registry).is_some());
    assert_eq!(registry.active_key, Some(key(0x0020_0000)));
}

#[test]
fn promotion_clears_active_when_no_live_rng_remains() {
    let _guard = TEST_LOCK.lock();
    let mut registry = RngRegistry {
        records: alloc::vec![test_record(key(0x0010_0000), true)],
        active_key: Some(key(0x0010_0000)),
    };

    assert!(promote_active_locked(&mut registry).is_none());
    assert_eq!(registry.active_key, None);
}

#[test]
fn hwrng_publish_failure_clears_active_provider() {
    let _guard = TEST_LOCK.lock();
    cleanup_hwrng_devices();
    {
        let mut registry = RNGS.lock();
        registry.records.clear();
        registry.active_key = Some(key(0x0010_0000));
    }
    let conflict = drv::try_device_add(Arc::new(
        drv::Device::new("misc", String::from("hwrng"), 0, 0, 0)
            .with_devnode("misc", String::from("hwrng"), Some((10, 183))),
    ))
    .expect("conflict device registration");
    let candidate = Arc::new(
        drv::Device::new("misc", String::from("hwrng"), 0, 0, 0)
            .with_devnode("misc", String::from("hwrng"), Some((10, 183))),
    );

    assert!(!publish_hwrng_or_clear_active(key(0x0010_0000), candidate));
    assert_eq!(RNGS.lock().active_key, None);
    assert_eq!(
        drv::devices()
            .iter()
            .filter(|dev| dev.bus == "misc" && dev.addr == "hwrng")
            .count(),
        1
    );

    drv::device_del(&conflict);
}

#[test]
fn hwrng_publish_success_keeps_single_model_device() {
    let _guard = TEST_LOCK.lock();
    cleanup_hwrng_devices();
    {
        let mut registry = RNGS.lock();
        registry.records.clear();
        registry.active_key = Some(key(0x0020_0000));
    }
    let candidate = Arc::new(
        drv::Device::new("misc", String::from("hwrng"), 0, 0, 0)
            .with_devnode("misc", String::from("hwrng"), Some((10, 183))),
    );

    assert!(publish_hwrng_or_clear_active(key(0x0020_0000), Arc::clone(&candidate)));
    assert_eq!(RNGS.lock().active_key, Some(key(0x0020_0000)));
    assert_eq!(
        drv::devices()
            .iter()
            .filter(|dev| dev.bus == "misc" && dev.addr == "hwrng")
            .count(),
        1
    );

    drv::device_del(&candidate);
    devfs::misc::clear_hwrng_source();
    RNGS.lock().active_key = None;
}

#[test]
fn uninstall_then_republish_restores_single_hwrng_model_device() {
    let _guard = TEST_LOCK.lock();
    cleanup_hwrng_devices();
    {
        let mut registry = RNGS.lock();
        registry.records.clear();
        registry.active_key = None;
    }
    static REMOVED: Spinlock<Vec<String>, DriverLockClass> = Spinlock::new(Vec::new());
    fn del_hook(name: &str) {
        REMOVED.lock().push(String::from(name));
    }
    drv::set_devtmpfs_del_hook(del_hook);
    REMOVED.lock().clear();

    let key0 = key(0x0030_0000);
    let mut cfg0 = [0u8; 0x20];
    let first = test_hwrng_device();
    {
        let mut registry = RNGS.lock();
        registry.records.push(test_record_with_device(key0, cfg0.as_mut_ptr() as u64, Arc::clone(&first)));
        registry.active_key = Some(key0);
    }
    assert!(publish_hwrng_or_clear_active(key0, first));
    assert_eq!(
        drv::devices()
            .iter()
            .filter(|dev| dev.bus == "misc" && dev.addr == "hwrng")
            .count(),
        1
    );

    assert!(uninstall(key0));
    assert_eq!(RNGS.lock().active_key, None);
    assert_eq!(
        drv::devices()
            .iter()
            .filter(|dev| dev.bus == "misc" && dev.addr == "hwrng")
            .count(),
        0
    );
    assert!(REMOVED.lock().iter().any(|name| name == "hwrng"));

    let mut cfg1 = [0u8; 0x20];
    let second = test_hwrng_device();
    {
        let mut registry = RNGS.lock();
        registry.records.push(test_record_with_device(key0, cfg1.as_mut_ptr() as u64, Arc::clone(&second)));
        registry.active_key = Some(key0);
    }
    assert!(publish_hwrng_or_clear_active(key0, second));
    assert_eq!(
        drv::devices()
            .iter()
            .filter(|dev| dev.bus == "misc" && dev.addr == "hwrng")
            .count(),
        1
    );
    assert!(uninstall(key0));
    assert_eq!(RNGS.lock().active_key, None);
}

/// A handle cloned out of the registry outlives the removal, so `uninstall`
/// must disarm the record before its bounce frame goes back to the PMM.
/// Without that, the in-flight clone programs a freed frame as a
/// device-WRITE descriptor and the device DMAs into reallocated memory.
#[test]
fn uninstall_disarms_a_handle_cloned_before_removal() {
    let _guard = TEST_LOCK.lock();
    cleanup_hwrng_devices();
    {
        let mut registry = RNGS.lock();
        registry.records.clear();
        registry.active_key = None;
    }
    let key0 = key(0x0060_0000);
    let mut desc = [0u64; 2];
    let mut avail = [0u16; 4];
    let mut used = [0u16; 6];
    let mut notify = 0u16;
    let mut bounce = [0xc3u8; 32];
    {
        let mut registry = RNGS.lock();
        registry.records.push(ready_queue_record(
            key0, &mut desc, &mut avail, &mut used, &mut notify, &mut bounce));
        registry.active_key = Some(key0);
    }
    // Model the racing reader: it has the handle before uninstall runs.
    let inflight = find_handle(key0).expect("handle cloned before removal");

    assert!(uninstall(key0));

    assert_eq!(inflight.lock().bounce_pa, 0);
    assert!(inflight.lock().shutdown);
    let mut out = [0u8; 32];
    assert_eq!(crate::fill::fill_record(&inflight, &mut out), 0);
    assert_eq!(out, [0u8; 32]);
    assert_eq!(avail[1], 0);

    RNGS.lock().active_key = None;
}

/// `uninstall` on a record whose transport never mapped a common-cfg window
/// must not write through the null base. `virtio::reset_device` refuses a
/// zero `cfg_va`; a raw store to `cfg_va + status_off` would not.
#[test]
fn uninstall_without_a_config_window_writes_nothing() {
    let _guard = TEST_LOCK.lock();
    cleanup_hwrng_devices();
    {
        let mut registry = RNGS.lock();
        registry.records.clear();
        registry.active_key = None;
    }
    let key0 = key(0x0070_0000);
    {
        let mut registry = RNGS.lock();
        registry.records.push(test_record(key0, false));
        registry.active_key = Some(key0);
    }

    assert!(uninstall(key0));
    assert_eq!(RNGS.lock().active_key, None);
}

#[test]
fn uninstall_active_promotes_next_live_hwrng_provider() {
    let _guard = TEST_LOCK.lock();
    cleanup_hwrng_devices();
    {
        let mut registry = RNGS.lock();
        registry.records.clear();
        registry.active_key = None;
    }
    let key0 = key(0x0040_0000);
    let key1 = key(0x0050_0000);
    let mut cfg0 = [0u8; 0x20];
    let mut cfg1 = [0u8; 0x20];
    let first = test_hwrng_device();
    let second = test_hwrng_device();
    {
        let mut registry = RNGS.lock();
        registry.records.push(test_record_with_device(key0, cfg0.as_mut_ptr() as u64, Arc::clone(&first)));
        registry.records.push(test_record_with_device(key1, cfg1.as_mut_ptr() as u64, Arc::clone(&second)));
        registry.active_key = Some(key0);
    }

    assert!(publish_hwrng_or_clear_active(key0, first));
    assert!(uninstall(key0));
    assert_eq!(RNGS.lock().active_key, Some(key1));
    assert_eq!(
        drv::devices()
            .iter()
            .filter(|dev| dev.bus == "misc" && dev.addr == "hwrng")
            .count(),
        1
    );

    assert!(uninstall(key1));
    assert_eq!(RNGS.lock().active_key, None);
    assert_eq!(
        drv::devices()
            .iter()
            .filter(|dev| dev.bus == "misc" && dev.addr == "hwrng")
            .count(),
        0
    );
}
