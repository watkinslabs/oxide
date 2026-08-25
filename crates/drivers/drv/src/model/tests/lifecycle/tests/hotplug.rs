use super::*;

#[test]
fn parent_probe_publishes_child_inside_one_outer_hotplug_transaction() {
    let _model = crate::model::test_claim::claim_model();
    register_driver(&NESTED_CHILD_DRV);
    let parent = device_add(Arc::new(Device::new(
        "platform", String::from("nested-parent-test0"), 0, NESTED_PARENT_ID, 0)));

    assert_eq!(parent.bound(), Some("nested-child-test"));
    let child = devices().into_iter().find(|device|
        device.bus == "nested-bus" && device.addr == NESTED_CHILD_ADDR)
        .expect("nested probe child must publish");
    assert_eq!(child.parent(), Some(("platform", "nested-parent-test0")));

    device_del(&child);
    device_del(&parent);
}

#[test]
fn device_del_unbinds_bound_driver_once() {
    let _model = crate::model::test_claim::claim_model();
    REMOVE_HITS.store(0, Ordering::Release);
    register_driver(&REMOVE_DRV);
    let d = device_add(Arc::new(Device::new(
        "pci", String::from("0000:00:11.0"), 0x1234, 0x7777, 0)));
    assert_eq!(d.bound(), Some("remove-test"));

    device_del(&d);
    assert_eq!(REMOVE_HITS.load(Ordering::Acquire), 1);
    assert!(d.bound().is_none());
    assert!(!devices().iter().any(|x| Arc::ptr_eq(x, &d)));

    device_del(&d);
    assert_eq!(REMOVE_HITS.load(Ordering::Acquire), 1);
}

#[test]
fn device_del_orders_remove_event_and_devtmpfs_teardown() {
    let _model = crate::model::test_claim::claim_model();
    DEVICE_DEL_ORDER.lock().clear();
    DEVICE_DEL_ORDER_ACTIVE.store(1, Ordering::Release);
    set_sysfs_remove_hook(device_del_order_sysfs_remove);
    set_devtmpfs_del_hook(device_del_order_devtmpfs_del);
    register_driver(&DEVICE_DEL_ORDER_DRV);
    let d = device_add(Arc::new(
        Device::new("platform", String::from("device-del-order0"), 0, 0x6203, 0)
            .with_devnode("misc", String::from("device-del-order-node"), Some((10, 251)))));

    assert_eq!(d.bound(), Some("device-del-order-test"));
    device_del(&d);

    assert_eq!(
        &*DEVICE_DEL_ORDER.lock(),
        &["driver-remove", "sysfs-remove", "devtmpfs-del"]
    );
    assert!(!devices().iter().any(|dev| Arc::ptr_eq(dev, &d)));
}

#[test]
fn try_device_add_rejects_duplicate_bus_identity() {
    let _model = crate::model::test_claim::claim_model();
    let first = try_device_add(Arc::new(Device::new(
        "platform", String::from("duplicate-device-test0"), 0, 0x51fd, 0)))
        .unwrap();
    let duplicate = try_device_add(Arc::new(Device::new(
        "platform", String::from("duplicate-device-test0"), 0, 0x51fd, 0)));

    assert!(matches!(duplicate, Err(crate::Error::Busy)));
    assert_eq!(
        devices().iter()
            .filter(|d| d.bus == "platform" && d.addr == "duplicate-device-test0")
            .count(),
        1
    );

    device_del(&first);
    assert!(!devices().iter().any(|d| {
        d.bus == "platform" && d.addr == "duplicate-device-test0"
    }));
}

#[test]
fn rollback_devices_after_conflict_removes_only_published_batch() {
    let _model = crate::model::test_claim::claim_model();
    let existing = try_device_add(Arc::new(Device::new(
        "tty", String::from(ROLLBACK_KEEP_ADDR), 0, ROLLBACK_KEEP_ID, 0)))
        .unwrap();
    let published = try_device_add(Arc::new(Device::new(
        "tty", String::from(ROLLBACK_DROP_ADDR), 0, ROLLBACK_DROP_ID, 0)))
        .unwrap();
    let conflict = try_device_add(Arc::new(Device::new(
        "tty", String::from(ROLLBACK_KEEP_ADDR), 0, ROLLBACK_CONFLICT_ID, 0)));

    assert!(matches!(conflict, Err(crate::Error::Busy)));
    rollback_devices(&[Arc::clone(&published)]);

    assert!(devices().iter().any(|d| Arc::ptr_eq(d, &existing)));
    assert!(!devices().iter().any(|d| Arc::ptr_eq(d, &published)));
    assert_eq!(
        devices().iter()
            .filter(|d| d.bus == "tty" && d.addr == ROLLBACK_KEEP_ADDR)
            .count(),
        1
    );

    device_del(&existing);
}


