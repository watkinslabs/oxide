use super::*;

#[test]
fn driver_registration_binds_existing_matching_devices() {
    LATE_PROBES.store(0, Ordering::Release);
    LATE_REMOVES.store(0, Ordering::Release);
    let d = device_add(Arc::new(Device::new(
        "platform", String::from("late-register-test0"), 0, 0x6200, 0)));

    assert!(d.bound().is_none());
    register_driver(&LATE_REGISTER_DRV);

    assert_eq!(d.bound(), Some("late-register-test"));
    assert_eq!(LATE_PROBES.load(Ordering::Acquire), 1);
    device_del(&d);
    assert_eq!(LATE_REMOVES.load(Ordering::Acquire), 1);
}

#[test]
fn duplicate_driver_registration_does_not_reprobe_existing_devices() {
    DUP_REGISTER_PROBES.store(0, Ordering::Release);
    DUP_REGISTER_REMOVES.store(0, Ordering::Release);
    register_driver(&DUPLICATE_REGISTER_DRV);
    let d = device_add(Arc::new(Device::new(
        "platform", String::from("duplicate-register-test0"), 0, 0x6201, 0)));

    assert_eq!(d.bound(), Some("duplicate-register-test"));
    assert_eq!(DUP_REGISTER_PROBES.load(Ordering::Acquire), 1);
    assert_eq!(unbind(&d), Ok(()));
    assert_eq!(DUP_REGISTER_REMOVES.load(Ordering::Acquire), 1);

    register_driver(&DUPLICATE_REGISTER_DRV);

    assert!(d.bound().is_none());
    assert_eq!(DUP_REGISTER_PROBES.load(Ordering::Acquire), 1);
    device_del(&d);
}

#[test]
fn unregister_driver_unbinds_devices_before_removing_driver() {
    UNREGISTER_PROBES.store(0, Ordering::Release);
    UNREGISTER_REMOVES.store(0, Ordering::Release);
    register_driver(&UNREGISTER_DRV);
    let d = device_add(Arc::new(Device::new(
        "platform", String::from("unregister-test0"), 0, 0x6202, 0)));

    assert_eq!(d.bound(), Some("unregister-test"));
    assert_eq!(UNREGISTER_PROBES.load(Ordering::Acquire), 1);
    assert!(driver_names_for_bus("platform").contains(&"unregister-test"));

    assert_eq!(unregister_driver(&UNREGISTER_DRV), Ok(()));
    assert_eq!(d.bound(), None);
    assert_eq!(UNREGISTER_REMOVES.load(Ordering::Acquire), 1);
    assert!(!driver_names_for_bus("platform").contains(&"unregister-test"));
    assert_eq!(bind(&d, "unregister-test"), Err(crate::Error::NotFound));
    assert_eq!(unregister_driver(&UNREGISTER_DRV), Err(crate::Error::NotFound));

    device_del(&d);
}

#[test]
fn failed_probe_leaves_device_unbound_and_retriable() {
    FAIL_PROBES.store(0, Ordering::Release);
    register_driver(&FAILING_PROBE_DRV);
    let d = device_add(Arc::new(Device::new(
        "pci", String::from("0000:00:13.0"), 0x1234, 0xf00d, 0)));

    assert!(d.bound().is_none());
    assert_eq!(FAIL_PROBES.load(Ordering::Acquire), 1);
    assert_eq!(bind(&d, "failing-probe"), Err(crate::Error::ProbeFailed));
    assert!(d.bound().is_none());
    assert_eq!(FAIL_PROBES.load(Ordering::Acquire), 2);

    assert_eq!(bind(&d, "failing-probe"), Err(crate::Error::ProbeFailed));
    assert!(d.bound().is_none());
    assert_eq!(FAIL_PROBES.load(Ordering::Acquire), 3);
}

#[test]
fn device_del_unbinds_bound_driver_once() {
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
fn repeated_bind_unbind_keeps_model_state_consistent() {
    LOOP_PROBES.store(0, Ordering::Release);
    LOOP_REMOVES.store(0, Ordering::Release);
    register_driver(&LOOP_LIFECYCLE_DRV);
    let d = device_add(Arc::new(Device::new(
        "platform", String::from("loop-lifecycle-test0"), 0, 0x51fe, 0)));
    assert_eq!(d.bound(), Some("loop-lifecycle-test"));
    assert_eq!(unbind(&d), Ok(()));

    for i in 1..=16 {
        assert_eq!(bind(&d, "loop-lifecycle-test"), Ok(()));
        assert_eq!(d.bound(), Some("loop-lifecycle-test"));
        assert_eq!(bind(&d, "loop-lifecycle-test"), Err(crate::Error::AlreadyBound));
        assert_eq!(unbind(&d), Ok(()));
        assert_eq!(d.bound(), None);
        assert_eq!(LOOP_PROBES.load(Ordering::Acquire), i + 1);
        assert_eq!(LOOP_REMOVES.load(Ordering::Acquire), i + 1);
    }

    device_del(&d);
}

#[test]
fn remove_readd_rebind_loop_reuses_bus_identity_after_device_del() {
    READD_PROBES.store(0, Ordering::Release);
    READD_REMOVES.store(0, Ordering::Release);
    register_driver(&READD_LIFECYCLE_DRV);

    for i in 1..=16 {
        let d = try_device_add(Arc::new(Device::new(
            "platform", String::from("readd-lifecycle-test0"), 0, 0x51ff, 0)))
            .unwrap();
        assert_eq!(d.bound(), Some("readd-lifecycle-test"));

        device_del(&d);

        assert_eq!(d.bound(), None);
        assert!(!devices().iter().any(|dev| {
            dev.bus == "platform" && dev.addr == "readd-lifecycle-test0"
        }));
        assert_eq!(READD_PROBES.load(Ordering::Acquire), i);
        assert_eq!(READD_REMOVES.load(Ordering::Acquire), i);
    }
}

#[test]
fn shutdown_all_quiesces_bound_devices_in_reverse_registration_order() {
    use sync::Spinlock as TestLock;
    static ORDER: TestLock<Vec<String>, DriverListClass> = TestLock::new(Vec::new());

    struct OrderedShutdownDrv;
    impl Driver for OrderedShutdownDrv {
        fn name(&self) -> &'static str { "ordered-shutdown-test" }
        fn matches(&self, dev: &Device) -> bool { dev.device_id == 0x7779 }
        fn shutdown(&self, dev: &Device) {
            ORDER.lock().push(dev.addr.clone());
        }
    }
    static ORDERED_SHUTDOWN_DRV: OrderedShutdownDrv = OrderedShutdownDrv;

    ORDER.lock().clear();
    register_driver(&ORDERED_SHUTDOWN_DRV);
    let first = device_add(Arc::new(Device::new(
        "pci", String::from("0000:00:15.0"), 0x1234, 0x7779, 0)));
    let second = device_add(Arc::new(Device::new(
        "pci", String::from("0000:00:16.0"), 0x1234, 0x7779, 0)));
    assert_eq!(first.bound(), Some("ordered-shutdown-test"));
    assert_eq!(second.bound(), Some("ordered-shutdown-test"));

    shutdown_all();

    assert_eq!(
        &*ORDER.lock(),
        &[String::from("0000:00:16.0"), String::from("0000:00:15.0")]
    );
    assert_eq!(first.bound(), Some("ordered-shutdown-test"));
    assert_eq!(second.bound(), Some("ordered-shutdown-test"));
}
