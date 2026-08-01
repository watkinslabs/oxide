use super::*;

#[test]
fn driver_registration_binds_existing_matching_devices() {
    let _model = crate::model::test_claim::claim_model();
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
    let _model = crate::model::test_claim::claim_model();
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
    let _model = crate::model::test_claim::claim_model();
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
fn unbind_calls_remove_before_clearing_binding() {
    let _model = crate::model::test_claim::claim_model();
    UNBIND_ORDER_REMOVE_SAW_BOUND.store(0, Ordering::Release);
    register_driver(&UNBIND_ORDER_DRV);
    let d = device_add(Arc::new(Device::new(
        "platform", String::from("unbind-order-test0"), 0, 0x6204, 0)));

    assert_eq!(d.bound(), Some("unbind-order-test"));
    assert_eq!(unbind(&d), Ok(()));
    assert_eq!(UNBIND_ORDER_REMOVE_SAW_BOUND.load(Ordering::Acquire), 1);
    assert_eq!(d.bound(), None);

    device_del(&d);
}

#[test]
fn failed_probe_leaves_device_unbound_and_retriable() {
    let _model = crate::model::test_claim::claim_model();
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

#[test]
fn find_matching_device_identity_reuses_only_exact_platform_identity() {
    let _model = crate::model::test_claim::claim_model();
    let existing = try_device_add(Arc::new(Device::new(
        "platform", String::from(PLATFORM_REUSE_ADDR),
        PLATFORM_REUSE_VENDOR_ID, PLATFORM_REUSE_DEVICE_ID, PLATFORM_REUSE_CLASS,
    )))
    .unwrap();
    let same = Device::new(
        "platform", String::from(PLATFORM_REUSE_ADDR),
        PLATFORM_REUSE_VENDOR_ID, PLATFORM_REUSE_DEVICE_ID, PLATFORM_REUSE_CLASS,
    );
    let with_parent = Device::new(
        "platform", String::from(PLATFORM_REUSE_ADDR),
        PLATFORM_REUSE_VENDOR_ID, PLATFORM_REUSE_DEVICE_ID, PLATFORM_REUSE_CLASS,
    )
        .with_parent("platform", String::from(PLATFORM_REUSE_PARENT_ADDR));
    let with_devnode = Device::new(
        "platform", String::from(PLATFORM_REUSE_ADDR),
        PLATFORM_REUSE_VENDOR_ID, PLATFORM_REUSE_DEVICE_ID, PLATFORM_REUSE_CLASS,
    )
        .with_devnode(
            PLATFORM_REUSE_DEVNODE_CLASS,
            String::from(PLATFORM_REUSE_DEVNODE_NAME),
            Some((PLATFORM_REUSE_DEV_MAJOR, PLATFORM_REUSE_DEV_MINOR)),
        );
    let with_resource = Device::new(
        "platform", String::from(PLATFORM_REUSE_ADDR),
        PLATFORM_REUSE_VENDOR_ID, PLATFORM_REUSE_DEVICE_ID, PLATFORM_REUSE_CLASS,
    )
        .with_resources(Vec::from([
            Resource {
                bar: PLATFORM_REUSE_RESOURCE_BAR,
                start: PLATFORM_REUSE_RESOURCE_START,
                end: PLATFORM_REUSE_RESOURCE_END,
                flags: IORESOURCE_MEM,
            },
        ]));

    assert!(Arc::ptr_eq(&find_matching_device_identity(&same).unwrap(), &existing));
    assert!(!existing.identity_eq(&with_parent));
    assert!(!existing.identity_eq(&with_devnode));
    assert!(!existing.identity_eq(&with_resource));
    assert!(find_matching_device_identity(&with_parent).is_none());
    assert!(find_matching_device_identity(&with_devnode).is_none());
    assert!(find_matching_device_identity(&with_resource).is_none());

    device_del(&existing);
}

#[test]
fn platform_identity_conflict_is_busy_but_not_reusable() {
    let _model = crate::model::test_claim::claim_model();
    let existing = try_device_add(Arc::new(Device::new(
        "platform", String::from(PLATFORM_CONFLICT_ADDR),
        PLATFORM_REUSE_VENDOR_ID, PLATFORM_REUSE_DEVICE_ID, PLATFORM_REUSE_CLASS,
    )))
    .unwrap();
    let conflict = Arc::new(Device::new(
        "platform", String::from(PLATFORM_CONFLICT_ADDR),
        PLATFORM_REUSE_VENDOR_ID, PLATFORM_REUSE_DEVICE_ID, PLATFORM_REUSE_CLASS,
    )
    .with_devnode(
        PLATFORM_CONFLICT_DEVNODE_CLASS,
        String::from(PLATFORM_CONFLICT_DEVNODE_NAME),
        Some((PLATFORM_CONFLICT_DEV_MAJOR, PLATFORM_CONFLICT_DEV_MINOR)),
    ));

    assert!(matches!(
        try_device_add(Arc::clone(&conflict)),
        Err(crate::Error::Busy)
    ));
    assert!(find_matching_device_identity(&conflict).is_none());
    assert!(devices().iter().any(|d| Arc::ptr_eq(d, &existing)));
    assert_eq!(
        devices().iter()
            .filter(|d| d.bus == "platform" && d.addr == PLATFORM_CONFLICT_ADDR)
            .count(),
        1
    );

    device_del(&existing);
}

#[test]
fn try_device_add_preserves_pci_bar_resources_and_rejects_republish() {
    let _model = crate::model::test_claim::claim_model();
    let first = try_device_add(Arc::new(
        Device::new("pci", String::from("0000:00:18.0"), 0x1234, 0x5678, 0x010601)
            .with_resources(Vec::from([
                Resource { bar: 0, start: 0x8000_0000, end: 0x8000_0fff, flags: IORESOURCE_MEM },
                Resource { bar: 5, start: 0x0000_c000, end: 0x0000_c0ff, flags: IORESOURCE_IO },
            ]))))
        .unwrap();

    assert_eq!(first.resources.len(), 2);
    assert_eq!(
        first.resources[0],
        Resource { bar: 0, start: 0x8000_0000, end: 0x8000_0fff, flags: IORESOURCE_MEM });
    assert_eq!(
        first.resources[1],
        Resource { bar: 5, start: 0x0000_c000, end: 0x0000_c0ff, flags: IORESOURCE_IO });

    let duplicate = try_device_add(Arc::new(
        Device::new("pci", String::from("0000:00:18.0"), 0x1234, 0x5678, 0x010601)
            .with_resources(Vec::from([
                Resource { bar: 0, start: 0x9000_0000, end: 0x9000_0fff, flags: IORESOURCE_MEM },
            ]))));

    assert!(matches!(duplicate, Err(crate::Error::Busy)));
    let dev = devices().into_iter()
        .find(|d| d.bus == "pci" && d.addr == "0000:00:18.0")
        .unwrap();
    assert_eq!(dev.resources, first.resources);

    device_del(&first);
}

#[test]
fn pci_identity_mismatch_does_not_replace_or_rebind() {
    let _model = crate::model::test_claim::claim_model();
    PCI_IDENTITY_PROBES.store(0, Ordering::Release);
    PCI_MISMATCH_PROBES.store(0, Ordering::Release);
    register_driver(&PCI_IDENTITY_DRV);
    register_driver(&PCI_MISMATCH_DRV);
    for (idx, addr) in ["0000:00:17.0", "0000:01:17.0"].iter().enumerate() {
        let first = try_device_add(Arc::new(Device::new(
            "pci", String::from(*addr), 0x1af4, 0x1041, 0x010000)))
            .unwrap();

        assert_eq!(first.bound(), Some("pci-identity-test"));
        assert_eq!(PCI_IDENTITY_PROBES.load(Ordering::Acquire), (idx + 1) as u32);
        assert_eq!(PCI_MISMATCH_PROBES.load(Ordering::Acquire), 0);

        let mismatch = try_device_add(Arc::new(Device::new(
            "pci", String::from(*addr), 0x1af4, 0x1042, 0x020000)));

        assert!(matches!(mismatch, Err(crate::Error::Busy)));
        assert_eq!(first.bound(), Some("pci-identity-test"));
        assert_eq!(PCI_IDENTITY_PROBES.load(Ordering::Acquire), (idx + 1) as u32);
        assert_eq!(PCI_MISMATCH_PROBES.load(Ordering::Acquire), 0);
        assert_eq!(
            devices().iter()
                .filter(|d| d.bus == "pci" && d.addr == *addr)
                .count(),
            1
        );
        let dev = devices().into_iter()
            .find(|d| d.bus == "pci" && d.addr == *addr)
            .unwrap();
        assert_eq!(dev.vendor_id, 0x1af4);
        assert_eq!(dev.device_id, 0x1041);
        assert_eq!(dev.class, 0x010000);

        device_del(&first);
    }
}

#[test]
fn repeated_bind_unbind_keeps_model_state_consistent() {
    let _model = crate::model::test_claim::claim_model();
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
    let _model = crate::model::test_claim::claim_model();
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
fn multi_device_fault_hotplug_cycle_keeps_model_state_consistent() {
    let _model = crate::model::test_claim::claim_model();
    HARDEN_PLATFORM_PROBES.store(0, Ordering::Release);
    HARDEN_PLATFORM_REMOVES.store(0, Ordering::Release);
    HARDEN_PCI_PROBES.store(0, Ordering::Release);
    HARDEN_PCI_REMOVES.store(0, Ordering::Release);
    HARDEN_FAIL_PROBES.store(0, Ordering::Release);
    register_driver(&HARDENING_PLATFORM_DRV);
    register_driver(&HARDENING_PCI_DRV);
    register_driver(&HARDENING_FAIL_DRV);

    for cycle in 1..=HARDEN_LOOP_COUNT {
        let first = try_device_add(Arc::new(Device::new(
            "platform", String::from(HARDEN_PLATFORM_ADDRS[0]), 0, HARDEN_PLATFORM_ID, 0)))
            .unwrap();
        let second = try_device_add(Arc::new(Device::new(
            "platform", String::from(HARDEN_PLATFORM_ADDRS[1]), 0, HARDEN_PLATFORM_ID, 0)))
            .unwrap();
        let pci = try_device_add(Arc::new(Device::new(
            "pci", String::from(HARDEN_PCI_ADDR), HARDEN_PCI_VENDOR, HARDEN_PCI_ID, HARDEN_CLASS)))
            .unwrap();
        let failing = try_device_add(Arc::new(Device::new(
            "platform", String::from(HARDEN_FAIL_ADDR), 0, HARDEN_FAIL_ID, 0)))
            .unwrap();

        assert_eq!(first.bound(), Some("hardening-platform-test"));
        assert_eq!(second.bound(), Some("hardening-platform-test"));
        assert_eq!(pci.bound(), Some("hardening-pci-test"));
        assert_eq!(failing.bound(), None);
        assert!(matches!(
            try_device_add(Arc::new(Device::new(
                "platform", String::from(HARDEN_PLATFORM_ADDRS[0]), 0, HARDEN_PLATFORM_ID, 0))),
            Err(crate::Error::Busy)
        ));
        assert_eq!(bind(&failing, "hardening-fail-test"), Err(crate::Error::ProbeFailed));
        assert_eq!(failing.bound(), None);

        assert_eq!(unbind(&first), Ok(()));
        assert_eq!(bind(&first, "hardening-platform-test"), Ok(()));
        assert_eq!(unbind(&pci), Ok(()));
        assert_eq!(bind(&pci, "hardening-pci-test"), Ok(()));

        device_del(&first);
        device_del(&second);
        device_del(&pci);
        device_del(&failing);
        assert!(!devices().iter().any(|dev| {
            dev.addr == HARDEN_PLATFORM_ADDRS[0] || dev.addr == HARDEN_PLATFORM_ADDRS[1]
                || dev.addr == HARDEN_PCI_ADDR || dev.addr == HARDEN_FAIL_ADDR
        }));
        assert_eq!(HARDEN_PLATFORM_PROBES.load(Ordering::Acquire), cycle * 3);
        assert_eq!(HARDEN_PLATFORM_REMOVES.load(Ordering::Acquire), cycle * 3);
        assert_eq!(HARDEN_PCI_PROBES.load(Ordering::Acquire), cycle * 2);
        assert_eq!(HARDEN_PCI_REMOVES.load(Ordering::Acquire), cycle * 2);
        assert_eq!(HARDEN_FAIL_PROBES.load(Ordering::Acquire), cycle * 2);
    }
}

#[test]
fn shutdown_all_quiesces_bound_devices_in_reverse_registration_order() {
    let _model = crate::model::test_claim::claim_model();
    use sync::Spinlock as TestLock;
    static ORDER: TestLock<Vec<String>, DriverListClass> = TestLock::new(Vec::new());

    struct OrderedShutdownDrv;
    impl Driver for OrderedShutdownDrv {
        fn name(&self) -> &'static str { "ordered-shutdown-test" }
        fn matches(&self, dev: &Device) -> bool { dev.device_id == 0x7779 }
        fn remove(&self, _dev: &Device) {
            SHUTDOWN_REMOVES.fetch_add(1, Ordering::Release);
        }
        fn shutdown(&self, dev: &Device) {
            ORDER.lock().push(dev.addr.clone());
        }
    }
    static ORDERED_SHUTDOWN_DRV: OrderedShutdownDrv = OrderedShutdownDrv;

    ORDER.lock().clear();
    SHUTDOWN_REMOVES.store(0, Ordering::Release);
    SHUTDOWN_UNBOUND_EVENTS.store(0, Ordering::Release);
    SHUTDOWN_EVENT_ACTIVE.store(1, Ordering::Release);
    set_bind_hook(shutdown_all_bind_event);
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
    assert_eq!(SHUTDOWN_REMOVES.load(Ordering::Acquire), 0);
    assert_eq!(SHUTDOWN_UNBOUND_EVENTS.load(Ordering::Acquire), 0);
    SHUTDOWN_EVENT_ACTIVE.store(0, Ordering::Release);
}
