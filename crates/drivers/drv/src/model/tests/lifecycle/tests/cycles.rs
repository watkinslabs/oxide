use super::*;

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
