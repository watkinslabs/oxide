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


