use super::*;
use alloc::vec;
use core::cell::RefCell;

fn resource(path: &str, level: u8, order: u16) -> aml_eval::PowerResourceDecl {
    aml_eval::PowerResourceDecl { path: String::from(path), system_level: level, order }
}

fn device(path: &str, resources: &[&str]) -> aml_eval::PrwDevice {
    aml_eval::PrwDevice { path: String::from(path), gpe_device: None, gpe_number: 7,
        sleep_state: 5, default_enabled: false,
        power_resources: resources.iter().map(|path| String::from(*path)).collect() }
}

#[test]
fn devices_reference_one_canonical_power_resource_owner() {
    let registry = build_registry(vec![resource("\\PR00", 4, 9)],
        vec![device("\\DEV0", &["\\PR00"]), device("\\DEV1", &["\\PR00"])],
        |_| RESOURCE_OFF);
    assert_eq!(registry.resources.len(), 1);
    assert_eq!(registry.devices[0].resources, vec![0]);
    assert_eq!(registry.devices[1].resources, vec![0]);
    resource_lock(&registry.resources[registry.devices[0].resources[0]].owner).refs = 2;
    assert_eq!(resource_lock(&registry.resources[registry.devices[1].resources[0]].owner).refs, 2);
}

#[test]
fn resource_lists_are_deduplicated_ordered_and_limit_the_sleep_state() {
    let registry = build_registry(
        vec![resource("\\LATE", 4, 20), resource("\\EARLY", 3, 10)],
        vec![device("\\DEV0", &["\\LATE", "\\EARLY", "\\LATE"])], |_| RESOURCE_OFF);
    assert_eq!(registry.devices[0].resources, vec![1, 0]);
    assert_eq!(registry.devices[0].deepest, 3);
}

#[test]
fn an_unresolved_power_resource_invalidates_the_prw_owner() {
    let registry = build_registry(Vec::new(), vec![device("\\DEV0", &["\\MISSING"])],
        |_| RESOURCE_UNKNOWN);
    assert!(registry.devices.is_empty());
}

#[test]
fn shared_resources_transition_only_on_zero_one_edges() {
    let registry = build_registry(vec![resource("\\PR00", 5, 0)],
        vec![device("\\DEV0", &["\\PR00"])], |_| RESOURCE_OFF);
    let resource = &registry.resources[0];
    let calls = RefCell::new(Vec::new());
    let mut transition = |path: &str, on| { calls.borrow_mut().push((String::from(path), on)); true };
    assert!(resource_on(resource, &mut transition));
    assert!(resource_on(resource, &mut transition));
    assert!(resource_off(resource, &mut transition));
    assert!(resource_off(resource, &mut transition));
    assert_eq!(*calls.borrow(), vec![(String::from("\\PR00"), true),
        (String::from("\\PR00"), false)]);
}

#[test]
fn ordered_power_on_failure_rolls_back_in_reverse_order() {
    let registry = build_registry(
        vec![resource("\\ONE", 5, 1), resource("\\TWO", 5, 2), resource("\\THREE", 5, 3)],
        vec![device("\\DEV0", &["\\THREE", "\\ONE", "\\TWO"])], |_| RESOURCE_OFF);
    let calls = RefCell::new(Vec::new());
    let mut transition = |path: &str, on| {
        calls.borrow_mut().push((String::from(path), on));
        !(path == "\\THREE" && on)
    };
    assert!(!power_on(&registry, &registry.devices[0], &mut transition));
    assert_eq!(*calls.borrow(), vec![(String::from("\\ONE"), true),
        (String::from("\\TWO"), true), (String::from("\\THREE"), true),
        (String::from("\\TWO"), false), (String::from("\\ONE"), false)]);
    assert!(registry.resources.iter().all(|resource| resource_lock(&resource.owner).refs == 0));
}

#[test]
fn transition_and_accounting_share_one_exclusive_owner() {
    let registry = build_registry(vec![resource("\\PR00", 5, 0)], Vec::new(),
        |_| RESOURCE_OFF);
    let resource = &registry.resources[0];
    let mut transition = |_: &str, _: bool| {
        assert!(resource.owner.try_lock().is_none(),
            "state and references must stay hidden until the firmware transition finishes");
        true
    };
    assert!(resource_on(resource, &mut transition));
    let owner = resource_lock(&resource.owner);
    assert_eq!((owner.refs, owner.state), (1, RESOURCE_ON));
}

#[test]
fn failed_unused_reconciliation_invalidates_the_cached_state_under_the_owner() {
    let registry = build_registry(vec![resource("\\PR00", 5, 0)], Vec::new(),
        |_| RESOURCE_ON);
    let resource = &registry.resources[0];
    let mut transition = |_: &str| {
        assert!(resource.owner.try_lock().is_none());
        false
    };
    reconcile_resource(resource, &mut transition);
    let owner = resource_lock(&resource.owner);
    assert_eq!((owner.refs, owner.state), (0, RESOURCE_UNKNOWN));
}
