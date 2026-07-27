use super::*;

#[test]
fn prepared_generation_is_invisible_until_publish() {
    let stack = crate::NetStack::new();
    let owner = owner();
    let ns = owner.id().as_u64();
    let reg = stack.prepare_iface(Arc::new(DummyDev {
        name: "pending0", mtu: 1500, stats: NetStats::default(),
    }), &owner).unwrap();
    let id = reg.id();

    assert!(stack.ifaces.lookup_in_ns(id, ns).is_none());
    assert!(stack.ifaces.lookup_name_in_ns("pending0", ns).is_none());
    assert!(stack.ifaces.snapshot_in_ns(ns).is_empty());
    assert!(stack.ifaces.acquire_ingress(id).is_none());
    assert!(stack.publish_iface(reg));
    assert!(stack.ifaces.lookup_in_ns(id, ns).is_some());
    assert_eq!(stack.ifaces.snapshot_in_ns(ns).len(), 1);
}

#[test]
fn ingress_admission_requires_exact_device_arc() {
    let stack = crate::NetStack::new();
    let installed = Arc::new(DummyDev {
        name: "owner0", mtu: 1500, stats: NetStats::default(),
    }) as Arc<dyn NetDev>;
    let alias = Arc::new(DummyDev {
        name: "owner0", mtu: 1500, stats: NetStats::default(),
    }) as Arc<dyn NetDev>;
    let iface = stack.ifaces.register(installed.clone());

    assert!(stack.ifaces.acquire_ingress_for(iface, &alias).is_none());
    assert!(stack.ifaces.acquire_ingress_for(iface, &installed).is_some());
}

#[test]
fn aborted_generation_wakes_unregister_waiter() {
    let stack = Arc::new(crate::NetStack::new());
    let owner = network_namespace::initial();
    let reg = stack.prepare_iface(Arc::new(DummyDev {
        name: "abort0", mtu: 1500, stats: NetStats::default(),
    }), &owner).unwrap();
    let id = reg.id();
    let worker = stack.clone();
    let waiter = std::thread::spawn(move || worker.unregister_iface_current(id));
    while stack.ifaces.resume_waiters(id) == 0 { std::thread::yield_now(); }

    assert!(stack.abort_iface(reg));
    assert!(waiter.join().unwrap());
    assert!(!stack.ifaces.registered(id));
}

#[test]
fn dropped_registration_aborts_and_wakes_unregister_waiter() {
    let stack = Arc::new(crate::NetStack::new());
    let owner = network_namespace::initial();
    let reg = stack.prepare_iface(Arc::new(DummyDev {
        name: "drop0", mtu: 1500, stats: NetStats::default(),
    }), &owner).unwrap();
    let id = reg.id();
    let worker = stack.clone();
    let waiter = std::thread::spawn(move || worker.unregister_iface_current(id));
    while stack.ifaces.resume_waiters(id) == 0 { std::thread::yield_now(); }

    drop(reg);
    assert!(waiter.join().unwrap());
    assert!(!stack.ifaces.registered(id));
}

#[test]
fn pending_loopback_has_no_canonical_state() {
    let stack = crate::NetStack::new();
    let owner = owner();
    let ns = owner.id().as_u64();
    let rtnl = stack.rtnl_lock();
    let (reg, _) = stack.prepare_loopback_in_rtnl(&rtnl, &owner);
    let id = reg.id();

    assert!(stack.ifaces.lookup_in_ns(id, ns).is_none());
    assert!(crate::iface_addr::primary(ns, id).is_none());
    assert!(stack.routes.lookup_in(ns, crate::Ipv4Addr::LOOPBACK).is_none());
    assert!(stack.routes6.lookup_in_table_in(ns, crate::policy_rule::RT_TABLE_LOCAL,
        crate::Ipv6Addr::LOOPBACK).is_none());
    assert!(!stack.v6_addr_owned_by(id, crate::Ipv6Addr::LOOPBACK));
}

#[test]
fn pending_registration_retains_concrete_namespace_owner() {
    let _guard = crate::net_ns::test_support::LIFETIME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let stack = crate::NetStack::new();
    let owner = owner();
    let id = owner.id();
    let weak = Arc::downgrade(&owner);
    let reg = stack.prepare_iface(Arc::new(DummyDev {
        name: "retained0", mtu: 1500, stats: NetStats::default(),
    }), &owner).unwrap();

    drop(owner);
    assert!(weak.upgrade().is_some());
    drop(reg);
    assert!(weak.upgrade().is_none());
    let claimed = network_namespace::take_dead_namespace_ids();
    assert!(claimed.contains(&id));
    crate::net_ns::test_support::finish_claimed(&stack, &claimed);
}

#[test]
fn namespace_teardown_aborts_pending_registration() {
    let stack = crate::NetStack::new();
    let owner = owner();
    let ns = owner.id().as_u64();
    let reg = stack.prepare_iface(Arc::new(DummyDev {
        name: "teardown0", mtu: 1500, stats: NetStats::default(),
    }), &owner).unwrap();
    let id = reg.id();

    assert!(crate::net_ns::destroy_namespace_into(&stack, ns));
    assert!(!stack.ifaces.registered(id));
    assert!(!stack.publish_iface(reg));
    assert!(stack.ifaces.lookup_in_ns(id, ns).is_none());
}

#[test]
fn concurrent_publish_and_teardown_leave_no_interface() {
    let stack = crate::NetStack::new();
    let owner = owner();
    let ns = owner.id().as_u64();
    let reg = stack.prepare_iface(Arc::new(DummyDev {
        name: "race0", mtu: 1500, stats: NetStats::default(),
    }), &owner).unwrap();
    let id = reg.id();
    let barrier = std::sync::Barrier::new(3);

    std::thread::scope(|scope| {
        let publish = scope.spawn(|| {
            barrier.wait();
            stack.publish_iface(reg)
        });
        let teardown = scope.spawn(|| {
            barrier.wait();
            crate::net_ns::destroy_namespace_into(&stack, ns)
        });
        barrier.wait();
        let _published = publish.join().unwrap();
        assert!(teardown.join().unwrap());
    });
    assert!(!stack.ifaces.registered(id));
    assert!(stack.ifaces.lookup_in_ns(id, ns).is_none());
}

#[test]
fn loopback_publication_includes_addresses_and_routes() {
    const NS: u64 = 0x8440_102;
    let stack = crate::NetStack::new();
    let (id, _) = stack.register_loopback_in(NS);

    assert_eq!(crate::iface_addr::primary(NS, id).map(|row| row.0), Some(crate::Ipv4Addr::LOOPBACK));
    assert_eq!(stack.routes.lookup_in(NS, crate::Ipv4Addr::LOOPBACK).map(|route| route.iface),
        Some(id));
    assert_eq!(stack.routes6.lookup_in_table_in(NS, crate::policy_rule::RT_TABLE_LOCAL,
        crate::Ipv6Addr::LOOPBACK).map(|route| route.iface), Some(id));
    assert!(stack.v6_addr_owned_by(id, crate::Ipv6Addr::LOOPBACK));
}
