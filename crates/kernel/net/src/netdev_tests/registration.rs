use super::*;
use core::sync::atomic::{AtomicUsize, Ordering};

static CARRIER_NEWLINKS: AtomicUsize = AtomicUsize::new(0);

#[test]
fn iface_registry_lock_excludes_network_bottom_halves() {
    let source = include_str!("../netdev.rs");
    assert!(source.contains("pub(crate) inner: IfaceRegistryLock"));
    assert!(source.contains("self.0.lock_bh::<sched::bh::SchedBh>()"),
        "the RX-softirq-shared interface registry must use spin_lock_bh");
}

fn record_carrier_newlink(event: &crate::control_event::ControlEvent) {
    if matches!(event, crate::control_event::ControlEvent::Link(link)
        if link.kind == crate::control_event::EventKind::New && link.name == "carrier0") {
        CARRIER_NEWLINKS.fetch_add(1, Ordering::Relaxed);
    }
}

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
fn driver_carrier_transition_updates_the_reported_link_state() {
    let domain = crate::hosted_fixture::init_net_domain();
    domain.set_notifier(record_carrier_newlink);
    CARRIER_NEWLINKS.store(0, Ordering::Relaxed);
    let stack = crate::NetStack::new();
    let owner = owner();
    let reg = stack.prepare_iface(Arc::new(DummyDev {
        name: "carrier0", mtu: 1500, stats: NetStats::default(),
    }), &owner).unwrap();
    let id = reg.id();
    assert!(stack.publish_iface(reg));
    CARRIER_NEWLINKS.store(0, Ordering::Relaxed);
    let rtnl = stack.rtnl_lock();
    assert!(stack.ifaces.set_iface_flags_in_ns(&rtnl, id, owner.id().as_u64(),
        crate::netdev::iff::IFF_UP, crate::netdev::iff::IFF_UP).is_some());
    drop(rtnl);
    assert_eq!(stack.ifaces.iface_carrier(id), Some(true));
    assert!(stack.set_iface_carrier(id, false));
    assert_eq!(stack.ifaces.iface_carrier(id), Some(false));
    assert_eq!(stack.ifaces.iface_flags(id).unwrap() & crate::netdev::iff::IFF_LOWER_UP, 0);
    assert_eq!(CARRIER_NEWLINKS.load(Ordering::Relaxed), 1,
        "a carrier transition must emit RTM_NEWLINK");
    assert!(stack.set_iface_carrier(id, false), "repeating the current state is harmless");
    assert_eq!(CARRIER_NEWLINKS.load(Ordering::Relaxed), 1,
        "a no-op carrier update must not emit RTM_NEWLINK");
    assert!(stack.set_iface_carrier(id, true));
    assert_eq!(stack.ifaces.iface_carrier(id), Some(true));
    assert_ne!(stack.ifaces.iface_flags(id).unwrap() & crate::netdev::iff::IFF_LOWER_UP, 0);
    assert_eq!(CARRIER_NEWLINKS.load(Ordering::Relaxed), 2);
}

#[test]
fn ingress_admission_requires_exact_device_arc() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
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
    crate::hosted_fixture::spin_until("a resume waiter appears",
        || stack.ifaces.resume_waiters(id) != 0);

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
    crate::hosted_fixture::spin_until("a resume waiter appears",
        || stack.ifaces.resume_waiters(id) != 0);

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
    let stack = crate::NetStack::new();
    let owner = owner();
    let ns = owner.id().as_u64();
    let (id, _) = stack.register_loopback_for(&owner);

    assert_eq!(crate::iface_addr::primary(ns, id).map(|row| row.0), Some(crate::Ipv4Addr::LOOPBACK));
    assert_eq!(stack.routes.lookup_in(ns, crate::Ipv4Addr::LOOPBACK).map(|route| route.iface),
        Some(id));
    assert_eq!(stack.routes6.lookup_in_table_in(ns, crate::policy_rule::RT_TABLE_LOCAL,
        crate::Ipv6Addr::LOOPBACK).map(|route| route.iface), Some(id));
    assert!(stack.v6_addr_owned_by(id, crate::Ipv6Addr::LOOPBACK));
}
