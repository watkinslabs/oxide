use super::*;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::{
    Ipv4Addr, Ipv6Addr, MacAddr, NamespaceDropAction, NetDev, NetResult,
    NetStack, Pkt, UnixRegistry,
};

struct PersistentDev { retired: AtomicBool }

fn owner() -> network_namespace::NetworkNamespaceRef {
    test_support::allocate_namespace()
}

impl NetDev for PersistentDev {
    fn name(&self) -> &str { "phys0" }
    fn mac(&self) -> MacAddr { MacAddr::ZERO }
    fn mtu(&self) -> u32 { 1500 }
    fn retire_namespace(&self) { self.retired.store(true, Ordering::Release); }
    fn namespace_drop_action(&self) -> NamespaceDropAction {
        NamespaceDropAction::MoveToInitial
    }
    fn xmit(&self, _pkt: Pkt) -> NetResult<()> { Ok(()) }
}

// Statics persist across the whole test binary and tests run in
// parallel, so each test uses a UNIQUE ns id + path and cleans up.

#[test]
fn same_id_returns_the_same_state() {
    let owner = owner();
    let a = materialize_state(&owner);
    let b = try_ns_net(owner.id().as_u64()).unwrap();
    assert!(core::ptr::eq(&*a, &*b), "one net_ns id -> one isolated state");
}

#[test]
fn same_path_binds_in_two_ns_and_connect_is_isolated() {
    let _serial = crate::unix_sock::test_support::guard();
    let p = String::from("/run/b518-iso.sock");
    let o1 = owner();
    let o2 = owner();
    let n1 = materialize_state(&o1);
    let n2 = materialize_state(&o2);
    let l1 = n1.unix.bind(p.clone()).expect("bind ns1");
    let l2 = n2.unix.bind(p.clone()).expect("same path in ns2 is free — isolated");
    l1.listen(128, crate::sysctl::DEFAULT_SOMAXCONN);
    l2.listen(128, crate::sysctl::DEFAULT_SOMAXCONN);
    // A connect in ns1 reaches ns1's listener ONLY.
    assert!(n1.unix.connect(&p).is_ok());
    assert_eq!(l1.pending_len(), 1);
    assert_eq!(l2.pending_len(), 0, "ns2's listener is untouched");
    n1.unix.unbind(&p);
    n2.unix.unbind(&p);
}

#[test]
fn listener_in_one_ns_invisible_to_another() {
    let _serial = crate::unix_sock::test_support::guard();
    let p = String::from("/run/b518-cross.sock");
    let o1 = owner();
    let o2 = owner();
    let n1 = materialize_state(&o1);
    let n2 = materialize_state(&o2);
    let _l = n1.unix.bind(p.clone()).expect("bind ns1");
    // connect from ns2 finds nobody -> None (ECONNREFUSED at the ABI).
    assert!(matches!(n2.unix.connect(&p), Err(crate::UnixConnectError::Refused)), "ns2 must not reach ns1's listener");
    n1.unix.unbind(&p);
}

#[test]
fn fresh_ns_bind_is_free_even_when_a_peer_ns_holds_it() {
    let _serial = crate::unix_sock::test_support::guard();
    // ns0 double-bind semantics (EADDRINUSE) are proven on a plain
    // UnixRegistry by the pre-existing unix_sock tests; here we prove
    // a peer ns holding the path does NOT make a fresh ns's bind fail.
    let p = String::from("/run/b518-dup.sock");
    let o1 = owner();
    let n1 = materialize_state(&o1);
    let _held = n1.unix.bind(p.clone()).expect("first bind");
    assert!(n1.unix.bind(p.clone()).is_err(), "double-bind in one ns is EADDRINUSE");
    let o2 = owner();
    let n2 = materialize_state(&o2);
    assert!(n2.unix.bind(p.clone()).is_ok(), "a fresh ns sees the path as free");
    n1.unix.unbind(&p);
    n2.unix.unbind(&p);
}

#[test]
fn dgram_registry_is_per_ns() {
    let _serial = crate::unix_sock::test_support::guard();
    let p = String::from("/run/b518-dgram.sock");
    let o1 = owner();
    let o2 = owner();
    let n1 = materialize_state(&o1);
    let n2 = materialize_state(&o2);
    n1.unix.dgram_bind(p.clone(), crate::UnixDgramQueue::new()).expect("dgram bind ns1");
    assert!(n1.unix.dgram_lookup(&p).is_some());
    assert!(n2.unix.dgram_lookup(&p).is_none(), "ns2 cannot see ns1's dgram bind");
    assert!(n2.unix.dgram_bind(p.clone(), crate::UnixDgramQueue::new()).is_ok());
    n1.unix.dgram_unbind(&p);
    n2.unix.dgram_unbind(&p);
}

// SC1: pathname AF_UNIX sockets are filesystem-global (cross net_ns);
// only abstract addresses are per-net_ns.
#[test]
fn pathname_is_global_abstract_is_per_ns() {
    assert!(unix_path_is_global("/run/dbus/system_bus_socket"),
        "a pathname socket is filesystem-global");
    assert!(unix_path_is_global("/run/systemd/private"),
        "any leading-'/' path is global");
    // Abstract addresses carry a leading NUL byte.
    assert!(!unix_path_is_global("\0/org/freedesktop/systemd1"),
        "an abstract socket (leading NUL) stays per-net_ns");
}

// SC1 regression: a PrivateNetwork=yes service (polkit / rtkit-daemon /
// systemd-hostnamed) runs in a fresh net_ns yet MUST reach the D-Bus
// system bus, a PATHNAME socket bound by dbus-broker in ns 0. Model the
// routing: pathname → the global registry (reachable from any ns);
// abstract → the caller's own ns registry (isolated).
#[test]
fn pathname_socket_reachable_across_net_ns() {
    let _serial = crate::unix_sock::test_support::guard();
    // `g` plays the role of ns 0's global registry; `priv_ns` is a
    // PrivateNetwork service's private registry.
    let g = UnixRegistry::new();
    let priv_ns = UnixRegistry::new();

    let bus = String::from("/run/dbus/system_bus_socket");
    // dbus-broker (ns 0) binds the pathname listener into the global reg.
    let listener = g.bind(bus.clone()).expect("bind system bus in ns 0");
    listener.listen(128, crate::sysctl::DEFAULT_SOMAXCONN);

    // A private-ns client's connect ROUTES by unix_path_is_global: a
    // pathname address resolves against the global registry, NOT its
    // own (empty) private one — the pre-fix bug returned ECONNREFUSED.
    let reg_for_connect = if unix_path_is_global(&bus) { &g } else { &priv_ns };
    assert!(!core::ptr::eq(reg_for_connect, &priv_ns),
        "pathname connect must NOT resolve in the private-ns registry");
    // connect-before-accept: dbus-broker has not accept()'d yet, so the
    // connection must QUEUE into the listen backlog, never be refused.
    let pair = reg_for_connect.connect(&bus);
    assert!(pair.is_ok(), "cross-ns pathname connect must succeed (queue), not ECONNREFUSED");
    assert_eq!(listener.pending_len(), 1,
        "the pending connection is queued for a later accept()");

    // Abstract addresses stay isolated: an abstract listener bound in
    // the private ns is invisible to the global registry.
    let abs = String::from("\0sc1-abstract");
    let _al = priv_ns.bind(abs.clone()).expect("abstract bind in private ns");
    assert!(matches!(g.connect(&abs), Err(crate::UnixConnectError::Refused)),
        "an abstract socket must remain private to its own net_ns");

    g.unbind(&bus);
    priv_ns.unbind(&abs);
}

// SC1: connect() to a bound listener that has not accept()'d yet must
// QUEUE the connection (Linux listen backlog), returning success — the
// whole premise of D-Bus socket activation. It must NOT ECONNREFUSE.
#[test]
fn connect_before_accept_queues_not_refused() {
    let _serial = crate::unix_sock::test_support::guard();
    let reg = UnixRegistry::new();
    let p = String::from("/run/sc1-queue.sock");
    let l = reg.bind(p.clone()).expect("bind");
    l.listen(128, crate::sysctl::DEFAULT_SOMAXCONN);
    // No accept() has run.
    assert_eq!(l.pending_len(), 0);
    assert!(reg.connect(&p).is_ok(), "connect-before-accept queues");
    assert!(reg.connect(&p).is_ok(), "a second pending connection also queues");
    assert_eq!(l.pending_len(), 2, "both connections wait in the backlog");
    // A connect to an UNbound path is refused (None → ECONNREFUSED).
    assert!(matches!(reg.connect("/run/sc1-nobody"), Err(crate::UnixConnectError::Refused)),
        "no listener bound → ECONNREFUSED");
    reg.unbind(&p);
}

#[test]
fn fresh_ns_sees_loopback_only() {
    let owner = owner();
    let ns = owner.id().as_u64();
    let stack = NetStack::new();
    assert!(stack.ifaces.snapshot_devs_in_ns(ns).is_empty(), "ns starts empty");
    materialize_loopback_into(&stack, &owner);
    let devs = stack.ifaces.snapshot_devs_in_ns(ns);
    assert_eq!(devs.len(), 1, "loopback only");
    assert_eq!(devs[0].1.name(), "lo");
    // Idempotent — a second call does not duplicate lo.
    materialize_loopback_into(&stack, &owner);
    assert_eq!(stack.ifaces.snapshot_devs_in_ns(ns).len(), 1);
    // And it carries the 127.0.0.1/8 host address, privately.
    let addrs = crate::iface_addr::snapshot_ns(ns);
    assert!(addrs.iter().any(|a| a.addr == Ipv4Addr::LOOPBACK && a.prefixlen == 8));
    let id = devs[0].0;
    assert!(stack.v6_addr_owned_by(id, Ipv6Addr::LOOPBACK));
    assert_eq!(stack.routes6.lookup_in_table_in(ns, crate::policy_rule::RT_TABLE_LOCAL,
        Ipv6Addr::LOOPBACK).map(|r| r.iface), Some(id));
    assert!(stack.routes6.lookup(Ipv6Addr::LOOPBACK).is_none());
}

#[test]
fn concurrent_materialization_publishes_one_loopback() {
    let stack = Arc::new(NetStack::new());
    let owner = owner();
    let ns = owner.id().as_u64();
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let mut workers = alloc::vec::Vec::new();
    for _ in 0..2 {
        let stack = stack.clone();
        let owner = owner.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            materialize_loopback_into(&stack, &owner);
        }));
    }
    barrier.wait();
    for worker in workers { worker.join().unwrap(); }
    assert_eq!(stack.ifaces.snapshot_devs_in_ns(ns).len(), 1);
    assert_eq!(crate::iface_addr::snapshot_ns(ns).len(), 1);
    assert_eq!(stack.routes.snapshot_in(ns).len(), 1);
    assert_eq!(stack.routes6.snapshot_in(ns).len(), 1);
}

#[test]
fn namespace_teardown_removes_owned_state_only() {
    let stack = NetStack::new();
    let owner_a = owner();
    let owner_b = owner();
    let a = owner_a.id().as_u64();
    let b = owner_b.id().as_u64();
    materialize_loopback_into(&stack, &owner_a);
    materialize_loopback_into(&stack, &owner_b);
    let persistent = Arc::new(PersistentDev { retired: AtomicBool::new(false) });
    let persistent_iface = stack.ifaces.register_in_ns(persistent.clone(), a);
    let a_iface = stack.ifaces.lookup_name_in_ns("lo", a).unwrap().0;
    let b_iface = stack.ifaces.lookup_name_in_ns("lo", b).unwrap().0;
    stack.ndp_insert(a_iface, Ipv6Addr::LOOPBACK, crate::MacAddr::ZERO);
    stack.v6_mcast.lock().entry(a_iface).or_default();
    {
        let rtnl = stack.rtnl_lock();
        stack.policy_rules().insert_rtnl(&rtnl, crate::policy_rule::PolicyRule {
            ns: a, family: crate::policy_rule::AF_INET6, dst_len: 0, src_len: 0,
            tos: 0, table: crate::policy_rule::RT_TABLE_MAIN,
            action: crate::policy_rule::FR_ACT_TO_TBL, flags: 0, priority: 100,
        });
    }
    let frag4_a = crate::ipv4_reasm::ReasmKey {
        net_ns: a, domain: 0, src: Ipv4Addr::LOOPBACK, dst: Ipv4Addr::LOOPBACK,
        proto: 17, id: 81,
    };
    let frag4_b = crate::ipv4_reasm::ReasmKey { net_ns: b, ..frag4_a };
    let frag6_a = crate::ipv6_reasm::ReasmKey {
        net_ns: a, src: Ipv6Addr::LOOPBACK, dst: Ipv6Addr::LOOPBACK,
        next_header: 17, id: 82,
    };
    let frag6_b = crate::ipv6_reasm::ReasmKey { net_ns: b, ..frag6_a };
    assert!(stack.ipv4_reasm.push(frag4_a, 1, 0, b"aaaaaaaa", true).is_none());
    assert!(stack.ipv4_reasm.push(frag4_b, 1, 0, b"bbbbbbbb", true).is_none());
    assert!(stack.ipv6_reasm.push(frag6_a, 1, 0, b"aaaaaaaa", true).is_none());
    assert!(stack.ipv6_reasm.push(frag6_b, 1, 0, b"bbbbbbbb", true).is_none());
    let _ = materialize_state(&owner_a);
    let _ = stack.inet_tables(a);
    assert!(destroy_namespace_into(&stack, a));
    assert!(stack.ifaces.snapshot_devs_in_ns(a).is_empty());
    assert_eq!(stack.ifaces.namespace(persistent_iface), Some(0));
    assert!(persistent.retired.load(Ordering::Acquire));
    assert!(crate::iface_addr::snapshot_ns(a).is_empty());
    assert!(stack.routes6.snapshot_in(a).is_empty());
    assert!(stack.routes.snapshot_in(a).is_empty());
    assert!(!stack.inet.lock().contains_key(&a));
    assert!(stack.ndp_lookup(a_iface, Ipv6Addr::LOOPBACK).is_none());
    assert!(!stack.v6_mcast.lock().contains_key(&a_iface));
    assert!(stack.policy_rules().snapshot_custom_ns(a).is_empty());
    assert!(!NET_NS.lock().contains_key(&a));
    assert!(!destroy_namespace_into(&stack, a));
    assert!(stack.ipv4_reasm.push(frag4_a, 2, 8, b"AAAA", false).is_none());
    assert_eq!(stack.ipv4_reasm.push(frag4_b, 2, 8, b"BBBB", false).unwrap(),
        b"bbbbbbbbBBBB");
    assert!(stack.ipv6_reasm.push(frag6_a, 2, 8, b"AAAA", false).is_none());
    assert_eq!(stack.ipv6_reasm.push(frag6_b, 2, 8, b"BBBB", false).unwrap(),
        b"bbbbbbbbBBBB");
    assert_eq!(stack.ifaces.lookup_name_in_ns("lo", b).map(|v| v.0), Some(b_iface));
    assert!(stack.routes6.lookup_in_table_in(b, crate::policy_rule::RT_TABLE_LOCAL,
        Ipv6Addr::LOOPBACK).is_some());
    assert!(!destroy_namespace_into(&stack, 0));
}
