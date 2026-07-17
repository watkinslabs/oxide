use super::*;
use sync::TaskList;

#[path = "netdev_tests/uninstall.rs"]
mod uninstall;
#[path = "netdev_tests/registration.rs"]
mod registration;
#[path = "netdev_tests/tx_dispatch.rs"]
mod tx_dispatch;

struct DummyDev { name: &'static str, mtu: u32, stats: NetStats }
impl NetDev for DummyDev {
    fn name(&self) -> &str { self.name }
    fn mac(&self) -> MacAddr { MacAddr::ZERO }
    fn mtu(&self) -> u32 { self.mtu }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> NamespaceDropAction { NamespaceDropAction::Destroy }
    fn xmit(&self, _pkt: Pkt) -> NetResult<()> { Ok(()) }
    fn stats(&self) -> NetStats { self.stats }
}

struct PersistentDev;
impl NetDev for PersistentDev {
    fn name(&self) -> &str { "persist0" }
    fn mac(&self) -> MacAddr { MacAddr::ZERO }
    fn mtu(&self) -> u32 { 1500 }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> NamespaceDropAction { NamespaceDropAction::MoveToInitial }
    fn xmit(&self, _pkt: Pkt) -> NetResult<()> { Ok(()) }
}

fn owner() -> network_namespace::NetworkNamespaceRef {
    crate::net_ns::test_support::allocate_namespace()
}

#[test]
fn register_assigns_increasing_ids() {
    let r = IfaceRegistry::new();
    let a = r.register(Arc::new(DummyDev { name: "lo", mtu: 65535, stats: NetStats::default() }));
    let b = r.register(Arc::new(DummyDev { name: "eth0", mtu: 1500, stats: NetStats::default() }));
    assert_ne!(a, b);
    assert!(r.lookup(a).is_some());
    assert_eq!(r.lookup_name("lo").unwrap().0, a);
    assert_eq!(r.lookup_name("eth0").unwrap().0, b);
}

#[test]
fn lookup_missing_returns_none() {
    let r = IfaceRegistry::new();
    assert!(r.lookup(NetIfaceId::from_raw(99)).is_none());
    assert!(r.lookup_name("nope").is_none());
}

#[test]
fn snapshot_lists_all() {
    let r = IfaceRegistry::new();
    r.register(Arc::new(DummyDev { name: "lo", mtu: 65535, stats: NetStats::default() }));
    r.register(Arc::new(DummyDev { name: "eth0", mtu: 1500, stats: NetStats::default() }));
    let s = r.snapshot();
    assert_eq!(s.len(), 2);
    assert!(s.iter().any(|t| t.name == "lo"));
    assert!(s.iter().any(|t| t.name == "eth0"));
}

#[test]
fn snapshot_carries_live_stats_without_second_lookup() {
    let r = IfaceRegistry::new();
    let stats = NetStats {
        rx_packets: 11, rx_bytes: 1100, rx_errors: 1, rx_dropped: 2,
        tx_packets: 13, tx_bytes: 1300, tx_errors: 3, tx_dropped: 4,
    };
    let id = r.register(Arc::new(DummyDev { name: "eth0", mtu: 1500, stats }));
    let s = r.snapshot();
    let row = s.iter().find(|t| t.id == id).unwrap();
    assert_eq!(row.name, "eth0");
    assert_eq!(row.mtu, 1500);
    assert_eq!(row.stats.rx_packets, 11);
    assert_eq!(row.stats.tx_dropped, 4);
}

#[test]
fn netstats_field_maps_known_counters() {
    let st = NetStats {
        rx_packets: 7, rx_bytes: 700, rx_errors: 1, rx_dropped: 2,
        tx_packets: 9, tx_bytes: 900, tx_errors: 4, tx_dropped: 3,
    };
    assert_eq!(st.field("rx_packets"), Some(7));
    assert_eq!(st.field("tx_packets"), Some(9));
    assert_eq!(st.field("rx_bytes"),   Some(700));
    assert_eq!(st.field("tx_bytes"),   Some(900));
    assert_eq!(st.field("rx_errors"),  Some(1));
    assert_eq!(st.field("tx_errors"),  Some(4));
    assert_eq!(st.field("rx_dropped"), Some(2));
    assert_eq!(st.field("tx_dropped"), Some(3));
}

#[test]
fn netstats_field_unbacked_is_zero_known_is_none() {
    let st = NetStats::default();
    assert_eq!(st.field("multicast"),      Some(0));
    assert_eq!(st.field("collisions"),     Some(0));
    assert_eq!(st.field("rx_over_errors"), Some(0));
    assert_eq!(st.field("rx_nohandler"),   Some(0));
    assert_eq!(st.field("bogus"), None);
    assert_eq!(st.field(""),      None);
}

#[test]
fn stat_fields_match_linux_names_and_count() {
    assert_eq!(STAT_FIELDS[0], "rx_packets");
    assert_eq!(STAT_FIELDS[1], "tx_packets");
    assert!(STAT_FIELDS.contains(&"collisions"));
    assert!(STAT_FIELDS.contains(&"rx_nohandler"));
    assert_eq!(STAT_FIELDS.len(), 24);
}

#[test]
fn held_ingress_lease_closes_admission_and_blocks_move_until_release() {
    let stack = Arc::new(crate::NetStack::new());
    let owner = owner();
    let net_ns = owner.id().as_u64();
    let iface = stack.ifaces.register_in_ns(Arc::new(PersistentDev), net_ns);
    let lease = stack.ifaces.acquire_ingress(iface).unwrap();
    assert_eq!(lease.iface(), iface);
    assert_eq!(lease.net_ns(), net_ns);
    assert_eq!(lease.generation(), 1);

    let worker = stack.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let teardown = std::thread::spawn(move || {
        done_tx.send(worker.teardown_iface_in(net_ns, iface)).unwrap();
    });
    loop {
        match stack.ifaces.acquire_ingress(iface) {
            Some(probe) => drop(probe),
            None => break,
        }
        std::thread::yield_now();
    }
    assert!(matches!(done_rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)));
    assert_eq!(stack.ifaces.namespace(iface), None);

    drop(lease);
    assert!(done_rx.recv().unwrap());
    teardown.join().unwrap();
    let moved = stack.ifaces.acquire_ingress(iface).unwrap();
    assert_eq!(moved.net_ns(), 0);
    assert_eq!(moved.generation(), 2);
}

#[test]
fn stale_ingress_generation_cannot_acquire_after_move() {
    let stack = crate::NetStack::new();
    let owner = owner();
    let net_ns = owner.id().as_u64();
    let iface = stack.ifaces.register_in_ns(Arc::new(PersistentDev), net_ns);
    let generation = stack.ifaces.acquire_ingress(iface).unwrap().generation();
    assert!(stack.teardown_iface_in(net_ns, iface));
    assert!(stack.ifaces.acquire_ingress_generation(iface, generation).is_none());
    assert_eq!(stack.ifaces.acquire_ingress(iface).unwrap().generation(), generation + 1);
}

#[test]
fn destroyed_ingress_gate_does_not_reopen() {
    let stack = crate::NetStack::new();
    let owner = owner();
    let net_ns = owner.id().as_u64();
    let iface = stack.ifaces.register_in_ns(Arc::new(DummyDev {
        name: "drop0", mtu: 1500, stats: NetStats::default(),
    }), net_ns);
    assert!(stack.teardown_iface_in(net_ns, iface));
    assert!(stack.ifaces.acquire_ingress(iface).is_none());
}

#[test]
fn ingress_lease_retains_concrete_namespace_owner() {
    let stack = crate::NetStack::new();
    let owner = owner();
    let net_ns = owner.id().as_u64();
    let iface = stack.ifaces.register_in_ns(Arc::new(PersistentDev), net_ns);
    let lease = stack.ifaces.acquire_ingress(iface).unwrap();

    drop(owner);
    assert!(network_namespace::lookup_u64(net_ns).is_some());
    drop(lease);
    assert!(network_namespace::lookup_u64(net_ns).is_none());
}

#[test]
fn name_lease_matches_exact_rtnl_namespace_generation() {
    let stack = crate::NetStack::new();
    let owner = owner();
    let net_ns = owner.id().as_u64();
    let iface = stack.ifaces.register_in_ns(Arc::new(PersistentDev), net_ns);
    let lease = stack.ifaces.acquire_ingress_name_in_ns("persist0", net_ns).unwrap();
    let rtnl = stack.rtnl_lock();
    let (found, _, generation) = stack.ifaces
        .control_ready_name_generation_in_ns(&rtnl, "persist0", net_ns).unwrap();

    assert_eq!(found, iface);
    assert_eq!(found, lease.iface());
    assert_eq!(generation, lease.generation());
    assert!(stack.ifaces.acquire_ingress_name_in_ns("persist0", 0).is_none());
}

#[test]
fn registry_rename_updates_canonical_namespace_name_and_rejects_collision() {
    let stack = crate::NetStack::new();
    let owner = owner();
    let ns = owner.id().as_u64();
    let first = stack.ifaces.register_in_ns(Arc::new(PersistentDev), ns);
    let second = stack.ifaces.register_in_ns(Arc::new(PersistentDev), ns);
    let rtnl = stack.rtnl_lock();
    assert_eq!(stack.ifaces.rename_in_ns(&rtnl, first, ns, "renamed"), Ok(String::from("persist0")));
    assert_eq!(stack.ifaces.name_in_ns(first, ns).as_deref(), Some("renamed"));
    assert_eq!(stack.ifaces.rename_in_ns(&rtnl, second, ns, "renamed"),
        Err(syscall::errno::Errno::Eexist));
}

#[allow(dead_code)]
fn _lock_class_marker() -> TaskList { TaskList }
