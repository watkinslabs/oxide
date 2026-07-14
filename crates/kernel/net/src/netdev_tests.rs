use super::*;
use sync::TaskList;

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

#[allow(dead_code)]
fn _lock_class_marker() -> TaskList { TaskList }
