use super::*;

#[test]
fn lookup_default_matches_anything() {
    let t = RouteTable::new();
    t.add(RouteEntry::main(Ipv4Addr::ANY, 0, NetIfaceId::from_raw(1), None, None));
    let r = t.lookup(Ipv4Addr::new(8, 8, 8, 8)).unwrap();
    assert_eq!(r.iface, NetIfaceId::from_raw(1));
}

#[test]
fn longest_prefix_wins() {
    let t = RouteTable::new();
    t.add(RouteEntry::main(Ipv4Addr::ANY, 0, NetIfaceId::from_raw(1), None, None));
    t.add(RouteEntry::main(
        Ipv4Addr::new(127, 0, 0, 0), 8, NetIfaceId::from_raw(2), None, None,
    ));
    let r = t.lookup(Ipv4Addr::LOOPBACK).unwrap();
    assert_eq!(r.iface, NetIfaceId::from_raw(2));
}

#[test]
fn no_match_returns_none() {
    let t = RouteTable::new();
    t.add(RouteEntry::main(
        Ipv4Addr::new(10, 0, 0, 0), 8, NetIfaceId::from_raw(1), None, None,
    ));
    assert!(t.lookup(Ipv4Addr::new(8, 8, 8, 8)).is_none());
}

#[test]
fn ecmp_equal_prefix_uses_destination_hash() {
    let t = RouteTable::new();
    t.add(RouteEntry::main(Ipv4Addr::ANY, 0, NetIfaceId::from_raw(1), None, None));
    t.add(RouteEntry::main(Ipv4Addr::ANY, 0, NetIfaceId::from_raw(2), None, None));
    let first = t.lookup(Ipv4Addr::new(203, 0, 113, 1)).unwrap().iface;
    let mut saw_other = false;
    for last in 2..=254 {
        let r = t.lookup(Ipv4Addr::new(203, 0, 113, last)).unwrap();
        if r.iface != first {
            saw_other = true;
            break;
        }
    }
    assert!(saw_other);
    assert_eq!(t.lookup(Ipv4Addr::new(203, 0, 113, 1)).unwrap().iface, first);
}

#[test]
fn lower_metric_wins_before_ecmp_selection() {
    let t = RouteTable::new();
    t.add_record_in(0, RouteRecord {
        route: RouteEntry::main(Ipv4Addr::ANY, 0, NetIfaceId::from_raw(1), None, None),
        metric: 200,
        ..RouteRecord::kernel(RouteEntry::main(
            Ipv4Addr::ANY, 0, NetIfaceId::from_raw(1), None, None,
        ))
    });
    t.add_record_in(0, RouteRecord {
        route: RouteEntry::main(Ipv4Addr::ANY, 0, NetIfaceId::from_raw(2), None, None),
        metric: 100,
        ..RouteRecord::kernel(RouteEntry::main(
            Ipv4Addr::ANY, 0, NetIfaceId::from_raw(2), None, None,
        ))
    });
    for last in 1..=32 {
        let record = t.lookup_record_in(0, Ipv4Addr::new(203, 0, 113, last)).unwrap();
        assert_eq!((record.route.iface, record.metric), (NetIfaceId::from_raw(2), 100));
    }
}

#[test]
fn equal_prefix_metric_different_aliases_do_not_form_ecmp() {
    let t = RouteTable::new();
    let first = RouteEntry::main(
        Ipv4Addr::ANY, 0, NetIfaceId::from_raw(1), None, None,
    );
    let second = RouteEntry::main(
        Ipv4Addr::ANY, 0, NetIfaceId::from_raw(2), None, None,
    );
    t.add_record_in(0, RouteRecord::kernel(first));
    t.add_record_in(0, RouteRecord { protocol: 99, ..RouteRecord::kernel(second) });
    for last in 1..=254 {
        assert_eq!(
            t.lookup(Ipv4Addr::new(203, 0, 113, last)).unwrap().iface,
            NetIfaceId::from_raw(1),
        );
    }
}
