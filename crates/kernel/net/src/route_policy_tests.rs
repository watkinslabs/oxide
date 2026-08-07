use super::*;

fn rule(ns: u64, table: u32) -> policy_rule::PolicyRule {
    policy_rule::PolicyRule { ns, family: policy_rule::AF_INET, priority: 100, table,
        action: policy_rule::FR_ACT_TO_TBL, dst_len: 0, src_len: 0, tos: 0, flags: 0, fwmark: 0, fwmask: 0 }
}

#[test]
fn custom_policy_rule_selects_custom_table() {
    let stack = crate::NetStack::new();
    stack.routes.add(RouteEntry::main(Ipv4Addr::ANY, 0, NetIfaceId::from_raw(1), None, None));
    stack.routes.add(RouteEntry { table: 100, dst: Ipv4Addr::ANY, prefix_len: 0,
        iface: NetIfaceId::from_raw(2), gateway: None, src_hint: None });
    { let rtnl = stack.rtnl_lock(); stack.policy_rules().insert_rtnl(&rtnl, rule(0, 100)); }
    let r = stack.routes.lookup_in(0, Ipv4Addr::new(8, 8, 8, 8)).unwrap();
    assert_eq!(r.iface, NetIfaceId::from_raw(2));
}

#[test]
fn fwmark_rule_selects_its_table_only_for_matching_packet_mark() {
    const NS: u64 = 0x8250_1001;
    let stack = crate::NetStack::new();
    let dst = Ipv4Addr::new(198, 51, 100, 8);
    stack.routes.add_in(NS, RouteEntry::main(
        Ipv4Addr::ANY, 0, NetIfaceId::from_raw(1), None, None));
    stack.routes.add_in(NS, RouteEntry { table: 101, dst: Ipv4Addr::ANY, prefix_len: 0,
        iface: NetIfaceId::from_raw(101), gateway: None, src_hint: None });
    let marked = policy_rule::PolicyRule { fwmark: 0x20, fwmask: 0xf0,
        ..rule(NS, 101) };
    { let rtnl = stack.rtnl_lock(); stack.policy_rules().insert_rtnl(&rtnl, marked); }

    assert_eq!(stack.routes.lookup_record_mark_in(NS, dst, 0x21)
        .map(|record| record.route.iface), Some(NetIfaceId::from_raw(101)));
    assert_eq!(stack.routes.lookup_record_mark_in(NS, dst, 0x11)
        .map(|record| record.route.iface), Some(NetIfaceId::from_raw(1)));
}

#[test]
fn throw_route_continues_with_next_policy_rule() {
    const NS: u64 = 0x8250_2001;
    let stack = crate::NetStack::new();
    let thrown = RouteEntry { table: 100, dst: Ipv4Addr::ANY, prefix_len: 0,
        iface: NetIfaceId::from_raw(0), gateway: None, src_hint: None };
    stack.routes.add_record_in(NS, RouteRecord { kind: RTN_THROW, ..RouteRecord::kernel(thrown) });
    stack.routes.add_in(NS, RouteEntry::main(
        Ipv4Addr::ANY, 0, NetIfaceId::from_raw(9), None, None));
    { let rtnl = stack.rtnl_lock(); stack.policy_rules().insert_rtnl(&rtnl, rule(NS, 100)); }
    let route = stack.routes.lookup_result_in(NS, Ipv4Addr::new(203, 0, 113, 1)).unwrap();
    assert_eq!(route.iface, NetIfaceId::from_raw(9));
}

#[test]
fn two_stacks_route_through_their_own_policy_tables() {
    const NS: u64 = 0x8250_3001;
    let a = crate::NetStack::new();
    let b = crate::NetStack::new();
    assert!(core::ptr::eq(a.policy_rules(), a.routes.policy_rules()));
    assert!(core::ptr::eq(b.policy_rules(), b.routes.policy_rules()));
    for stack in [&a, &b] {
        stack.routes.add_in(NS, RouteEntry::main(
            Ipv4Addr::ANY, 0, NetIfaceId::from_raw(1), None, None));
        stack.routes.add_in(NS, RouteEntry { table: 100, dst: Ipv4Addr::ANY, prefix_len: 0,
            iface: NetIfaceId::from_raw(100), gateway: None, src_hint: None });
        stack.routes.add_in(NS, RouteEntry { table: 200, dst: Ipv4Addr::ANY, prefix_len: 0,
            iface: NetIfaceId::from_raw(200), gateway: None, src_hint: None });
    }
    { let rtnl = a.rtnl_lock(); a.policy_rules().insert_rtnl(&rtnl, rule(NS, 100)); }
    { let rtnl = b.rtnl_lock(); b.policy_rules().insert_rtnl(&rtnl, rule(NS, 200)); }
    let dst = Ipv4Addr::new(198, 51, 100, 7);
    assert_eq!(a.routes.lookup_in(NS, dst).unwrap().iface,
        NetIfaceId::from_raw(100));
    assert_eq!(b.routes.lookup_in(NS, dst).unwrap().iface,
        NetIfaceId::from_raw(200));
}

#[test]
fn equal_priority_rules_keep_insertion_order() {
    const NS: u64 = 0x8250_4001;
    let stack = crate::NetStack::new();
    for (table, iface) in [(100, 100), (200, 200)] {
        stack.routes.add_in(NS, RouteEntry { table, dst: Ipv4Addr::ANY, prefix_len: 0,
            iface: NetIfaceId::from_raw(iface), gateway: None, src_hint: None });
    }
    let first = rule(NS, 100);
    let second = rule(NS, 200);
    {
        let rtnl = stack.rtnl_lock();
        stack.policy_rules().insert_rtnl(&rtnl, first);
        stack.policy_rules().insert_rtnl(&rtnl, second);
    }
    let dst = Ipv4Addr::new(192, 0, 2, 1);
    assert_eq!(stack.routes.lookup_in(NS, dst).unwrap().iface, NetIfaceId::from_raw(100));
    {
        let rtnl = stack.rtnl_lock();
        assert_eq!(stack.policy_rules().remove_one_rtnl(
            &rtnl, NS, policy_rule::AF_INET, Some(100), None), Some(first));
    }
    assert_eq!(stack.routes.lookup_in(NS, dst).unwrap().iface, NetIfaceId::from_raw(200));
}

#[test]
fn ipv6_policy_rule_selects_custom_table() {
    const NS: u64 = 0x8250_6001;
    let stack = crate::NetStack::new();
    let main = NetIfaceId::from_raw(6);
    let custom = NetIfaceId::from_raw(106);
    let dst = crate::Ipv6Addr::from_segments([0x2001, 0xdb8, 6, 0, 0, 0, 0, 1]);
    stack.routes6.add_in(NS, crate::Route6Entry {
        table: policy_rule::RT_TABLE_MAIN, dst: crate::Ipv6Addr::ANY, prefix_len: 0,
        iface: main, gateway: None, src_hint: None,
        origin: crate::Route6Origin::Static,
    });
    stack.routes6.add_in(NS, crate::Route6Entry {
        table: 600, dst: crate::Ipv6Addr::ANY, prefix_len: 0,
        iface: custom, gateway: None, src_hint: None,
        origin: crate::Route6Origin::Static,
    });
    let row = policy_rule::PolicyRule {
        ns: NS, family: policy_rule::AF_INET6, priority: 100, table: 600,
        action: policy_rule::FR_ACT_TO_TBL, dst_len: 0, src_len: 0, tos: 0, flags: 0, fwmark: 0, fwmask: 0,
    };
    { let rtnl = stack.rtnl_lock(); stack.policy_rules().insert_rtnl(&rtnl, row); }

    assert_eq!(stack.routes6.lookup_policy_in(NS, dst, stack.policy_rules())
        .map(|route| route.iface), Some(custom));
}

#[test]
fn deleting_builtin_main_rule_changes_ipv4_datapath() {
    const NS: u64 = 0x8250_7001;
    let stack = crate::NetStack::new();
    let dst = Ipv4Addr::new(198, 51, 100, 19);
    stack.routes.add_in(NS, RouteEntry::main(
        Ipv4Addr::ANY, 0, NetIfaceId::from_raw(7), None, None));
    assert_eq!(stack.routes.lookup_in(NS, dst).map(|route| route.iface),
        Some(NetIfaceId::from_raw(7)));
    {
        let rtnl = stack.rtnl_lock();
        assert_eq!(stack.policy_rules().remove_one_rtnl(&rtnl, NS, policy_rule::AF_INET,
            Some(32766), Some(policy_rule::RT_TABLE_MAIN)),
            Some(policy_rule::builtin_rules(NS, policy_rule::AF_INET)[1]));
    }
    assert!(stack.routes.lookup_in(NS, dst).is_none());
    assert!(!stack.policy_rules().snapshot_effective(NS, policy_rule::AF_INET).iter()
        .any(|row| row.priority == 32766 && row.table == policy_rule::RT_TABLE_MAIN));
}
