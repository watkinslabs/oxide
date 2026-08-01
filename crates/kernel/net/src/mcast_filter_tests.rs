use super::*;
use alloc::sync::Arc;
use core::sync::atomic::AtomicBool;

#[test]
fn unjoined_and_source_filters_gate_delivery() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let state = SocketMcast::new();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let group = Ipv4Addr::new(239, 1, 2, 3);
    let allowed = Ipv4Addr::new(10, 0, 0, 1);
    let denied = Ipv4Addr::new(10, 0, 0, 2);
    // Unconditional multicast delivery is ON at creation, so a group this
    // socket never joined is delivered anyway; clearing it is what makes
    // membership a gate.
    assert!(state.accept_v4(iface, group, allowed));
    state.set_multicast_all_v4(false);
    assert!(!state.accept_v4(iface, group, allowed));
    // Once the socket DOES join, the source filter decides and unconditional
    // delivery has no say either way.
    state.set_v4(&stack, iface, group, Ipv4Addr::LOOPBACK, FilterMode::Include, &[allowed]).unwrap();
    assert!(state.accept_v4(iface, group, allowed));
    assert!(!state.accept_v4(iface, group, denied));
    state.set_multicast_all_v4(true);
    assert!(!state.accept_v4(iface, group, denied));
}

#[test]
fn unconditional_delivery_is_the_creation_default_for_both_families() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let state = SocketMcast::new();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    assert!(state.multicast_all_v4());
    assert!(state.multicast_all_v6());
    let group = Ipv4Addr::new(239, 9, 9, 9);
    let group6 = Ipv6Addr::from_segments([0xff02, 0, 0, 0, 0, 0, 0, 0xfb]);
    assert!(state.accept_v4(iface, group, Ipv4Addr::new(10, 0, 0, 1)));
    assert!(state.accept_v6(iface, group6, Ipv6Addr::LOOPBACK));
    // The two families are cleared independently.
    state.set_multicast_all_v4(false);
    assert!(!state.accept_v4(iface, group, Ipv4Addr::new(10, 0, 0, 1)));
    assert!(state.accept_v6(iface, group6, Ipv6Addr::LOOPBACK));
    state.set_multicast_all_v6(false);
    assert!(!state.accept_v6(iface, group6, Ipv6Addr::LOOPBACK));
    let _ = &stack;
}

#[test]
fn failed_source_operations_do_not_mutate_filter() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let state = SocketMcast::new();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let group = Ipv4Addr::new(239, 1, 2, 4);
    let source = Ipv4Addr::new(10, 0, 0, 1);
    state.change_v4(&stack, iface, group, Ipv4Addr::LOOPBACK, true).unwrap();
    let before = state.get_v4(iface, group).unwrap();
    assert_eq!(state.source_v4(&stack, iface, group, Ipv4Addr::LOOPBACK,
        source, SourceOp::Join), Err(NetError::Eaddrinuse));
    assert_eq!(state.get_v4(iface, group).unwrap(), before);
    assert_eq!(state.source_v4(&stack, iface, group, Ipv4Addr::LOOPBACK,
        source, SourceOp::Unblock), Err(NetError::Eaddrnotavail));
    assert_eq!(state.get_v4(iface, group).unwrap(), before);
}

#[test]
fn include_empty_removes_membership_and_interface_reference() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let state = SocketMcast::new();
    let stack = NetStack::new();
    let (iface, lo) = stack.register_loopback();
    let group = Ipv4Addr::new(232, 1, 2, 5);
    let source = Ipv4Addr::new(10, 0, 0, 2);
    state.set_v4(&stack, iface, group, Ipv4Addr::LOOPBACK,
        FilterMode::Include, &[source]).unwrap();
    let _ = lo.rx_pop().expect("source join report");
    state.set_v4(&stack, iface, group, Ipv4Addr::LOOPBACK,
        FilterMode::Include, &[]).unwrap();
    let leave = lo.rx_pop().expect("include-empty leave report");
    let header_len = usize::from(leave.data()[0] & 0x0f) * 4;
    let body = &leave.data()[header_len..];
    assert_eq!(body[8], crate::igmp::IGMP_V3_RECORD_BLOCK_OLD_SOURCES);
    assert_eq!(u16::from_be_bytes([body[10], body[11]]), 1);
    assert_eq!(&body[16..20], &source.octets());
    // Membership is gone, so only a socket that also cleared unconditional
    // multicast delivery stops accepting the group.
    state.set_multicast_all_v4(false);
    assert!(!state.accept_v4(iface, group, source));
    assert!(stack.v4_mcast.lock().get(&iface).is_some_and(|groups| {
        groups.iter().any(|entry| entry.group == group && entry.is_empty()
            && matches!(entry.change.as_ref().map(|change| &change.report),
                Some(crate::mcast_state::V4Report::Tomb)))
    }));
    stack.retry_multicast_reports(crate::mcast_state::REPORT_INTERVAL_NS);
    let _ = lo.rx_pop().expect("include-empty leave retry");
    assert!(!stack.v4_mcast.lock().get(&iface).is_some_and(|groups| {
        groups.iter().any(|entry| entry.group == group)
    }));
}

#[test]
fn release_clears_socket_before_interface_reporting() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let state = SocketMcast::new();
    let stack = NetStack::new();
    let (iface, lo) = stack.register_loopback();
    let group = Ipv4Addr::new(239, 1, 2, 6);
    state.change_v4(&stack, iface, group, Ipv4Addr::LOOPBACK, true).unwrap();
    let _ = lo.rx_pop().expect("join report");
    state.release(&stack);
    // Release drops the membership; with unconditional delivery cleared the
    // group is then refused.
    state.set_multicast_all_v4(false);
    assert!(!state.accept_v4(iface, group, Ipv4Addr::new(10, 0, 0, 3)));
    assert!(lo.rx_pop().is_some());
}

#[test]
fn v4_membership_and_release_use_captured_namespace() {
    let state = SocketMcast::new();
    let stack = NetStack::new();
    let local_owner = crate::net_ns::test_support::allocate_namespace();
    let foreign_owner = crate::net_ns::test_support::allocate_namespace();
    let local_ns = local_owner.id().as_u64();
    let foreign_ns = foreign_owner.id().as_u64();
    let (local, lo) = stack.register_loopback_in(local_ns);
    let (foreign, _) = stack.register_loopback_in(foreign_ns);
    let group = Ipv4Addr::new(239, 1, 2, 7);
    assert_eq!(state.change_v4_in(&stack, local_ns, foreign, group, Ipv4Addr::LOOPBACK, true),
        Err(NetError::Enodev));
    state.change_v4_in(&stack, local_ns, local, group, Ipv4Addr::LOOPBACK, true).unwrap();
    let _ = lo.rx_pop().expect("namespace join report");
    state.release(&stack);
    assert!(lo.rx_pop().is_some());
    state.set_multicast_all_v4(false);
    assert!(!state.accept_v4(local, group, Ipv4Addr::new(10, 0, 0, 3)));
}

#[test]
fn v6_zero_ifindex_uses_bound_mcast_then_route() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::route6::Route6Entry;
    let stack = NetStack::new();
    let (route_iface, _) = stack.register_loopback();
    let (selected_iface, _) = stack.register_loopback();
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x1234]);
    stack.routes6.add(Route6Entry {
        table: crate::policy_rule::RT_TABLE_MAIN,
        dst: Ipv6Addr::ANY, prefix_len: 0, iface: route_iface, gateway: None, src_hint: None,
        origin: crate::route6::Route6Origin::Static,
    });
    assert_eq!(resolve_v6_iface(&stack, 0, 0, 0, 0, group), Ok(route_iface));
    assert_eq!(resolve_v6_iface(&stack, 0, 0, 0, selected_iface.raw(), group), Ok(selected_iface));
    assert_eq!(resolve_v6_iface(&stack, 0, 0, selected_iface.raw(), route_iface.raw(), group), Ok(selected_iface));
    assert_eq!(resolve_v6_iface(&stack, 0, route_iface.raw(), selected_iface.raw(), 0, group), Ok(route_iface));
}

#[test]
fn v6_resolution_rejects_foreign_iface_and_uses_namespace_route() {
    use crate::route6::Route6Entry;
    let stack = NetStack::new();
    let (a, _) = stack.register_loopback_in(51);
    let (b, _) = stack.register_loopback_in(52);
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x4321]);
    stack.routes6.add_in(51, Route6Entry {
        table: crate::policy_rule::RT_TABLE_MAIN,
        dst: Ipv6Addr::ANY, prefix_len: 0, iface: a, gateway: None, src_hint: None,
        origin: crate::route6::Route6Origin::Static,
    });
    assert_eq!(resolve_v6_iface(&stack, 51, 0, 0, 0, group), Ok(a));
    assert_eq!(resolve_v6_iface(&stack, 51, b.raw(), 0, 0, group), Err(NetError::Enodev));
}
#[test]
fn socket_gate_closes_admission_and_waits_active_operation() {
    let gate = Arc::new(SocketMcastGate::new());
    let released = Arc::new(AtomicBool::new(false));
    let operation = gate.enter(&released).unwrap();
    let closing = gate.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        closing.close_wait();
        done_tx.send(()).unwrap();
    });
    crate::hosted_fixture::spin_until("the released gate rejects entry",
        || matches!(gate.enter(&released), Err(NetError::Einval)));
    assert!(matches!(done_rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)));

    drop(operation);
    done_rx.recv().unwrap();
    worker.join().unwrap();
    assert!(matches!(gate.enter(&released), Err(NetError::Einval)));
}

#[test]
fn retired_v4_report_work_preserves_replacement_generation() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let group = Ipv4Addr::new(239, 9, 8, 7);
    let filter = SourceFilter { mode: FilterMode::Exclude, sources: alloc::vec::Vec::new() };
    let rtnl = stack.rtnl_lock();
    let iface_generation = stack.multicast_generation_in(&rtnl, 0, iface).unwrap();
    let driver = stack.ifaces.mcast_report_in_ns(iface, 0).unwrap();
    let owner = network_namespace::initial();
    let work = stack.set_ipv4_multicast_rtnl(&rtnl, &owner, 0, iface_generation, 17,
        iface, group, Ipv4Addr::LOOPBACK, Some(&filter)).unwrap();
    driver.retire();
    let replacement_generation = iface_generation + 1;
    {
        let mut state = crate::mcast_state::V4IfaceGroup::new(
            replacement_generation, group, Ipv4Addr::LOOPBACK);
        state.asm_refs = 1;
        state.stage(None, 0);
        stack.v4_mcast.lock().entry(iface).or_default().push(state);
    }
    drop(rtnl);
    stack.finish_v4_multicast(work);
    assert!(stack.v4_mcast.lock().get(&iface).is_some_and(|groups| groups.iter()
        .any(|state| state.iface_generation() == replacement_generation
            && state.group == group && state.change.is_some())));
}

#[test]
fn retired_v6_report_work_preserves_replacement_generation() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x9876]);
    let filter = SourceFilter6 { mode: FilterMode::Exclude, sources: alloc::vec::Vec::new() };
    let rtnl = stack.rtnl_lock();
    let iface_generation = stack.multicast_generation_in(&rtnl, 0, iface).unwrap();
    let driver = stack.ifaces.mcast_report_in_ns(iface, 0).unwrap();
    let owner = network_namespace::initial();
    let work = stack.set_ipv6_multicast_rtnl(&rtnl, &owner, 0, iface_generation, 19,
        iface, group, Ipv6Addr::ANY, Some(&filter)).unwrap();
    driver.retire();
    let replacement_generation = iface_generation + 1;
    {
        let mut state = crate::mcast_state::V6IfaceGroup::new(
            replacement_generation, group, Ipv6Addr::ANY);
        state.asm_refs = 1;
        state.stage(None, 0);
        stack.v6_mcast.lock().entry(iface).or_default().push(state);
    }
    drop(rtnl);
    stack.finish_v6_multicast(work);
    assert!(stack.v6_mcast.lock().get(&iface).is_some_and(|groups| groups.iter()
        .any(|state| state.iface_generation() == replacement_generation
            && state.group == group && state.change.is_some())));
}

#[test]
fn rtnl_report_work_rejects_foreign_namespace_owner_before_mutation() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let foreign = crate::net_ns::test_support::allocate_namespace();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let v4_group = Ipv4Addr::new(239, 9, 8, 8);
    let v6_group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x9877]);
    let v4_filter = SourceFilter { mode: FilterMode::Exclude, sources: alloc::vec::Vec::new() };
    let v6_filter = SourceFilter6 { mode: FilterMode::Exclude, sources: alloc::vec::Vec::new() };
    let rtnl = stack.rtnl_lock();
    let generation = stack.multicast_generation_in(&rtnl, 0, iface).unwrap();
    assert!(matches!(stack.set_ipv4_multicast_rtnl(&rtnl, &foreign, 0, generation, 23,
        iface, v4_group, Ipv4Addr::LOOPBACK, Some(&v4_filter)), Err(NetError::Enodev)));
    assert!(matches!(stack.set_ipv6_multicast_rtnl(&rtnl, &foreign, 0, generation, 29,
        iface, v6_group, Ipv6Addr::ANY, Some(&v6_filter)), Err(NetError::Enodev)));
    assert!(!stack.v4_mcast.lock().contains_key(&iface));
    assert!(!stack.v6_mcast.lock().contains_key(&iface));
}
