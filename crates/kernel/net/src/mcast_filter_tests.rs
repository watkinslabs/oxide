use super::*;

#[test]
fn unjoined_and_source_filters_gate_delivery() {
    let state = SocketMcast::new();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let group = Ipv4Addr::new(239, 1, 2, 3);
    let allowed = Ipv4Addr::new(10, 0, 0, 1);
    let denied = Ipv4Addr::new(10, 0, 0, 2);
    assert!(!state.accept_v4(iface, group, allowed));
    state.set_v4(&stack, iface, group, Ipv4Addr::LOOPBACK, FilterMode::Include, &[allowed]).unwrap();
    assert!(state.accept_v4(iface, group, allowed));
    assert!(!state.accept_v4(iface, group, denied));
}

#[test]
fn failed_source_operations_do_not_mutate_filter() {
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
    let state = SocketMcast::new();
    let stack = NetStack::new();
    let (iface, lo) = stack.register_loopback();
    let group = Ipv4Addr::new(239, 1, 2, 6);
    state.change_v4(&stack, iface, group, Ipv4Addr::LOOPBACK, true).unwrap();
    let _ = lo.rx_pop().expect("join report");
    state.release(&stack);
    assert!(!state.accept_v4(iface, group, Ipv4Addr::new(10, 0, 0, 3)));
    assert!(lo.rx_pop().is_some());
}

#[test]
fn v4_membership_and_release_use_captured_namespace() {
    let state = SocketMcast::new();
    let stack = NetStack::new();
    let (local, lo) = stack.register_loopback_in(61);
    let (foreign, _) = stack.register_loopback_in(62);
    let group = Ipv4Addr::new(239, 1, 2, 7);
    assert_eq!(state.change_v4_in(&stack, 61, foreign, group, Ipv4Addr::LOOPBACK, true),
        Err(NetError::Enodev));
    state.change_v4_in(&stack, 61, local, group, Ipv4Addr::LOOPBACK, true).unwrap();
    let _ = lo.rx_pop().expect("namespace join report");
    state.release(&stack);
    assert!(lo.rx_pop().is_some());
    assert!(!state.accept_v4(local, group, Ipv4Addr::new(10, 0, 0, 3)));
}

#[test]
fn v6_zero_ifindex_uses_bound_mcast_then_route() {
    use crate::route6::Route6Entry;
    let stack = NetStack::new();
    let (route_iface, _) = stack.register_loopback();
    let (selected_iface, _) = stack.register_loopback();
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x1234]);
    stack.routes6.add(Route6Entry {
        dst: Ipv6Addr::ANY, prefix_len: 0, iface: route_iface, gateway: None, src_hint: None,
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
        dst: Ipv6Addr::ANY, prefix_len: 0, iface: a, gateway: None, src_hint: None,
    });
    assert_eq!(resolve_v6_iface(&stack, 51, 0, 0, 0, group), Ok(a));
    assert_eq!(resolve_v6_iface(&stack, 51, b.raw(), 0, 0, group), Err(NetError::Enodev));
}
