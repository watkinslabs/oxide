// Linux `__inet_lookup_listener` tier and dual-stack rules for the TCP
// listener demux (`lookup_listen_bucket`).
use super::*;

const PORT: u16 = 22;
const LOCAL_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
const OTHER_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 99);

fn namespace() -> network_namespace::NetworkNamespaceRef {
    crate::net_ns::test_support::allocate_namespace()
}

fn publish(stack: &NetStack, owner: &network_namespace::NetworkNamespaceRef,
           ip: IpAddr, v6only: bool) -> Arc<TcpListenEntry> {
    let bind = stack.tcp_reserve_in(owner.id().as_u64(), ip, PORT, None, true, false, 0, v6only)
        .expect("reserve listener bind");
    stack.tcp_listen_reserved(&bind).expect("publish listener")
}

fn lookup(stack: &NetStack, owner: &network_namespace::NetworkNamespaceRef, dst: IpAddr)
    -> Option<Vec<Arc<TcpListenEntry>>>
{
    let tables = stack.inet_tables(owner.id().as_u64());
    let listens = tables.tcp_listens.lock();
    lookup_listen_bucket(&listens, dst, PORT)
}

fn only(bucket: Option<Vec<Arc<TcpListenEntry>>>) -> IpAddr {
    let bucket = bucket.expect("listener bucket");
    assert_eq!(bucket.len(), 1, "one listener per published address");
    bucket[0].local.ip
}

#[test]
fn ipv6_wildcard_listener_accepts_ipv4_traffic() {
    let stack = NetStack::new();
    let owner = namespace();
    let listener = publish(&stack, &owner, IpAddr::V6(Ipv6Addr::ANY), false);
    assert_eq!(only(lookup(&stack, &owner, IpAddr::V4(LOCAL_V4))), listener.local.ip);
    assert_eq!(only(lookup(&stack, &owner, IpAddr::V6(Ipv6Addr::ANY))), listener.local.ip);
}

#[test]
fn ipv6_only_wildcard_listener_rejects_ipv4_traffic() {
    let stack = NetStack::new();
    let owner = namespace();
    publish(&stack, &owner, IpAddr::V6(Ipv6Addr::ANY), true);
    assert!(lookup(&stack, &owner, IpAddr::V4(LOCAL_V4)).is_none());
}

#[test]
fn ipv4_mapped_listener_serves_only_its_own_ipv4_address() {
    let stack = NetStack::new();
    let owner = namespace();
    let mapped = IpAddr::V6(Ipv6Addr::from_v4_mapped(LOCAL_V4));
    publish(&stack, &owner, mapped, false);
    assert_eq!(only(lookup(&stack, &owner, IpAddr::V4(LOCAL_V4))), mapped);
    assert!(lookup(&stack, &owner, IpAddr::V4(OTHER_V4)).is_none());
}

#[test]
fn ipv4_only_mapped_listener_rejects_ipv4_traffic_when_v6only() {
    let stack = NetStack::new();
    let owner = namespace();
    publish(&stack, &owner, IpAddr::V6(Ipv6Addr::from_v4_mapped(LOCAL_V4)), true);
    assert!(lookup(&stack, &owner, IpAddr::V4(LOCAL_V4)).is_none());
}

#[test]
fn exact_ipv4_listener_outranks_the_ipv4_wildcard() {
    let stack = NetStack::new();
    let owner = namespace();
    publish(&stack, &owner, IpAddr::V4(LOCAL_V4), false);
    assert_eq!(only(lookup(&stack, &owner, IpAddr::V4(LOCAL_V4))), IpAddr::V4(LOCAL_V4));
    assert!(lookup(&stack, &owner, IpAddr::V4(OTHER_V4)).is_none());
}

#[test]
fn ipv4_listener_never_serves_ipv6_traffic() {
    let stack = NetStack::new();
    let owner = namespace();
    publish(&stack, &owner, IpAddr::V4(Ipv4Addr::ANY), false);
    assert!(lookup(&stack, &owner, IpAddr::V6(Ipv6Addr::ANY)).is_none());
}
