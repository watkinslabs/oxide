// The outbound source screen a raw IPv4 endpoint applies to the address it
// was bound to.
//
// A raw socket reaches route output with the same rule every other IPv4
// transmit does: a source this host does not own is refused unless the socket
// carries the any-source permission. Two things grant it — the transparent
// bind permission, and a header-including socket, which writes the source word
// itself. A socket bound nonlocally through freebind alone gets neither.
//
// The permission is read off the endpoint's retained option state, never a
// copy of the bit, so a write that lands after the endpoint was published is
// the one the next send sees.

use super::*;
use crate::sock_opts::sol_ip::{flag, IpOpts};

const FOREIGN: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 77);
const DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);
const HDRINCL_PROTOCOL: u8 = 255;

fn owned_endpoint(protocol: u8, opts: Arc<IpOpts>) -> Arc<Raw4Endpoint> {
    Raw4Endpoint::new_owned_with_pmtudisc(protocol,
        crate::SocketOwner::root(network_namespace::initial(), 0),
        Arc::new(SocketFilter::new()), Arc::new(SocketMcast::new()),
        Arc::new(crate::SocketError::new()),
        Arc::new(core::sync::atomic::AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)), opts)
}

/// A route to `DST` over a capture device, with the next hop already resolved
/// so the send reaches the transmit path rather than an address resolution.
fn routed(stack: &NetStack) {
    let dev = Arc::new(CaptureDev::new(1500));
    let iface = stack.ifaces.register(dev as Arc<dyn NetDev>);
    stack.routes.add(RouteEntry::main(DST, 32, iface, None,
        Some(Ipv4Addr::new(192, 0, 2, 10))));
    if let Some(cache) = stack.ifaces.arp_cache_in_ns(iface, 0) {
        cache.insert(DST, MacAddr([2, 0, 0, 0, 0, 2]));
    }
}

fn send(stack: &NetStack, endpoint: &Raw4Endpoint) -> NetResult<()> {
    stack.send_raw4(endpoint, DST, &[0x5a; 16], Raw4TxOptions::default(),
        &crate::send_control::Raw4Control::default(), crate::TxMeta::NONE)
}

#[test]
fn a_raw_socket_bound_nonlocally_cannot_source_from_that_address() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    routed(&stack);
    let opts = Arc::new(IpOpts::default());
    let endpoint = owned_endpoint(PROTOCOL, opts.clone());
    // Freebind is what admitted the bind; it buys nothing on transmit.
    opts.set_flag(flag::FREEBIND, true);
    endpoint.bind(FOREIGN, None).unwrap();

    assert_eq!(send(&stack, &endpoint), Err(NetError::Enetunreach));

    // The permission is read live: a write after publication is honoured with
    // no rebind and no second socket lookup.
    opts.set_flag(flag::TRANSPARENT, true);
    assert_eq!(send(&stack, &endpoint), Ok(()));
    opts.set_flag(flag::TRANSPARENT, false);
    assert_eq!(send(&stack, &endpoint), Err(NetError::Enetunreach));
}

#[test]
fn a_header_including_raw_socket_is_never_source_screened() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    routed(&stack);
    let opts = Arc::new(IpOpts::default());
    let endpoint = owned_endpoint(HDRINCL_PROTOCOL, opts);
    endpoint.bind(FOREIGN, None).unwrap();
    assert!(endpoint.snapshot().hdrincl);

    let mut packet = alloc::vec![0u8; IPV4_HDR_LEN + 4];
    packet[0] = 0x45;
    packet[9] = IpProto::Udp as u8;
    packet[16..20].copy_from_slice(&DST.octets());
    assert_eq!(stack.send_raw4(&endpoint, DST, &packet, Raw4TxOptions::default(),
        &crate::send_control::Raw4Control::default(), crate::TxMeta::NONE), Ok(()));
}

/// The screen looks at the source the SEND chose, never at one route output
/// picked for itself: an unbound raw socket takes the outbound interface's
/// address and needs no permission for it.
#[test]
fn a_route_selected_source_needs_no_permission() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    routed(&stack);
    let endpoint = owned_endpoint(PROTOCOL, Arc::new(IpOpts::default()));
    assert_eq!(send(&stack, &endpoint), Ok(()));
}
