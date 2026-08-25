use super::*;

/// Raw IPv6 send with socket scope, PMTU, and protocol-override state. # C: O(payload + N)
pub(crate) fn sendto_raw6(sock: &InetSocket, endpoint: &crate::raw6::Raw6Endpoint,
    dst_ip: crate::Ipv6Addr, dst_protocol: Option<u16>, scope_id: u32,
    payload: &[u8], control: &crate::send_control::Raw6Control, tx: crate::TxMeta)
    -> Result<usize, NetError>
{
    validate_raw6_destination_protocol(endpoint.protocol(), dst_protocol)?;
    let protocol_override = if endpoint.protocol() == crate::addr::IpProto::Raw as u8
        && !endpoint.header_included()
    {
        match dst_protocol {
            Some(protocol) if protocol <= u8::MAX as u16 => Some(protocol as u8),
            Some(_) => return Err(NetError::Einval),
            None => None,
        }
    } else { None };
    xmit_raw6_with_sticky(sock, endpoint, dst_ip, protocol_override, scope_id, payload, control, tx)?;
    // Transmit and receive must not share a frame: the loopback pass below re-enters the
    // whole receive stack, and the sticky-option merge above holds a cloned `Raw6Control`
    // plus the transmit argument block the whole way down.
    drain_loopback();
    Ok(payload.len())
}

/// Validate the protocol selector carried in `sockaddr_in6.sin6_port` for a
/// raw IPv6 send.
///
/// Linux `rawv6_sendmsg` uses that port as the next-header selector: zero
/// means the socket's protocol, a fixed-protocol socket accepts only its own
/// protocol, and `IPPROTO_RAW` is the one socket allowed to select any
/// protocol byte.  The selector is checked before route lookup, so a bad
/// destination cannot hide an `EINVAL` behind a later routing error.
/// # C: O(1)
fn validate_raw6_destination_protocol(socket_protocol: u8,
                                      destination_protocol: Option<u16>) -> Result<(), NetError>
{
    let Some(destination_protocol) = destination_protocol else { return Ok(()); };
    if destination_protocol > u8::MAX as u16 { return Err(NetError::Einval); }
    if destination_protocol == 0 || socket_protocol == crate::addr::IpProto::Raw as u8 {
        return Ok(());
    }
    if destination_protocol as u8 == socket_protocol { Ok(()) }
    else { Err(NetError::Einval) }
}

/// Apply the socket's sticky IPv6 options to one message's control block.
///
/// `#[inline(never)]`: cloning a `Raw6Control` materialises four optional
/// extension-header vectors, and those temporaries have no business living in the
/// transmit frame that follows.
/// # C: O(control bytes)
#[inline(never)]
fn merge_sticky_raw6_control(sock: &InetSocket, control: &crate::send_control::Raw6Control)
    -> crate::send_control::Raw6Control
{
    let mut effective = control.clone();
    if effective.multicast_loop.is_none() {
        effective.multicast_loop = Some(
            sock.opts.ipv6_mcast_loop.load(core::sync::atomic::Ordering::Acquire) != 0);
    }
    // Linux tclass precedence: per-message IPV6_TCLASS cmsg > sticky
    // IPV6_TCLASS > flowinfo tclass byte. Inject the sticky value only when
    // it is set (>= 0) and no cmsg carried one, leaving the flowinfo fallback
    // (raw.rs) intact when the socket option is unset.
    if effective.traffic_class.is_none() {
        let sticky = sock.opts.ipv6_tclass.load(core::sync::atomic::Ordering::Acquire);
        if sticky >= 0 { effective.traffic_class = Some(sticky); }
    }
    if effective.source.is_none() {
        let (addr, _) = sock.opts.ipv6.sticky_pktinfo();
        let addr = crate::Ipv6Addr(addr);
        if !addr.is_unspecified() { effective.source = Some(addr); }
    }
    effective.automatic_flow_label = sock.opts.ipv6.generates_flow_label(
        crate::sysctl::ipv6_auto_flowlabels_in(sock.net_ns()));
    effective.merge_sticky_headers(&sock.opts.ipv6);
    effective
}

/// Merge sticky socket options into the per-message control block and transmit.
/// Split out of `sendto_raw6` so the merged control never occupies the frame that
/// continues into the loopback receive pass (Linux `noinline_for_stack`).
/// # C: O(payload)
#[inline(never)]
fn xmit_raw6_with_sticky(sock: &InetSocket, endpoint: &crate::raw6::Raw6Endpoint,
    dst_ip: crate::Ipv6Addr, protocol_override: Option<u8>, scope_id: u32,
    payload: &[u8], control: &crate::send_control::Raw6Control, tx: crate::TxMeta)
    -> Result<(), NetError>
{
    let hop = resolve_v6_hop_limit(sock, dst_ip);
    let pmtudisc = sock.opts.ipv6_mtu_discover.load(core::sync::atomic::Ordering::Acquire);
    let effective = merge_sticky_raw6_control(sock, control);
    let scoped = if control.iface.is_some() && scope_id == 0 {
        crate::sock::bound_iface(sock)?
    } else { scoped_iface(sock, dst_ip, scope_id)? };
    let (_, scoped) = sticky_pktinfo_choice(crate::Ipv6Addr::ANY,
        sock.opts.ipv6.sticky_pktinfo(), scoped);
    // A header-included send carries the caller's own header chain, so no
    // extension-header area of ours stands between the fixed header and the
    // payload and none comes off the announced MTU.
    let header_bytes = if endpoint.header_included() { 0 } else { extension_bytes(&effective) };
    stack().send_raw6_with_frag_size(endpoint, dst_ip, scoped,
        protocol_override, payload, hop, pmtudisc, sock.opts.ipv6.frag_size(), &effective,
        sock.opts.ipv6.srcprefs(), tx)
        .map_err(|error| crate::socket_error::report_send_failure_pmtu(&sock.error, sock.net_ns(),
            crate::addr::IpAddr::V6(dst_ip), RAW_NO_PORT, scoped, error, recvpathmtu(sock),
            header_bytes))
}

/// A raw socket names no transport port, so the destination a local error
/// records carries none.
pub(crate) const RAW_NO_PORT: u16 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw6_sockaddr_protocol_follows_linux_port_selector() {
        let icmpv6 = crate::addr::IpProto::Icmpv6 as u8;
        assert_eq!(validate_raw6_destination_protocol(icmpv6, None), Ok(()));
        assert_eq!(validate_raw6_destination_protocol(icmpv6, Some(0)), Ok(()));
        assert_eq!(validate_raw6_destination_protocol(icmpv6, Some(58)), Ok(()));
        assert_eq!(validate_raw6_destination_protocol(icmpv6, Some(17)), Err(NetError::Einval));
        assert_eq!(validate_raw6_destination_protocol(icmpv6, Some(256)), Err(NetError::Einval));
        // IPPROTO_RAW is the sole raw IPv6 socket protocol that may select a
        // different next header in sin6_port.
        assert_eq!(validate_raw6_destination_protocol(crate::addr::IpProto::Raw as u8,
            Some(17)), Ok(()));
    }

    const RAW_MTU: u32 = 1280;
    const RAW_LOCAL: crate::Ipv6Addr =
        crate::Ipv6Addr([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    const RAW_DST: crate::Ipv6Addr =
        crate::Ipv6Addr([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);

    struct RawSinkDev;

    impl crate::netdev::NetDev for RawSinkDev {
        fn name(&self) -> &str { "raw6err0" }
        fn mac(&self) -> crate::addr::MacAddr { crate::addr::MacAddr::ZERO }
        fn mtu(&self) -> u32 { RAW_MTU }
        fn retire_namespace(&self) {}
        fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
            crate::NamespaceDropAction::Destroy
        }
        fn xmit(&self, _packet: crate::pkt::Pkt) -> crate::netdev::NetResult<()> { Ok(()) }
    }

    /// A raw IPv6 socket in its own namespace, routed over one `RAW_MTU` link,
    /// forbidden to fragment and collecting both error reports. # C: O(1)
    fn raw6_socket(protocol: u8) -> InetSocket {
        let owner = crate::net_ns::test_support::allocate_namespace();
        let ns = owner.id().as_u64();
        let iface = stack().ifaces.register_in_ns(
            alloc::sync::Arc::new(RawSinkDev) as alloc::sync::Arc<dyn crate::netdev::NetDev>, ns);
        stack().add_v6_addr(iface, RAW_LOCAL);
        stack().routes6.add_in(ns, crate::route6::Route6Entry {
            table: crate::policy_rule::RT_TABLE_MAIN, dst: RAW_DST, prefix_len: 128,
            iface, gateway: None, src_hint: Some(RAW_LOCAL),
            origin: crate::route6::Route6Origin::Static,
        });
        let sock = InetSocket::new_raw6_in(protocol, owner);
        sock.error.set_recverr6(true);
        sock.opts.ipv6.set_flag(crate::sock_opts::sol_ipv6::flag::RXPATHMTU, true);
        sock.opts.ipv6_mtu_discover.store(crate::uapi::IPV6_PMTUDISC_DO as i32,
            core::sync::atomic::Ordering::Release);
        sock
    }

    /// The raw send under test, with one message's control block. # C: O(payload)
    fn raw6_send(sock: &InetSocket, bytes: usize,
        control: &crate::send_control::Raw6Control) -> Result<usize, NetError>
    {
        let endpoint = match &*sock.kind.lock() {
            crate::sock::SockKind::Raw6(endpoint) => endpoint.clone(),
            _ => unreachable!("the fixture builds a raw IPv6 socket"),
        };
        sendto_raw6(sock, &endpoint, RAW_DST, None, 0, &alloc::vec![0u8; bytes],
            control, crate::TxMeta::NONE)
    }

    // A raw send the path refuses on size is reported the same way an ordinary
    // datagram send is: a local-origin record naming the destination and the
    // MTU, plus the announcement a socket that asked for it collects.
    #[test]
    fn a_raw_ipv6_size_refusal_reports_the_local_error_and_the_announcement() {
        let _domain = crate::hosted_fixture::init_net_domain();
        let sock = raw6_socket(crate::addr::IpProto::Udp as u8);

        assert_eq!(raw6_send(&sock, RAW_MTU as usize * 2,
            &crate::send_control::Raw6Control::default()), Err(NetError::Emsgsize));

        let entry = sock.error.take_extended().expect("the refusal queues a local record");
        assert_eq!(entry.origin, crate::socket_error::SO_EE_ORIGIN_LOCAL);
        assert_eq!(entry.errno, syscall::errno::Errno::Emsgsize as i32);
        assert_eq!(entry.destination, crate::addr::IpAddr::V6(RAW_DST));
        assert_eq!(entry.info, RAW_MTU);
        assert_eq!(sock.error.pathmtu.take().map(|note| note.mtu), Some(RAW_MTU));
    }

    // The extension headers the send would have carried come off the number
    // both reports name, because what is announced is the room left for the
    // payload rather than the raw link MTU.
    #[test]
    fn a_raw_ipv6_refusal_takes_the_extension_headers_off_the_reported_mtu() {
        let _domain = crate::hosted_fixture::init_net_domain();
        let sock = raw6_socket(crate::addr::IpProto::Udp as u8);
        let control = crate::send_control::Raw6Control {
            hop_options: Some(alloc::vec![0u8; 8]),
            dst_after_routing: Some(alloc::vec![0u8; 16]),
            ..Default::default()
        };

        assert_eq!(raw6_send(&sock, RAW_MTU as usize * 2, &control), Err(NetError::Emsgsize));

        let entry = sock.error.take_extended().expect("the refusal queues a local record");
        assert_eq!(entry.info, RAW_MTU - 24);
        assert_eq!(sock.error.pathmtu.take().map(|note| note.mtu), Some(RAW_MTU - 24));
    }
}
