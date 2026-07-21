use super::*;

fn request(iface: net::NetIfaceId, addr: [u8; 4], flags: u16) -> (Nlmsghdr, Vec<u8>) {
    let (mut req, mut msg) = addr_req(RTM_NEWADDR, visible_ifindex(iface, 0), 24, addr);
    req.nlmsg_flags = crate::flags::NLM_F_REQUEST | flags;
    req.write_to(&mut msg[..Nlmsghdr::SIZE]);
    (req, msg)
}

fn peer_request(ty: u16, iface: net::NetIfaceId, local: [u8; 4], peer: [u8; 4], flags: u16)
    -> (Nlmsghdr, Vec<u8>)
{
    let (mut req, mut msg) = addr_req(ty, visible_ifindex(iface, 0), 24, local);
    req.nlmsg_flags = crate::flags::NLM_F_REQUEST | flags;
    put_nlattr(&mut msg, ifa::IFA_ADDRESS, &peer);
    req.nlmsg_len = msg.len() as u32;
    req.write_to(&mut msg[..Nlmsghdr::SIZE]);
    (req, msg)
}

#[test]
fn newaddr_matches_linux_create_replace_exclusive_semantics() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let stack = net::global_stack();
    let iface = stack.ifaces.register_in_ns(Arc::new(MovingDev), 0);
    let combinations = [0, crate::flags::NLM_F_CREATE, crate::flags::NLM_F_REPLACE,
        crate::flags::NLM_F_EXCL, crate::flags::NLM_F_CREATE | crate::flags::NLM_F_REPLACE,
        crate::flags::NLM_F_CREATE | crate::flags::NLM_F_EXCL,
        crate::flags::NLM_F_REPLACE | crate::flags::NLM_F_EXCL,
        crate::flags::NLM_F_CREATE | crate::flags::NLM_F_REPLACE | crate::flags::NLM_F_EXCL];
    for (index, flags) in combinations.into_iter().enumerate() {
        let addr = [198, 18, 84, 40 + index as u8];
        let (req, msg) = request(iface, addr, flags);
        assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), 0,
            "missing address flags {flags:#x}");
        let expected = if flags & crate::flags::NLM_F_REPLACE != 0
            && flags & crate::flags::NLM_F_EXCL == 0 { 0 } else { -17 };
        let (req, msg) = request(iface, addr, flags);
        assert_eq!(ack_errno(&handle_newaddr(&req, &msg)), expected);
        assert_eq!(net::iface_addr::remove(0, iface, net::Ipv4Addr::from_u32(
            u32::from_be_bytes(addr)), 24), 1);
    }
    let _ = stack.ifaces.unregister(iface);
}

#[test]
fn deladdr_missing_returns_eaddrnotavail() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let stack = net::global_stack();
    let iface = stack.ifaces.register_in_ns(Arc::new(MovingDev), 0);
    let (req, msg) = addr_req(RTM_DELADDR, visible_ifindex(iface, 0), 24, [198, 18, 84, 43]);
    assert_eq!(ack_errno(&handle_deladdr(&req, &msg)), -99);
    let _ = stack.ifaces.unregister(iface);
}

#[test]
fn address_only_is_local_and_distinct_peer_has_linux_semantics() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let stack = net::global_stack();
    let iface = stack.ifaces.register_in_ns(Arc::new(MovingDev), 0);
    let local = [198, 18, 84, 90];
    let (req, mut address_only) = request(iface, local, crate::flags::NLM_F_CREATE);
    let attr = Nlmsghdr::SIZE + Ifaddrmsg::SIZE;
    address_only[attr + 2..attr + 4].copy_from_slice(&ifa::IFA_ADDRESS.to_ne_bytes());
    assert_eq!(ack_errno(&handle_newaddr(&req, &address_only)), 0);
    assert!(net::iface_addr::snapshot_ns(0).iter().any(|row| {
        row.iface == iface && row.addr.octets() == local && row.peer.is_none()
    }));
    assert_eq!(net::iface_addr::remove(
        0, iface, net::Ipv4Addr::from_u32(u32::from_be_bytes(local)), 24), 1);

    let peer = [203, 0, 113, 9];
    let (req, peer_msg) = peer_request(
        RTM_NEWADDR, iface, local, peer, crate::flags::NLM_F_CREATE);
    assert_eq!(ack_errno(&handle_newaddr(&req, &peer_msg)), 0);
    let row = net::iface_addr::snapshot_ns(0).into_iter()
        .find(|row| row.iface == iface).unwrap();
    assert_eq!(row.addr.octets(), local);
    assert_eq!(row.peer.map(|addr| addr.octets()), Some(peer));
    assert_eq!(row.address().octets(), peer);

    let (req, wrong_peer) = peer_request(RTM_DELADDR, iface, local, [203, 0, 113, 10], 0);
    assert_eq!(ack_errno(&handle_deladdr(&req, &wrong_peer)), -99);
    assert!(net::iface_addr::snapshot_ns(0).iter().any(|row| row.iface == iface));
    let (req, peer_msg) = peer_request(RTM_DELADDR, iface, local, peer, 0);
    assert_eq!(ack_errno(&handle_deladdr(&req, &peer_msg)), 0);
    assert!(!net::iface_addr::snapshot_ns(0).iter().any(|row| row.iface == iface));
    let _ = stack.ifaces.unregister(iface);
}

#[test]
fn ipv4_address_family_and_prefix_are_validated_before_lookup() {
    for ty in [RTM_NEWADDR, RTM_DELADDR] {
        let (req, mut wrong_family) = addr_req(ty, u32::MAX, 24, [192, 0, 2, 1]);
        wrong_family[Nlmsghdr::SIZE] = AF_INET6;
        let reply = if ty == RTM_NEWADDR { handle_newaddr(&req, &wrong_family) }
            else { handle_deladdr(&req, &wrong_family) };
        assert_eq!(ack_errno(&reply), -97);

        let (req, invalid_prefix) = addr_req(ty, u32::MAX, 33, [192, 0, 2, 1]);
        let reply = if ty == RTM_NEWADDR { handle_newaddr(&req, &invalid_prefix) }
            else { handle_deladdr(&req, &invalid_prefix) };
        assert_eq!(ack_errno(&reply), -22);
    }
}

#[test]
fn malformed_trailing_address_attrs_are_atomic() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let stack = net::global_stack();
    let iface = stack.ifaces.register_in_ns(Arc::new(MovingDev), 0);
    let addr = [198, 18, 85, 44];
    let (new_req, mut malformed_new) = request(iface, addr, crate::flags::NLM_F_CREATE);
    malformed_new.push(0xaa);
    assert_eq!(ack_errno(&handle_newaddr(&new_req, &malformed_new)), -22);
    assert!(!net::iface_addr::snapshot_ns(0).iter().any(|row| {
        row.iface == iface && row.addr.as_u32() == u32::from_be_bytes(addr)
    }));

    let (new_req, new_msg) = request(iface, addr, crate::flags::NLM_F_CREATE);
    assert_eq!(ack_errno(&handle_newaddr(&new_req, &new_msg)), 0);
    let (del_req, mut malformed_del) = addr_req(RTM_DELADDR, visible_ifindex(iface, 0), 24, addr);
    malformed_del.push(0xbb);
    assert_eq!(ack_errno(&handle_deladdr(&del_req, &malformed_del)), -22);
    assert!(net::iface_addr::snapshot_ns(0).iter().any(|row| {
        row.iface == iface && row.addr.as_u32() == u32::from_be_bytes(addr)
    }));
    assert_eq!(net::iface_addr::remove(
        0, iface, net::Ipv4Addr::from_u32(u32::from_be_bytes(addr)), 24), 1);
    let _ = stack.ifaces.unregister(iface);
}
