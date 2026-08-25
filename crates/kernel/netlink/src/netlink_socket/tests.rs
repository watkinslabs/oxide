    use alloc::sync::Arc;

    use super::NetlinkSocket;
    use crate::{flags, proto, rtnetlink, Nlmsghdr};
    use crate::netlink_tests::test_namespace;

    fn request(ty: u16, body: &[u8]) -> alloc::vec::Vec<u8> {
        let hdr = Nlmsghdr {
            nlmsg_len: (Nlmsghdr::SIZE + body.len()) as u32,
            nlmsg_type: ty,
            nlmsg_flags: flags::NLM_F_REQUEST | flags::NLM_F_DUMP,
            nlmsg_seq: 71,
            nlmsg_pid: 72,
        };
        let mut msg = alloc::vec![0u8; hdr.nlmsg_len as usize];
        hdr.write_to(&mut msg);
        msg[Nlmsghdr::SIZE..].copy_from_slice(body);
        msg
    }

    fn reply_ifindices(reply: &[u8], ty: u16) -> alloc::vec::Vec<u32> {
        let mut out = alloc::vec::Vec::new();
        let mut off = 0;
        while off + Nlmsghdr::SIZE <= reply.len() {
            let Some(hdr) = Nlmsghdr::parse(&reply[off..]) else { break; };
            let len = hdr.nlmsg_len as usize;
            if len < Nlmsghdr::SIZE || off + len > reply.len() { break; }
            if hdr.nlmsg_type == ty {
                let start = off + Nlmsghdr::SIZE + 4;
                out.push(u32::from_ne_bytes(reply[start..start + 4].try_into().unwrap()));
            }
            off += crate::nlmsg_align(len);
        }
        out
    }

    fn ack_errno(reply: &[u8]) -> i32 {
        i32::from_ne_bytes(reply[Nlmsghdr::SIZE..Nlmsghdr::SIZE + 4].try_into().unwrap())
    }

    #[test]
    fn pending_recv_error_overwrites_with_latest_positive_errno() {
        let namespace = network_namespace::initial();
        let sock = NetlinkSocket::new(0, &namespace);
        assert_eq!(sock.take_pending_recv_error(), 0);
        assert!(!sock.set_pending_recv_error(0));
        assert!(!sock.set_pending_recv_error(-5));
        assert!(sock.set_pending_recv_error(111));
        assert!(sock.set_pending_recv_error(104));
        assert_eq!(sock.take_pending_recv_error(), 104);
        assert_eq!(sock.take_pending_recv_error(), 0);
    }

    #[test]
    fn send_preflight_enforces_linux_sndbuf_overhead_boundary() {
        let sock = NetlinkSocket::new(0, &network_namespace::initial());
        let limit = super::NETLINK_SNDBUF_DEFAULT - super::NETLINK_SEND_OVERHEAD;
        assert_eq!(sock.preflight_send(limit), Ok(()));
        assert_eq!(sock.preflight_send(limit + 1), Err(super::SendError::Emsgsize));
    }

    #[test]
    fn consumed_dump_chunk_schedules_the_socket_owned_continuation() {
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &network_namespace::initial());
        let mut reply = alloc::vec![0; super::dump::DUMP_CHUNK_BYTES];
        Nlmsghdr { nlmsg_len: super::dump::DUMP_CHUNK_BYTES as u32, nlmsg_type: rtnetlink::RTM_NEWLINK,
            nlmsg_flags: flags::NLM_F_MULTI, nlmsg_seq: 1, nlmsg_pid: 2 }.write_to(&mut reply);
        let done_at = reply.len();
        reply.resize(done_at + Nlmsghdr::SIZE, 0);
        Nlmsghdr { nlmsg_len: Nlmsghdr::SIZE as u32, nlmsg_type: crate::msg::NLMSG_DONE,
            nlmsg_flags: flags::NLM_F_MULTI, nlmsg_seq: 1, nlmsg_pid: 2 }.write_to(&mut reply[done_at..]);

        let first = sock.start_dump(reply).unwrap();
        assert!(sock.dump_active());
        sock.enqueue(first);
        assert!(sock.dequeue().is_some());
        assert!(!sock.dump_active(), "final continuation is generated after the first read");
        let (last, _) = sock.dequeue().expect("next chunk is queued after the read");
        assert_eq!(Nlmsghdr::parse(&last).unwrap().nlmsg_type, crate::msg::NLMSG_DONE);
    }

    #[test]
    fn empty_vectored_datagram_reaches_backend_enodata() {
        let sock = NetlinkSocket::new(0, &network_namespace::initial());
        assert_eq!(sock.write_iter(&[]), Err(vfs::VfsError::Enodata));
        assert_eq!(sock.write(&[]), Err(vfs::VfsError::Enodata));
    }

    /// Malformed framing is never a send failure: netlink core stops walking
    /// and reports every byte accepted, leaving the sender to learn about a bad
    /// request from an NLMSG_ERROR reply instead of a failed `sendto`.
    #[test]
    fn malformed_netlink_frames_are_accepted_without_a_send_error() {
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &network_namespace::initial());
        let runt = [0u8; Nlmsghdr::SIZE - 1];
        assert_eq!(sock.write(&runt), Ok(runt.len()));

        let mut short = alloc::vec![0u8; Nlmsghdr::SIZE];
        short[..2].copy_from_slice(&((Nlmsghdr::SIZE - 1) as u16).to_ne_bytes());
        assert_eq!(sock.write(&short), Ok(short.len()));

        let mut overrun = alloc::vec![0u8; Nlmsghdr::SIZE];
        overrun[..2].copy_from_slice(&((Nlmsghdr::SIZE + 1) as u16).to_ne_bytes());
        assert_eq!(sock.write(&overrun), Ok(overrun.len()));

        assert!(sock.dequeue().is_none(), "no reply is produced for unparsable framing");
    }

    /// `ip(8)` sends a fixed-size request buffer: `nlmsg_len` covers only the
    /// leading dump request and the rest of the buffer is zero. The request
    /// must be answered and the send must report the whole buffer accepted.
    #[test]
    fn zero_padded_dump_request_is_answered_and_fully_accepted() {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &test_namespace());
        let mut buf = request(rtnetlink::RTM_GETADDR, &[0u8; rtnetlink::Ifaddrmsg::SIZE]);
        let msg_len = buf.len();
        buf.resize(msg_len + 128, 0);
        assert_eq!(sock.write(&buf), Ok(msg_len + 128));
        let (reply, _) = sock.dequeue().expect("the padded dump request is answered");
        assert!(reply_ends_with_done(&reply));
        assert!(sock.dequeue().is_none(), "the padding produces no second reply");
    }

    /// A final message whose ALIGNED length runs past the datagram is accepted
    /// and dispatched; the walk clamps to the datagram end.
    #[test]
    fn unaligned_final_message_is_dispatched_not_rejected() {
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &network_namespace::initial());
        let unknown = rtnetlink::RTM_MAX + 1;
        let mut msg = request(unknown, &[0u8]);
        assert_eq!(msg.len(), Nlmsghdr::SIZE + 1);
        msg[..4].copy_from_slice(&((Nlmsghdr::SIZE + 1) as u32).to_ne_bytes());
        assert_eq!(sock.write(&msg), Ok(Nlmsghdr::SIZE + 1));
        let (reply, _) = sock.dequeue().expect("the trailing message still dispatched");
        assert_eq!(ack_errno(&reply), -(vfs::VfsError::Eopnotsupp as i32));
    }

    /// Reserved control types and non-request messages never reach a handler;
    /// they are acknowledged only when the sender set NLM_F_ACK.
    #[test]
    fn control_and_non_request_messages_skip_the_handler() {
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &network_namespace::initial());
        let mut noop = request(crate::msg::NLMSG_NOOP, &[]);
        assert_eq!(sock.write(&noop), Ok(noop.len()));
        assert!(sock.dequeue().is_none(), "a control message without NLM_F_ACK is silent");

        noop[6..8].copy_from_slice(&(flags::NLM_F_REQUEST | flags::NLM_F_ACK).to_ne_bytes());
        assert_eq!(sock.write(&noop), Ok(noop.len()));
        let (reply, _) = sock.dequeue().expect("NLM_F_ACK on a control message is answered");
        assert_eq!(ack_errno(&reply), 0);

        let mut not_request = request(rtnetlink::RTM_GETLINK, &[]);
        not_request[6..8].copy_from_slice(&0u16.to_ne_bytes());
        assert_eq!(sock.write(&not_request), Ok(not_request.len()));
        assert!(sock.dequeue().is_none(), "a non-request never runs the handler");
    }

    #[test]
    fn unknown_rtnetlink_request_queues_linux_eopnotsupp() {
        let socket = NetlinkSocket::new(proto::NETLINK_ROUTE, &network_namespace::initial());
        let unknown = rtnetlink::RTM_MAX + 1;
        socket.write(&request(unknown, &[])).unwrap();
        let (reply, _) = socket.dequeue().expect("unsupported RTNL request has error reply");
        assert_eq!(ack_errno(&reply), -(vfs::VfsError::Eopnotsupp as i32));
    }

    #[test]
    fn explicit_namespace_is_captured_by_socket() {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let namespace = test_namespace();
        let sock = NetlinkSocket::new(0, &namespace);
        assert!(Arc::ptr_eq(&sock.net_ns, &namespace));
    }

    #[test]
    fn route_dump_uses_socket_namespace() {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let namespace = test_namespace();
        let ns = namespace.id().as_u64();
        let row = rtnetlink::RouteRow {
            ns, table: rtnetlink::RT_TABLE_MAIN as u32,
            protocol: rtnetlink::RTPROT_STATIC, scope: rtnetlink::RT_SCOPE_LINK,
            kind: rtnetlink::RTN_UNICAST, dst: Some(([198, 18, 23, 0], 24)),
            gateway: None, oif_ifindex: 5511, prefsrc: None,
            metric: 0, metrics: net::RouteMetrics::NONE,
            flags: 0, weight: 1, nh_flags: 0,
        };
        rtnetlink::route_insert(row);
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace);
        let hdr = Nlmsghdr {
            nlmsg_len: (Nlmsghdr::SIZE + rtnetlink::Rtmsg::SIZE) as u32,
            nlmsg_type: rtnetlink::RTM_GETROUTE,
            nlmsg_flags: flags::NLM_F_REQUEST | flags::NLM_F_DUMP,
            nlmsg_seq: 1, nlmsg_pid: 2,
        };
        let mut msg = alloc::vec![0u8; hdr.nlmsg_len as usize];
        hdr.write_to(&mut msg);
        msg[Nlmsghdr::SIZE] = rtnetlink::AF_INET;
        sock.write(&msg).unwrap();
        let (reply, _) = sock.dequeue().unwrap();
        assert!(reply.windows(4).any(|bytes| bytes == [198, 18, 23, 0]));
        assert_eq!(rtnetlink::route_remove(ns, row.table, row.dst, row.oif_ifindex, row.gateway), 1);
    }

    #[test]
    fn passed_socket_keeps_captured_namespace_for_link_dump_and_mutation() {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let owner_namespace = test_namespace();
        let receiver_namespace = test_namespace();
        let owner_ns = owner_namespace.id().as_u64();
        let receiver_ns = receiver_namespace.id().as_u64();
        let stack = net::global_stack();
        let owner = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), owner_ns);
        let receiver = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), receiver_ns);
        let owner_ifindex = stack.ifaces.ifindex_in_ns(owner, owner_ns).unwrap();
        let receiver_ifindex = stack.ifaces.ifindex_in_ns(receiver, receiver_ns).unwrap();
        let passed = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE, &owner_namespace));
        let received_fd = Arc::clone(&passed);

        received_fd.write(&request(rtnetlink::RTM_GETLINK, &[])).unwrap();
        let (reply, _) = received_fd.dequeue().unwrap();
        let indices = reply_ifindices(&reply, rtnetlink::RTM_NEWLINK);
        assert!(indices.contains(&owner_ifindex));
        assert_eq!(indices.len(), 1);

        let mut ifi = rtnetlink::Ifinfomsg::default();
        // Both namespace-local loopbacks are ifindex 1. An index identifies
        // only an interface in the socket's captured namespace, so use an
        // absent owner-namespace index to verify the ENODEV boundary.
        ifi.ifi_index = receiver_ifindex.saturating_add(1) as i32;
        ifi.ifi_change = rtnetlink::iff::IFF_UP;
        let mut body = [0u8; rtnetlink::Ifinfomsg::SIZE];
        ifi.write_to(&mut body);
        received_fd.write(&request(rtnetlink::RTM_SETLINK, &body)).unwrap();
        let (reply, _) = received_fd.dequeue().unwrap();
        assert_eq!(ack_errno(&reply), -19, "owner socket cannot mutate receiver namespace link");

        ifi.ifi_index = owner_ifindex as i32;
        ifi.ifi_flags = 0;
        ifi.write_to(&mut body);
        received_fd.write(&request(rtnetlink::RTM_SETLINK, &body)).unwrap();
        let (reply, _) = received_fd.dequeue().unwrap();
        assert_eq!(ack_errno(&reply), 0);
        assert_eq!(stack.ifaces.iface_flags(owner).unwrap() & rtnetlink::iff::IFF_UP, 0);
        let _ = stack.ifaces.unregister(owner);
        let _ = stack.ifaces.unregister(receiver);
    }

    #[test]
    fn passed_socket_keeps_captured_namespace_for_addr_mutation_and_dump() {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let owner_namespace = test_namespace();
        let receiver_namespace = test_namespace();
        let owner_ns = owner_namespace.id().as_u64();
        let receiver_ns = receiver_namespace.id().as_u64();
        let stack = net::global_stack();
        let iface = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), owner_ns);
        let ifindex = stack.ifaces.ifindex_in_ns(iface, owner_ns).unwrap();
        let passed = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE, &owner_namespace));
        let received_fd = Arc::clone(&passed);
        let receiver = NetlinkSocket::new(proto::NETLINK_ROUTE, &receiver_namespace);
        let addr = [198, 18, 25, 1];
        let mut ifa = rtnetlink::Ifaddrmsg::default();
        ifa.ifa_family = rtnetlink::AF_INET;
        ifa.ifa_prefixlen = 24;
        ifa.ifa_scope = rtnetlink::RT_SCOPE_UNIVERSE;
        ifa.ifa_index = ifindex;
        let mut body = alloc::vec![0u8; rtnetlink::Ifaddrmsg::SIZE];
        ifa.write_to(&mut body);
        rtnetlink::put_nlattr(&mut body, rtnetlink::ifa::IFA_LOCAL, &addr);

        received_fd.write(&request(rtnetlink::RTM_NEWADDR, &body)).unwrap();
        let (reply, _) = received_fd.dequeue().unwrap();
        assert_eq!(ack_errno(&reply), 0);
        assert!(rtnetlink::addr_snapshot_ns(owner_ns).iter().any(|row|
            row.iface == iface && row.addr == net::Ipv4Addr::from_u32(u32::from_be_bytes(addr))));
        assert!(rtnetlink::addr_snapshot_ns(receiver_ns).is_empty());

        received_fd.write(&request(rtnetlink::RTM_GETADDR, &[])).unwrap();
        let (owner_dump, _) = received_fd.dequeue().unwrap();
        assert!(reply_ifindices(&owner_dump, rtnetlink::RTM_NEWADDR).contains(&ifindex));
        receiver.write(&request(rtnetlink::RTM_GETADDR, &[])).unwrap();
        let (receiver_dump, _) = receiver.dequeue().unwrap();
        assert!(!reply_ifindices(&receiver_dump, rtnetlink::RTM_NEWADDR).contains(&ifindex));

        receiver.write(&request(rtnetlink::RTM_DELADDR, &body)).unwrap();
        let (reply, _) = receiver.dequeue().unwrap();
        assert_eq!(ack_errno(&reply), -19);
        assert_eq!(rtnetlink::addr_snapshot_ns(owner_ns).len(), 1);
        received_fd.write(&request(rtnetlink::RTM_DELADDR, &body)).unwrap();
        let (reply, _) = received_fd.dequeue().unwrap();
        assert_eq!(ack_errno(&reply), 0);
        assert!(rtnetlink::addr_snapshot_ns(owner_ns).is_empty());
        let _ = stack.ifaces.unregister(iface);
    }

    const NEIGH_IP: [u8; 4] = [198, 18, 40, 7];
    const NEIGH_MAC: [u8; 6] = [0x02, 0x00, 0x5e, 0x00, 0x00, 0x07];

    /// One decoded RTM_NEWNEIGH reply: state + NDA_DST + optional NDA_LLADDR.
    fn parse_neigh_replies(reply: &[u8]) -> alloc::vec::Vec<(u16, alloc::vec::Vec<u8>, Option<[u8; 6]>)> {
        let mut out = alloc::vec::Vec::new();
        let mut off = 0;
        while off + Nlmsghdr::SIZE <= reply.len() {
            let Some(hdr) = Nlmsghdr::parse(&reply[off..]) else { break; };
            let len = hdr.nlmsg_len as usize;
            if len < Nlmsghdr::SIZE || off + len > reply.len() { break; }
            if hdr.nlmsg_type == rtnetlink::RTM_NEWNEIGH {
                let ndm = &reply[off + Nlmsghdr::SIZE..off + Nlmsghdr::SIZE + rtnetlink::Ndmsg::SIZE];
                let state = u16::from_ne_bytes([ndm[8], ndm[9]]);
                let mut dst = alloc::vec::Vec::new();
                let mut mac = None;
                let mut ao = off + Nlmsghdr::SIZE + rtnetlink::Ndmsg::SIZE;
                while ao + 4 <= off + len {
                    let al = u16::from_ne_bytes([reply[ao], reply[ao + 1]]) as usize;
                    let at = u16::from_ne_bytes([reply[ao + 2], reply[ao + 3]]) & 0x3fff;
                    if al < 4 || ao + al > off + len { break; }
                    let pl = &reply[ao + 4..ao + al];
                    if at == rtnetlink::nda::NDA_DST { dst = pl.to_vec(); }
                    else if at == rtnetlink::nda::NDA_LLADDR && pl.len() == 6 {
                        mac = Some([pl[0], pl[1], pl[2], pl[3], pl[4], pl[5]]);
                    }
                    ao += crate::nlmsg_align(al);
                }
                out.push((state, dst, mac));
            }
            off += crate::nlmsg_align(len);
        }
        out
    }

    fn reply_ends_with_done(reply: &[u8]) -> bool {
        let mut off = 0;
        let mut last = None;
        while off + Nlmsghdr::SIZE <= reply.len() {
            let Some(hdr) = Nlmsghdr::parse(&reply[off..]) else { break; };
            let len = hdr.nlmsg_len as usize;
            if len < Nlmsghdr::SIZE || off + len > reply.len() { break; }
            last = Some(hdr.nlmsg_type);
            off += crate::nlmsg_align(len);
        }
        last == Some(crate::msg::NLMSG_DONE)
    }

    fn neigh_body(family: u8, ifindex: u32, ip: &[u8], mac: Option<[u8; 6]>, state: u16)
        -> alloc::vec::Vec<u8>
    {
        let mut ndm = rtnetlink::Ndmsg::default();
        ndm.ndm_family = family;
        ndm.ndm_ifindex = ifindex as i32;
        ndm.ndm_state = state;
        ndm.ndm_type = rtnetlink::RTN_UNICAST;
        let mut body = alloc::vec![0u8; rtnetlink::Ndmsg::SIZE];
        ndm.write_to(&mut body);
        rtnetlink::put_nlattr(&mut body, rtnetlink::nda::NDA_DST, ip);
        if let Some(m) = mac { rtnetlink::put_nlattr(&mut body, rtnetlink::nda::NDA_LLADDR, &m); }
        body
    }

    fn seed_neigh_iface() -> (network_namespace::NetworkNamespaceRef, u64, net::NetIfaceId, u32) {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let namespace = test_namespace();
        let ns = namespace.id().as_u64();
        let stack = net::global_stack();
        let iface = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), ns);
        let ifindex = stack.ifaces.ifindex_in_ns(iface, ns).unwrap();
        (namespace, ns, iface, ifindex)
    }

    #[test]
    fn getneigh_dump_reports_seeded_arp_entry_and_terminates_with_done() {
        let (namespace, ns, iface, ifindex) = seed_neigh_iface();
        let stack = net::global_stack();
        let ip = net::Ipv4Addr::new(NEIGH_IP[0], NEIGH_IP[1], NEIGH_IP[2], NEIGH_IP[3]);
        stack.neigh_add_v4(ns, ifindex, ip, net::MacAddr(NEIGH_MAC), true).unwrap();

        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace);
        sock.write(&request(rtnetlink::RTM_GETNEIGH, &[])).unwrap();
        let (reply, _) = sock.dequeue().unwrap();
        assert!(reply_ends_with_done(&reply), "dump ends with NLMSG_DONE");
        let rows = parse_neigh_replies(&reply);
        let row = rows.iter().find(|(_, dst, _)| dst.as_slice() == NEIGH_IP)
            .expect("seeded neighbour present in dump");
        assert_eq!(row.2, Some(NEIGH_MAC), "NDA_LLADDR matches");
        assert!(row.0 & rtnetlink::nud::NUD_PERMANENT != 0, "permanent NUD state");
        let _ = stack.ifaces.unregister(iface);
    }

    #[test]
    fn getneigh_one_reads_one_canonical_arp_entry_without_done() {
        let (namespace, ns, iface, ifindex) = seed_neigh_iface();
        let stack = net::global_stack();
        let ip = net::Ipv4Addr::new(NEIGH_IP[0], NEIGH_IP[1], NEIGH_IP[2], NEIGH_IP[3]);
        stack.neigh_add_v4(ns, ifindex, ip, net::MacAddr(NEIGH_MAC), true).unwrap();
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace);
        let body = neigh_body(rtnetlink::AF_INET, ifindex, &NEIGH_IP, None, 0);
        let mut msg = request(rtnetlink::RTM_GETNEIGH, &body);
        msg[6..8].copy_from_slice(&flags::NLM_F_REQUEST.to_ne_bytes());
        sock.write(&msg).unwrap();
        let (reply, _) = sock.dequeue().unwrap();
        assert!(!reply_ends_with_done(&reply));
        let rows = parse_neigh_replies(&reply);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, NEIGH_IP);
        assert_eq!(rows[0].2, Some(NEIGH_MAC));
        let _ = stack.ifaces.unregister(iface);
    }

    #[test]
    fn getneigh_one_reports_enoent_for_an_absent_canonical_entry() {
        let (namespace, _ns, iface, ifindex) = seed_neigh_iface();
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace);
        let body = neigh_body(rtnetlink::AF_INET, ifindex, &NEIGH_IP, None, 0);
        let mut msg = request(rtnetlink::RTM_GETNEIGH, &body);
        msg[6..8].copy_from_slice(&flags::NLM_F_REQUEST.to_ne_bytes());
        sock.write(&msg).unwrap();
        let (reply, _) = sock.dequeue().unwrap();
        assert_eq!(ack_errno(&reply), -(vfs::VfsError::Enoent as i32));
        let _ = net::global_stack().ifaces.unregister(iface);
    }

    #[test]
    fn getaddr6_one_reads_one_canonical_address_without_done() {
        let (namespace, _ns, iface, ifindex) = seed_neigh_iface();
        let addr = net::Ipv6Addr([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
        net::global_stack().add_v6_addr(iface, addr);
        let mut body = alloc::vec![0u8; rtnetlink::Ifaddrmsg::SIZE];
        body[0] = rtnetlink::AF_INET6;
        body[4..8].copy_from_slice(&ifindex.to_ne_bytes());
        rtnetlink::put_nlattr(&mut body, rtnetlink::ifa::IFA_ADDRESS, &addr.0);
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace);
        let mut msg = request(rtnetlink::RTM_GETADDR, &body);
        msg[6..8].copy_from_slice(&flags::NLM_F_REQUEST.to_ne_bytes());
        sock.write(&msg).unwrap();
        let (reply, _) = sock.dequeue().unwrap();
        assert!(!reply_ends_with_done(&reply));
        let hdr = Nlmsghdr::parse(&reply).unwrap();
        assert_eq!(hdr.nlmsg_type, rtnetlink::RTM_NEWADDR);
        assert_eq!(reply[Nlmsghdr::SIZE], rtnetlink::AF_INET6);
        assert_eq!(u32::from_ne_bytes(reply[Nlmsghdr::SIZE + 4..Nlmsghdr::SIZE + 8].try_into().unwrap()), ifindex);
        let _ = net::global_stack().ifaces.unregister(iface);
    }

    #[test]
    fn newneigh_writes_the_canonical_arp_cache_no_split_table() {
        let (namespace, ns, iface, ifindex) = seed_neigh_iface();
        let stack = net::global_stack();
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace);
        let body = neigh_body(rtnetlink::AF_INET, ifindex, &NEIGH_IP, Some(NEIGH_MAC),
            rtnetlink::nud::NUD_PERMANENT);
        sock.write(&request(rtnetlink::RTM_NEWNEIGH, &body)).unwrap();
        let (reply, _) = sock.dequeue().unwrap();
        assert_eq!(ack_errno(&reply), 0);

        // Read back through the SAME canonical per-iface ArpCache SIOCSARP uses.
        let cache = stack.ifaces.arp_cache_in_ns(iface, ns).unwrap();
        let ip = net::Ipv4Addr::new(NEIGH_IP[0], NEIGH_IP[1], NEIGH_IP[2], NEIGH_IP[3]);
        let entry = cache.snapshot_states().into_iter().find(|(a, _, _)| *a == ip)
            .expect("RTM_NEWNEIGH wrote the canonical cache");
        assert_eq!(entry.1, Some(net::MacAddr(NEIGH_MAC)));
        assert_eq!(entry.2, net::arp::NudState::Permanent);
        let _ = stack.ifaces.unregister(iface);
    }

    #[test]
    fn delneigh_removes_from_the_canonical_arp_cache() {
        let (namespace, ns, iface, ifindex) = seed_neigh_iface();
        let stack = net::global_stack();
        let ip = net::Ipv4Addr::new(NEIGH_IP[0], NEIGH_IP[1], NEIGH_IP[2], NEIGH_IP[3]);
        stack.neigh_add_v4(ns, ifindex, ip, net::MacAddr(NEIGH_MAC), true).unwrap();
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace);
        let body = neigh_body(rtnetlink::AF_INET, ifindex, &NEIGH_IP, None, 0);
        sock.write(&request(rtnetlink::RTM_DELNEIGH, &body)).unwrap();
        let (reply, _) = sock.dequeue().unwrap();
        assert_eq!(ack_errno(&reply), 0);
        let cache = stack.ifaces.arp_cache_in_ns(iface, ns).unwrap();
        assert!(cache.snapshot_states().into_iter().all(|(a, _, _)| a != ip));
        let _ = stack.ifaces.unregister(iface);
    }

    mod neigh;
