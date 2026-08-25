use super::*;

    #[test]
    fn newneigh_for_iface_absent_in_socket_namespace_is_rejected() {
        let (_owner, owner_ns, iface, ifindex) = seed_neigh_iface();
        let stack = net::global_stack();
        // A socket in a DIFFERENT namespace cannot resolve the owner ifindex.
        let other = test_namespace();
        assert_ne!(other.id().as_u64(), owner_ns);
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &other);
        let body = neigh_body(rtnetlink::AF_INET, ifindex, &NEIGH_IP, Some(NEIGH_MAC),
            rtnetlink::nud::NUD_PERMANENT);
        sock.write(&request(rtnetlink::RTM_NEWNEIGH, &body)).unwrap();
        let (reply, _) = sock.dequeue().unwrap();
        assert_eq!(ack_errno(&reply), -19, "ENODEV: ifindex not in socket namespace");
        let _ = stack.ifaces.unregister(iface);
    }

