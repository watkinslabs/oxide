use super::*;

#[test]
fn wildcard_listener_conflicts_with_concrete_listener_on_same_port() {
    with_vsock_state(|| {
        assert!(driver_install(owner(81), 3, tx_ok, rx_noop));
        assert!(driver_install(owner(82), 4, tx_ok, rx_noop));
        let wildcard = TABLE.add_listener(None, 8888).expect("wildcard listener registered");
        assert!(TABLE.add_listener(Some(owner(82)), 8888).is_none());
        assert!(TABLE.remove_listener_exact(&wildcard));

        let exact = TABLE.add_listener(Some(owner(82)), 8888).expect("exact listener registered");
        assert!(TABLE.add_listener(None, 8888).is_none());
        assert!(TABLE.remove_listener_exact(&exact));

        assert!(driver_uninstall(owner(81)));
        assert!(driver_uninstall(owner(82)));
    });
}

#[test]
fn same_port_listener_backlogs_are_owner_keyed() {
    with_vsock_state(|| {
        assert!(driver_install(owner(83), 3, tx_ok, rx_noop));
        assert!(driver_install(owner(84), 4, tx_ok, rx_noop));
        TABLE.add_listener(Some(owner(83)), 9999).expect("owner 83 listener registered");
        TABLE.add_listener(Some(owner(84)), 9999).expect("owner 84 listener registered");
        let req = VsockHdr {
            src_cid: 2, dst_cid: 3, src_port: 4444, dst_port: 9999,
            len: 0, typ: VIRTIO_VSOCK_TYPE_STREAM,
            op: VIRTIO_VSOCK_OP_REQUEST, flags: 0, buf_alloc: 8192, fwd_cnt: 0,
        };
        deliver_rx_from(owner(83), &req, &[]);
        deliver_rx_from(owner(84), &VsockHdr { dst_cid: 4, src_port: 5555, ..req }, &[]);
        let a = TABLE.pop_accept(Some(owner(83)), 9999).expect("owner 83 queued");
        let b = TABLE.pop_accept(Some(owner(84)), 9999).expect("owner 84 queued");
        assert_eq!((a.owner, a.peer_port), (owner(83), 4444));
        assert_eq!((b.owner, b.peer_port), (owner(84), 5555));
        assert!(TABLE.pop_accept(Some(owner(83)), 9999).is_none());
        assert!(TABLE.pop_accept(Some(owner(84)), 9999).is_none());
        TABLE.remove_conn(&a); TABLE.remove_conn(&b);
        assert!(driver_uninstall(owner(83))); assert!(driver_uninstall(owner(84)));
    });
}

#[test]
fn connect_from_uses_requested_live_endpoint_and_local_port() {
    with_vsock_state(|| {
        assert!(driver_install(owner(91), 3, tx_ok, rx_noop));
        assert!(driver_install(owner(92), 4, tx_ok, rx_noop));
        let c = connect_from(Some(owner(92)), Some(6000), 2, 1234).expect("connect queued");
        assert_eq!(c.owner, owner(92));
        assert_eq!(c.local_cid, 4);
        assert_eq!(c.local_port, 6000);
        TABLE.remove_conn(&c);
        assert!(driver_uninstall(owner(91)));
        assert!(driver_uninstall(owner(92)));
    });
}

#[test]
fn uninstall_closes_only_matching_owner_connections() {
    with_vsock_state(|| {
        assert!(driver_install(owner(51), 3, tx_ok, rx_noop));
        assert!(driver_install(owner(52), 4, tx_ok, rx_noop));
        let a = alloc::sync::Arc::new(
            VsockConn::new(owner(51), 3, 2100, 2, 1234, VsockState::Connected));
        let b = alloc::sync::Arc::new(
            VsockConn::new(owner(52), 4, 2100, 2, 1234, VsockState::Connected));
        assert!(TABLE.insert(a.clone()));
        assert!(TABLE.insert(b.clone()));

        assert!(driver_uninstall(owner(51)));
        assert_eq!(*a.st.lock(), VsockState::Closed);
        assert_eq!(*b.st.lock(), VsockState::Connected);
        assert!(TABLE.find(a.key()).is_none());
        assert!(TABLE.find(b.key()).is_some());

        TABLE.remove_conn(&b);
        assert!(driver_uninstall(owner(52)));
    });
}
