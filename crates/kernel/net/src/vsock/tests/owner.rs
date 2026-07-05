use super::*;

#[test]
fn exact_owner_listener_wins_over_wildcard_listener() {
    with_vsock_state(|| {
        assert!(driver_install(81, 3, tx_ok, rx_noop));
        assert!(driver_install(82, 4, tx_ok, rx_noop));
        TABLE.add_listener(0, 8888);
        TABLE.add_listener(82, 8888);

        let req_b = VsockHdr {
            src_cid: 2, dst_cid: 4, src_port: 4444, dst_port: 8888,
            len: 0, typ: VIRTIO_VSOCK_TYPE_STREAM,
            op: VIRTIO_VSOCK_OP_REQUEST, flags: 0, buf_alloc: 8192, fwd_cnt: 0,
        };
        deliver_rx_from(82, &req_b, &[]);
        assert!(TABLE.pop_accept(0, 8888).is_none());
        let exact = TABLE.pop_accept(82, 8888).expect("exact listener queued");
        assert_eq!(exact.owner, 82);
        TABLE.remove(exact);

        let req_a = VsockHdr { dst_cid: 3, ..req_b };
        deliver_rx_from(81, &req_a, &[]);
        let wildcard = TABLE.pop_accept(0, 8888).expect("wildcard listener queued");
        assert_eq!(wildcard.owner, 81);
        TABLE.remove(wildcard);

        assert!(driver_uninstall(81));
        assert!(driver_uninstall(82));
    });
}

#[test]
fn same_port_listener_backlogs_are_owner_keyed() {
    with_vsock_state(|| {
        assert!(driver_install(83, 3, tx_ok, rx_noop));
        assert!(driver_install(84, 4, tx_ok, rx_noop));
        TABLE.add_listener(83, 9999); TABLE.add_listener(84, 9999);
        let req = VsockHdr {
            src_cid: 2, dst_cid: 3, src_port: 4444, dst_port: 9999,
            len: 0, typ: VIRTIO_VSOCK_TYPE_STREAM,
            op: VIRTIO_VSOCK_OP_REQUEST, flags: 0, buf_alloc: 8192, fwd_cnt: 0,
        };
        deliver_rx_from(83, &req, &[]);
        deliver_rx_from(84, &VsockHdr { dst_cid: 4, src_port: 5555, ..req }, &[]);
        let a = TABLE.pop_accept(83, 9999).expect("owner 83 queued");
        let b = TABLE.pop_accept(84, 9999).expect("owner 84 queued");
        assert_eq!((a.owner, a.peer_port), (83, 4444));
        assert_eq!((b.owner, b.peer_port), (84, 5555));
        assert!(TABLE.pop_accept(83, 9999).is_none());
        assert!(TABLE.pop_accept(84, 9999).is_none());
        TABLE.remove(a); TABLE.remove(b);
        assert!(driver_uninstall(83)); assert!(driver_uninstall(84));
    });
}

#[test]
fn connect_from_uses_requested_live_endpoint_and_local_port() {
    with_vsock_state(|| {
        assert!(driver_install(91, 3, tx_ok, rx_noop));
        assert!(driver_install(92, 4, tx_ok, rx_noop));
        let c = connect_from(92, Some(6000), 2, 1234).expect("connect queued");
        assert_eq!(c.owner, 92);
        assert_eq!(c.local_cid, 4);
        assert_eq!(c.local_port, 6000);
        TABLE.remove(c.key());
        assert!(driver_uninstall(91));
        assert!(driver_uninstall(92));
    });
}

#[test]
fn uninstall_closes_only_matching_owner_connections() {
    with_vsock_state(|| {
        assert!(driver_install(51, 3, tx_ok, rx_noop));
        assert!(driver_install(52, 4, tx_ok, rx_noop));
        let a = alloc::sync::Arc::new(
            VsockConn::new(51, 3, 2100, 2, 1234, VsockState::Connected));
        let b = alloc::sync::Arc::new(
            VsockConn::new(52, 4, 2100, 2, 1234, VsockState::Connected));
        TABLE.insert(a.clone());
        TABLE.insert(b.clone());

        assert!(driver_uninstall(51));
        assert_eq!(*a.st.lock(), VsockState::Closed);
        assert_eq!(*b.st.lock(), VsockState::Connected);
        assert!(TABLE.find(a.key()).is_none());
        assert!(TABLE.find(b.key()).is_some());

        TABLE.remove(b.key());
        assert!(driver_uninstall(52));
    });
}
