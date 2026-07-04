// Host tests for the PURE vsock protocol: header encode/decode round
// trips, credit accounting math, and the connection-table state machine
// across the 5 STREAM ops. Ring DMA is exercised by the boot smoke
// (tools/boot-smoke-vsock.sh), not here.

use super::*;
use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn tx_ok(_owner: u32, _frame: &[u8]) -> bool { true }

fn cleanup_driver_state() {
    loop {
        let owner = driver_owner();
        if owner == 0 {
            break;
        }
        let _ = driver_uninstall(owner);
        let _ = driver_cancel_reserved(owner);
    }
}

fn with_vsock_state<T>(f: impl FnOnce() -> T) -> T {
    let _guard = TEST_LOCK.lock().unwrap();
    cleanup_driver_state();
    let out = f();
    cleanup_driver_state();
    out
}

fn with_driver<T>(owner: u32, guest_cid: u64, f: impl FnOnce() -> T) -> T {
    with_vsock_state(|| {
        assert!(driver_install(owner, guest_cid, tx_ok));
        let out = f();
        assert!(driver_uninstall(owner));
        out
    })
}

#[test]
fn driver_reservation_is_not_live_until_publish() {
    with_vsock_state(|| {
        assert!(driver_reserve(7));
        assert!(!driver_up());
        assert_eq!(guest_cid(), 0);
        assert_eq!(driver_owner(), 0);
        assert!(driver_reserve(8));
        assert!(!driver_reserve(7));
        assert!(!driver_cancel_reserved(9));
        assert!(driver_cancel_reserved(8));
        assert!(driver_cancel_reserved(7));
        assert!(!driver_up());
        assert_eq!(driver_owner(), 0);
    });
}

#[test]
fn driver_endpoints_are_owner_keyed() {
    with_vsock_state(|| {
        assert!(driver_install(41, 3, tx_ok));
        assert!(driver_install(42, 4, tx_ok));
        assert!(!driver_install(41, 5, tx_ok));
        assert!(!driver_install(43, 4, tx_ok));
        assert!(driver_up_for(41));
        assert!(driver_up_for(42));
        assert_eq!(guest_cid_for(41), 3);
        assert_eq!(guest_cid_for(42), 4);
        assert!(driver_uninstall(41));
        assert!(!driver_up_for(41));
        assert!(driver_up_for(42));
        assert_eq!(guest_cid_for(42), 4);
        assert!(driver_uninstall(42));
    });
}

#[test]
fn driver_endpoint_uninstall_is_owner_keyed() {
    with_vsock_state(|| {
        assert!(driver_install(11, 3, tx_ok));
        assert!(driver_up());
        assert_eq!(guest_cid(), 3);
        assert_eq!(driver_owner(), 11);
        assert!(!driver_uninstall(12));
        assert!(driver_up());
        assert_eq!(guest_cid(), 3);
        assert!(driver_uninstall(11));
        assert!(!driver_up());
        assert_eq!(guest_cid(), 0);
        assert_eq!(driver_owner(), 0);
    });
}

#[test]
fn driver_quiesce_stops_tx_but_keeps_owner_reserved() {
    with_vsock_state(|| {
        assert!(driver_install(21, 9, tx_ok));
        assert!(driver_up());
        assert_eq!(guest_cid(), 9);
        assert_eq!(driver_owner(), 21);
        assert!(!driver_quiesce(22));
        assert!(driver_up());
        assert_eq!(guest_cid(), 9);

        assert!(driver_quiesce(21));
        assert!(!driver_up());
        assert_eq!(guest_cid(), 0);
        assert_eq!(driver_owner(), 0);
        assert!(!driver_reserve(21));
        assert!(driver_cancel_reserved(21));
        assert_eq!(driver_owner(), 0);
    });
}

#[test]
fn quiesced_endpoint_does_not_hide_remaining_live_endpoint() {
    with_vsock_state(|| {
        assert!(driver_install(31, 3, tx_ok));
        assert!(driver_install(32, 4, tx_ok));
        assert_eq!(driver_owner(), 31);
        assert_eq!(guest_cid(), 3);

        assert!(driver_quiesce(31));
        assert!(!driver_up_for(31));
        assert!(driver_up_for(32));
        assert_eq!(driver_owner(), 32);
        assert_eq!(guest_cid(), 4);
        assert!(!driver_reserve(31));

        assert!(driver_cancel_reserved(31));
        assert!(driver_uninstall(32));
        assert_eq!(driver_owner(), 0);
    });
}

#[test]
fn hdr_roundtrip_all_fields() {
    let h = VsockHdr {
        src_cid: 3, dst_cid: 2,
        src_port: 0xDEAD, dst_port: 1234,
        len: 16, typ: VIRTIO_VSOCK_TYPE_STREAM,
        op: VIRTIO_VSOCK_OP_RW, flags: 0,
        buf_alloc: 262144, fwd_cnt: 99,
    };
    let bytes = h.encode();
    assert_eq!(bytes.len(), VSOCK_HDR_LEN);
    let back = VsockHdr::decode(&bytes).unwrap();
    assert_eq!(h, back);
}

#[test]
fn hdr_is_little_endian_on_wire() {
    let h = VsockHdr { src_cid: 0x0102_0304_0506_0708, ..Default::default() };
    let b = h.encode();
    assert_eq!(&b[0..8], &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
}

#[test]
fn hdr_decode_short_buffer_none() {
    assert!(VsockHdr::decode(&[0u8; 43]).is_none());
    assert!(VsockHdr::decode(&[0u8; 44]).is_some());
}

#[test]
fn build_request_header() {
    let c = VsockConn::new(31, 3, 1024, 2, 1234, VsockState::Connecting);
    let h = c.make_hdr(VIRTIO_VSOCK_OP_REQUEST, 0, 0);
    assert_eq!(h.src_cid, 3);
    assert_eq!(h.dst_cid, 2);
    assert_eq!(h.src_port, 1024);
    assert_eq!(h.dst_port, 1234);
    assert_eq!(h.op, VIRTIO_VSOCK_OP_REQUEST);
    assert_eq!(h.typ, VIRTIO_VSOCK_TYPE_STREAM);
    assert_eq!(h.buf_alloc, VSOCK_DEFAULT_BUF_ALLOC);
    assert_eq!(h.fwd_cnt, 0);
}

#[test]
fn parse_response_promotes_state() {
    with_driver(31, 3, || {
        let c = alloc::sync::Arc::new(
            VsockConn::new(31, 3, 2000, 2, 1234, VsockState::Connecting));
        TABLE.insert(c.clone());
        let resp = VsockHdr {
            src_cid: 2, dst_cid: 3, src_port: 1234, dst_port: 2000,
            len: 0, typ: VIRTIO_VSOCK_TYPE_STREAM,
            op: VIRTIO_VSOCK_OP_RESPONSE, flags: 0,
            buf_alloc: 4096, fwd_cnt: 0,
        };
        deliver_rx(&resp, &[]);
        assert_eq!(*c.st.lock(), VsockState::Connected);
        assert_eq!(c.credit.lock().peer_buf_alloc, 4096);
        TABLE.remove(c.key());
    });
}

#[test]
fn credit_update_math() {
    let mut cr = Credit::default();
    cr.buf_alloc = 0; // isolate peer math
    cr.observe_peer(1000, 0);
    cr.tx_cnt = 200;
    // in-flight = 200 - 0 = 200; credit = 1000 - 200 = 800.
    assert_eq!(cr.peer_credit(), 800);
    // Peer consumed 150 → fwd_cnt 150; in-flight = 50; credit = 950.
    cr.observe_peer(1000, 150);
    assert_eq!(cr.peer_credit(), 950);
    // Saturating: peer window fully consumed → 0, never wraps.
    cr.tx_cnt = 5000;
    cr.observe_peer(1000, 0);
    assert_eq!(cr.peer_credit(), 0);
}

#[test]
fn rw_buffers_payload_and_recv_drains() {
    with_driver(32, 3, || {
        let c = alloc::sync::Arc::new(
            VsockConn::new(32, 3, 2001, 2, 1234, VsockState::Connected));
        TABLE.insert(c.clone());
        let payload = b"oxide-vsock-ping";
        let rw = VsockHdr {
            src_cid: 2, dst_cid: 3, src_port: 1234, dst_port: 2001,
            len: payload.len() as u32, typ: VIRTIO_VSOCK_TYPE_STREAM,
            op: VIRTIO_VSOCK_OP_RW, flags: 0, buf_alloc: 4096, fwd_cnt: 0,
        };
        deliver_rx(&rw, payload);
        let mut buf = [0u8; 32];
        let n = recv(&c, &mut buf).unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(&buf[..n], payload);
        // fwd_cnt bumped by what we consumed.
        assert_eq!(c.credit.lock().fwd_cnt, payload.len() as u32);
        TABLE.remove(c.key());
    });
}

#[test]
fn shutdown_then_eof() {
    with_driver(33, 3, || {
        let c = alloc::sync::Arc::new(
            VsockConn::new(33, 3, 2002, 2, 1234, VsockState::Connected));
        TABLE.insert(c.clone());
        let sh = VsockHdr {
            src_cid: 2, dst_cid: 3, src_port: 1234, dst_port: 2002,
            len: 0, typ: VIRTIO_VSOCK_TYPE_STREAM,
            op: VIRTIO_VSOCK_OP_SHUTDOWN,
            flags: VIRTIO_VSOCK_SHUTDOWN_SEND, buf_alloc: 0, fwd_cnt: 0,
        };
        deliver_rx(&sh, &[]);
        assert_eq!(*c.st.lock(), VsockState::RcvShutdown);
        // recv on an empty RcvShutdown conn = EOF (Ok(0)).
        let mut buf = [0u8; 8];
        assert_eq!(recv(&c, &mut buf).unwrap(), 0);
        TABLE.remove(c.key());
    });
}

#[test]
fn rst_closes_connection() {
    with_driver(34, 3, || {
        let c = alloc::sync::Arc::new(
            VsockConn::new(34, 3, 2003, 2, 1234, VsockState::Connected));
        TABLE.insert(c.clone());
        let rst = VsockHdr {
            src_cid: 2, dst_cid: 3, src_port: 1234, dst_port: 2003,
            len: 0, typ: VIRTIO_VSOCK_TYPE_STREAM,
            op: VIRTIO_VSOCK_OP_RST, flags: 0, buf_alloc: 0, fwd_cnt: 0,
        };
        deliver_rx(&rst, &[]);
        assert_eq!(*c.st.lock(), VsockState::Closed);
        TABLE.remove(c.key());
    });
}

#[test]
fn send_blocked_when_no_peer_credit() {
    with_vsock_state(|| {
        let c = VsockConn::new(0, 3, 2004, 2, 1234, VsockState::Connected);
        // peer_buf_alloc stays 0 → no credit → Eagain.
        assert_eq!(send(&c, b"data"), Err(crate::NetError::Eagain));
        // Open a window and it sends (tx hook is a no-op because no driver is
        // installed here) — assert credit gate, not the wire.
        c.credit.lock().observe_peer(1024, 0);
        // tx() returns false (no driver) → Eio; the gate let it through.
        assert_eq!(send(&c, b"data"), Err(crate::NetError::Eio));
    });
}

#[test]
fn listener_request_queues_accept() {
    with_driver(35, 3, || {
        TABLE.add_listener(5555);
        let req = VsockHdr {
            src_cid: 2, dst_cid: 3, src_port: 4444, dst_port: 5555,
            len: 0, typ: VIRTIO_VSOCK_TYPE_STREAM,
            op: VIRTIO_VSOCK_OP_REQUEST, flags: 0, buf_alloc: 8192, fwd_cnt: 0,
        };
        deliver_rx(&req, &[]);
        let k = TABLE.pop_accept(5555).expect("accept queued");
        assert_eq!(k.peer_cid, 2);
        assert_eq!(k.peer_port, 4444);
        assert_eq!(k.local_port, 5555);
        let conn = TABLE.find(k).expect("conn inserted");
        assert_eq!(*conn.st.lock(), VsockState::Connected);
        assert_eq!(conn.credit.lock().peer_buf_alloc, 8192);
        TABLE.remove(k);
    });
}

#[test]
fn rx_for_wrong_guest_cid_is_dropped() {
    with_driver(36, 3, || {
        TABLE.add_listener(6666);
        let req = VsockHdr {
            src_cid: 2, dst_cid: 99, src_port: 4444, dst_port: 6666,
            len: 0, typ: VIRTIO_VSOCK_TYPE_STREAM,
            op: VIRTIO_VSOCK_OP_REQUEST, flags: 0, buf_alloc: 8192, fwd_cnt: 0,
        };
        deliver_rx(&req, &[]);
        assert!(TABLE.pop_accept(6666).is_none());
    });
}

#[test]
fn rx_from_wrong_owner_is_dropped() {
    with_driver(37, 3, || {
        TABLE.add_listener(7777);
        let req = VsockHdr {
            src_cid: 2, dst_cid: 3, src_port: 4444, dst_port: 7777,
            len: 0, typ: VIRTIO_VSOCK_TYPE_STREAM,
            op: VIRTIO_VSOCK_OP_REQUEST, flags: 0, buf_alloc: 8192, fwd_cnt: 0,
        };
        deliver_rx_from(38, &req, &[]);
        assert!(TABLE.pop_accept(7777).is_none());
        deliver_rx_from(37, &req, &[]);
        assert!(TABLE.pop_accept(7777).is_some());
    });
}

#[test]
fn uninstall_closes_only_matching_owner_connections() {
    with_vsock_state(|| {
        assert!(driver_install(51, 3, tx_ok));
        assert!(driver_install(52, 4, tx_ok));
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
