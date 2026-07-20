// Host tests for the PURE vsock protocol: header encode/decode round
// trips, credit accounting math, and the connection-table state machine
// across the 5 STREAM ops. Ring DMA is exercised by the boot smoke
// (tools/boot-smoke-vsock.sh), not here.

use super::*;
use std::sync::atomic::{AtomicU32 as TestAtomicU32, Ordering as TestOrdering};

mod owner;
mod identity;
mod filter;
mod seqpacket;
pub(crate) use super::hosted_test::{domain as test_domain, Domain as TestDomain};

static TX_A_OWNER: TestAtomicU32 = TestAtomicU32::new(0);
static TX_B_OWNER: TestAtomicU32 = TestAtomicU32::new(0);
static RX_A_OWNER: TestAtomicU32 = TestAtomicU32::new(0);
static RX_B_OWNER: TestAtomicU32 = TestAtomicU32::new(0);

fn tx_ok(_owner: VsockOwner, _frame: &[u8]) -> bool { true }
fn rx_noop(_owner: VsockOwner) -> usize { 0 }
fn tx_a(owner: VsockOwner, _frame: &[u8]) -> bool {
    TX_A_OWNER.store(owner.raw(), TestOrdering::Relaxed);
    true
}
fn tx_b(owner: VsockOwner, _frame: &[u8]) -> bool {
    TX_B_OWNER.store(owner.raw(), TestOrdering::Relaxed);
    true
}
fn rx_a(owner: VsockOwner) -> usize {
    RX_A_OWNER.store(owner.raw(), TestOrdering::Relaxed);
    1
}
fn rx_b(owner: VsockOwner) -> usize {
    RX_B_OWNER.store(owner.raw(), TestOrdering::Relaxed);
    1
}

fn owner(raw: u32) -> VsockOwner {
    VsockOwner::from_raw(raw).expect("test owner is nonzero")
}

fn with_vsock_state<T>(f: impl FnOnce() -> T) -> T {
    let _domain = test_domain();
    f()
}

fn with_driver<T>(owner: VsockOwner, guest_cid: u64, f: impl FnOnce() -> T) -> T {
    with_vsock_state(|| {
        assert!(driver_install(owner, guest_cid, tx_ok, rx_noop));
        let out = f();
        assert!(driver_uninstall(owner));
        out
    })
}

#[test]
fn driver_reservation_is_not_live_until_publish() {
    with_vsock_state(|| {
        assert!(driver_reserve(owner(7)));
        assert!(!driver_up());
        assert_eq!(guest_cid(), 0);
        assert_eq!(driver_owner(), None);
        assert!(driver_reserve(owner(8)));
        assert!(!driver_reserve(owner(7)));
        assert!(!driver_cancel_reserved(owner(9)));
        assert!(driver_cancel_reserved(owner(8)));
        assert!(driver_cancel_reserved(owner(7)));
        assert!(!driver_up());
        assert_eq!(driver_owner(), None);
    });
}

#[test]
fn driver_owner_for_cid_resolves_only_live_endpoint() {
    with_vsock_state(|| {
        assert!(driver_install(owner(71), 3, tx_ok, rx_noop));
        assert!(driver_install(owner(72), 4, tx_ok, rx_noop));
        assert_eq!(driver_owner_for_cid(3), Some(owner(71)));
        assert_eq!(driver_owner_for_cid(4), Some(owner(72)));
        assert_eq!(driver_owner_for_cid(5), None);

        assert!(driver_quiesce(owner(71)));
        assert_eq!(driver_owner_for_cid(3), None);
        assert_eq!(driver_owner_for_cid(4), Some(owner(72)));
        assert!(driver_cancel_reserved(owner(71)));
        assert!(driver_uninstall(owner(72)));
    });
}

#[test]
fn bind_owner_for_cid_requires_matching_live_endpoint() {
    with_vsock_state(|| {
        assert_eq!(bind_owner_for_cid(VMADDR_CID_ANY), Ok(None));
        assert_eq!(bind_owner_for_cid(3), Err(NetError::Eaddrnotavail));
        assert!(driver_install(owner(73), 3, tx_ok, rx_noop));
        assert!(driver_install(owner(74), 4, tx_ok, rx_noop));
        assert_eq!(bind_owner_for_cid(3), Ok(Some(owner(73))));
        assert_eq!(bind_owner_for_cid(4), Ok(Some(owner(74))));

        assert!(driver_quiesce(owner(73)));
        assert_eq!(bind_owner_for_cid(3), Err(NetError::Eaddrnotavail));
        assert_eq!(bind_owner_for_cid(4), Ok(Some(owner(74))));
        assert!(driver_cancel_reserved(owner(73)));
        assert!(driver_uninstall(owner(74)));
    });
}

#[test]
fn driver_endpoints_are_owner_keyed() {
    with_vsock_state(|| {
        assert!(driver_install(owner(41), 3, tx_ok, rx_noop));
        assert!(driver_install(owner(42), 4, tx_ok, rx_noop));
        assert!(!driver_install(owner(41), 5, tx_ok, rx_noop));
        assert!(!driver_install(owner(43), 4, tx_ok, rx_noop));
        assert!(driver_up_for(owner(41)));
        assert!(driver_up_for(owner(42)));
        assert_eq!(guest_cid_for(owner(41)), 3);
        assert_eq!(guest_cid_for(owner(42)), 4);
        assert!(driver_uninstall(owner(41)));
        assert!(!driver_up_for(owner(41)));
        assert!(driver_up_for(owner(42)));
        assert_eq!(guest_cid_for(owner(42)), 4);
        assert!(driver_uninstall(owner(42)));
    });
}

#[test]
fn tx_for_routes_through_matching_owner_endpoint() {
    with_vsock_state(|| {
        TX_A_OWNER.store(0, TestOrdering::Relaxed);
        TX_B_OWNER.store(0, TestOrdering::Relaxed);
        assert!(driver_install(owner(61), 3, tx_a, rx_noop));
        assert!(driver_install(owner(62), 4, tx_b, rx_noop));
        let h = VsockHdr::default();

        assert!(tx_for(owner(62), &h, &[]));
        assert_eq!(TX_A_OWNER.load(TestOrdering::Relaxed), 0);
        assert_eq!(TX_B_OWNER.load(TestOrdering::Relaxed), 62);

        assert!(tx_for(owner(61), &h, &[]));
        assert_eq!(TX_A_OWNER.load(TestOrdering::Relaxed), 61);
        assert_eq!(TX_B_OWNER.load(TestOrdering::Relaxed), 62);
        assert!(!tx_for(owner(63), &h, &[]));

        assert!(driver_uninstall(owner(61)));
        assert!(driver_uninstall(owner(62)));
    });
}

#[test]
fn rx_poll_routes_through_matching_owner_endpoint() {
    with_vsock_state(|| {
        RX_A_OWNER.store(0, TestOrdering::Relaxed);
        RX_B_OWNER.store(0, TestOrdering::Relaxed);
        assert!(driver_install(owner(63), 3, tx_ok, rx_a));
        assert!(driver_install(owner(64), 4, tx_ok, rx_b));

        assert_eq!(poll_rx_for(owner(64)), 1);
        assert_eq!(RX_A_OWNER.load(TestOrdering::Relaxed), 0);
        assert_eq!(RX_B_OWNER.load(TestOrdering::Relaxed), 64);

        assert_eq!(poll_rx_for(owner(63)), 1);
        assert_eq!(RX_A_OWNER.load(TestOrdering::Relaxed), 63);
        assert_eq!(RX_B_OWNER.load(TestOrdering::Relaxed), 64);
        assert_eq!(poll_rx_for(owner(65)), 0);

        assert!(driver_uninstall(owner(63)));
        assert!(driver_uninstall(owner(64)));
    });
}

#[test]
fn driver_endpoint_uninstall_is_owner_keyed() {
    with_vsock_state(|| {
        assert!(driver_install(owner(11), 3, tx_ok, rx_noop));
        assert!(driver_up());
        assert_eq!(guest_cid(), 3);
        assert_eq!(driver_owner(), Some(owner(11)));
        assert!(!driver_uninstall(owner(12)));
        assert!(driver_up());
        assert_eq!(guest_cid(), 3);
        assert!(driver_uninstall(owner(11)));
        assert!(!driver_up());
        assert_eq!(guest_cid(), 0);
        assert_eq!(driver_owner(), None);
    });
}

#[test]
fn driver_quiesce_stops_tx_but_keeps_owner_reserved() {
    with_vsock_state(|| {
        assert!(driver_install(owner(21), 9, tx_ok, rx_noop));
        assert!(driver_up());
        assert_eq!(guest_cid(), 9);
        assert_eq!(driver_owner(), Some(owner(21)));
        assert!(!driver_quiesce(owner(22)));
        assert!(driver_up());
        assert_eq!(guest_cid(), 9);

        assert!(driver_quiesce(owner(21)));
        assert!(!driver_up());
        assert_eq!(guest_cid(), 0);
        assert_eq!(driver_owner(), None);
        assert!(!driver_reserve(owner(21)));
        assert!(driver_cancel_reserved(owner(21)));
        assert_eq!(driver_owner(), None);
    });
}

#[test]
fn quiesced_endpoint_does_not_hide_remaining_live_endpoint() {
    with_vsock_state(|| {
        assert!(driver_install(owner(31), 3, tx_ok, rx_noop));
        assert!(driver_install(owner(32), 4, tx_ok, rx_noop));
        assert_eq!(driver_owner(), Some(owner(31)));
        assert_eq!(guest_cid(), 3);

        assert!(driver_quiesce(owner(31)));
        assert!(!driver_up_for(owner(31)));
        assert!(driver_up_for(owner(32)));
        assert_eq!(driver_owner(), Some(owner(32)));
        assert_eq!(guest_cid(), 4);
        assert!(!driver_reserve(owner(31)));

        assert!(driver_cancel_reserved(owner(31)));
        assert!(driver_uninstall(owner(32)));
        assert_eq!(driver_owner(), None);
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
    let c = VsockConn::new(owner(31), 3, 1024, 2, 1234, VsockState::Connecting);
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
fn seqpacket_connection_emits_seqpacket_wire_type() {
    const OWNER_RAW: u32 = 31;
    const LOCAL_CID: u64 = 3;
    const LOCAL_PORT: u32 = 1024;
    const PEER_CID: u64 = 2;
    const PEER_PORT: u32 = 1234;
    const EMPTY_PAYLOAD_LENGTH: u32 = 0;
    const NO_FLAGS: u32 = 0;
    let c = VsockConn::new_with_filter_type(owner(OWNER_RAW), LOCAL_CID, LOCAL_PORT,
        PEER_CID, PEER_PORT, VsockState::Connecting, VsockTransportType::Seqpacket,
        alloc::sync::Arc::new(crate::bpf_filter::SocketFilter::new()));
    let h = c.make_hdr(VIRTIO_VSOCK_OP_REQUEST, EMPTY_PAYLOAD_LENGTH, NO_FLAGS);
    assert_eq!(h.typ, VIRTIO_VSOCK_TYPE_SEQPACKET);
}

#[test]
fn parse_response_promotes_state() {
    with_driver(owner(31), 3, || {
        let c = alloc::sync::Arc::new(
            VsockConn::new(owner(31), 3, 2000, 2, 1234, VsockState::Connecting));
        assert!(TABLE.insert(c.clone()));
        let resp = VsockHdr {
            src_cid: 2, dst_cid: 3, src_port: 1234, dst_port: 2000,
            len: 0, typ: VIRTIO_VSOCK_TYPE_STREAM,
            op: VIRTIO_VSOCK_OP_RESPONSE, flags: 0,
            buf_alloc: 4096, fwd_cnt: 0,
        };
        deliver_rx(&resp, &[]);
        assert_eq!(*c.st.lock(), VsockState::Connected);
        assert_eq!(c.tx.lock().credit.peer_buf_alloc, 4096);
        TABLE.remove_conn(&c);
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
fn socket_buffer_policy_controls_advertised_credit() {
    let c = VsockConn::new(VsockOwner::from_raw(1).unwrap(), 1, 2, 3, 4,
        VsockState::Connected);
    c.set_local_buf_alloc(4096);
    assert_eq!(c.tx.lock().credit.buf_alloc, 4096);
}

#[test]
fn rw_buffers_payload_and_recv_drains() {
    with_driver(owner(32), 3, || {
        let c = alloc::sync::Arc::new(
            VsockConn::new(owner(32), 3, 2001, 2, 1234, VsockState::Connected));
        assert!(TABLE.insert(c.clone()));
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
        assert_eq!(c.tx.lock().credit.fwd_cnt, payload.len() as u32);
        TABLE.remove_conn(&c);
    });
}

#[test]
fn recv_with_fault_rolls_back_and_peek_preserves_stream() {
    with_driver(owner(34), 3, || {
        let c = alloc::sync::Arc::new(
            VsockConn::new(owner(34), 3, 2003, 2, 1234, VsockState::Connected));
        c.rx.lock().extend(b"transaction".iter().copied());
        assert!(matches!(recv_with(&c, 64, false, |_| Err::<((), usize), _>(7u8)), Err(7)));
        let partial = recv_with(&c, 64, false, |bytes| Ok::<_, ()>((bytes[..4].to_vec(), 4))).unwrap();
        assert!(matches!(partial, RecvWith::Data(ref bytes) if bytes == b"tran"));
        let peeked = recv_with(&c, 64, true, |bytes| Ok::<_, ()>((bytes.to_vec(), bytes.len()))).unwrap();
        assert!(matches!(peeked, RecvWith::Data(ref bytes) if bytes == b"saction"));
        let consumed = recv_with(&c, 64, false, |bytes| Ok::<_, ()>((bytes.to_vec(), bytes.len()))).unwrap();
        assert!(matches!(consumed, RecvWith::Data(ref bytes) if bytes == b"saction"));
        assert!(c.rx.lock().is_empty());
        assert_eq!(c.tx.lock().credit.fwd_cnt, 11);
    });
}

#[test]
fn recv_peek_offset_reads_waitall_suffix_without_consuming() {
    with_driver(owner(35), 3, || {
        let c = alloc::sync::Arc::new(
            VsockConn::new(owner(35), 3, 2004, 2, 1234, VsockState::Connected));
        c.rx.lock().extend(b"abcdef".iter().copied());
        let first = recv_with_offset(&c, 3, true, 0,
            |bytes| Ok::<_, ()>((bytes.to_vec(), 0))).unwrap();
        let second = recv_with_offset(&c, 3, true, 3,
            |bytes| Ok::<_, ()>((bytes.to_vec(), 0))).unwrap();
        assert!(matches!(first, RecvWith::Data(ref bytes) if bytes == b"abc"));
        assert!(matches!(second, RecvWith::Data(ref bytes) if bytes == b"def"));
        assert_eq!(c.rx.lock().iter().copied().collect::<alloc::vec::Vec<_>>(), b"abcdef");
    });
}

#[test]
fn shutdown_then_eof() {
    with_driver(owner(33), 3, || {
        let c = alloc::sync::Arc::new(
            VsockConn::new(owner(33), 3, 2002, 2, 1234, VsockState::Connected));
        assert!(TABLE.insert(c.clone()));
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
        TABLE.remove_conn(&c);
    });
}

#[test]
fn rst_closes_connection() {
    with_driver(owner(34), 3, || {
        let c = alloc::sync::Arc::new(
            VsockConn::new(owner(34), 3, 2003, 2, 1234, VsockState::Connected));
        assert!(TABLE.insert(c.clone()));
        let rst = VsockHdr {
            src_cid: 2, dst_cid: 3, src_port: 1234, dst_port: 2003,
            len: 0, typ: VIRTIO_VSOCK_TYPE_STREAM,
            op: VIRTIO_VSOCK_OP_RST, flags: 0, buf_alloc: 0, fwd_cnt: 0,
        };
        deliver_rx(&rst, &[]);
        assert_eq!(*c.st.lock(), VsockState::Closed);
        TABLE.remove_conn(&c);
    });
}

#[test]
fn send_blocked_when_no_peer_credit() {
    with_vsock_state(|| {
        let c = VsockConn::new(owner(39), 3, 2004, 2, 1234, VsockState::Connected);
        // peer_buf_alloc stays 0 → no credit → Eagain.
        assert_eq!(send(&c, b"data"), Err(crate::NetError::Eagain));
        // Open a window and it sends (tx hook is a no-op because no driver is
        // installed here) — assert credit gate, not the wire.
        c.tx.lock().credit.observe_peer(1024, 0);
        // tx() returns false (no driver) → Eio; the gate let it through.
        assert_eq!(send(&c, b"data"), Err(crate::NetError::Eio));
    });
}

#[test]
fn listener_request_queues_accept() {
    with_driver(owner(35), 3, || {
        TABLE.add_listener(Some(owner(35)), 5555).expect("listener registered");
        let req = VsockHdr {
            src_cid: 2, dst_cid: 3, src_port: 4444, dst_port: 5555,
            len: 0, typ: VIRTIO_VSOCK_TYPE_STREAM,
            op: VIRTIO_VSOCK_OP_REQUEST, flags: 0, buf_alloc: 8192, fwd_cnt: 0,
        };
        deliver_rx(&req, &[]);
        let conn = TABLE.pop_accept(Some(owner(35)), 5555).expect("accept queued");
        assert_eq!(conn.peer_cid, 2);
        assert_eq!(conn.peer_port, 4444);
        assert_eq!(conn.local_port, 5555);
        assert_eq!(*conn.st.lock(), VsockState::Connected);
        assert_eq!(conn.tx.lock().credit.peer_buf_alloc, 8192);
        TABLE.remove_conn(&conn);
    });
}

#[test]
fn rx_for_wrong_guest_cid_is_dropped() {
    with_driver(owner(36), 3, || {
        TABLE.add_listener(Some(owner(36)), 6666).expect("listener registered");
        let req = VsockHdr {
            src_cid: 2, dst_cid: 99, src_port: 4444, dst_port: 6666,
            len: 0, typ: VIRTIO_VSOCK_TYPE_STREAM,
            op: VIRTIO_VSOCK_OP_REQUEST, flags: 0, buf_alloc: 8192, fwd_cnt: 0,
        };
        deliver_rx(&req, &[]);
        assert!(TABLE.pop_accept(Some(owner(36)), 6666).is_none());
    });
}

#[test]
fn rx_from_wrong_owner_is_dropped() {
    with_driver(owner(37), 3, || {
        TABLE.add_listener(Some(owner(37)), 7777).expect("listener registered");
        let req = VsockHdr {
            src_cid: 2, dst_cid: 3, src_port: 4444, dst_port: 7777,
            len: 0, typ: VIRTIO_VSOCK_TYPE_STREAM,
            op: VIRTIO_VSOCK_OP_REQUEST, flags: 0, buf_alloc: 8192, fwd_cnt: 0,
        };
        deliver_rx_from(owner(38), &req, &[]);
        assert!(TABLE.pop_accept(Some(owner(37)), 7777).is_none());
        deliver_rx_from(owner(37), &req, &[]);
        assert!(TABLE.pop_accept(Some(owner(37)), 7777).is_some());
    });
}
