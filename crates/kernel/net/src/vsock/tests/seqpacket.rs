use super::*;

use std::sync::Mutex;

const OWNER_RAW: u32 = 0x0d00_0001;
const LOCAL_CID: u64 = 3;
const PEER_CID: u64 = 2;
const LOCAL_PORT: u32 = 63_000;
const PEER_PORT: u32 = 1_024;
const LISTENER_PORT: u32 = 63_001;
const PEER_WINDOW: u32 = 4_096;
const SMALL_CAPACITY: usize = 3;
const RECORD: &[u8] = b"record";
const TEST_TX_PAYLOAD_LIMIT: usize = usize::MAX;

static FRAMES: Mutex<std::vec::Vec<VsockHdr>> = Mutex::new(std::vec::Vec::new());

fn tx_capture(_owner: VsockOwner, frame: &[u8]) -> bool {
    FRAMES.lock().unwrap().push(VsockHdr::decode(frame).expect("vsock frame header"));
    true
}

#[test]
fn negotiated_feature_gates_seqpacket_endpoint_and_tx_record_flags() {
    with_vsock_state(|| {
        FRAMES.lock().unwrap().clear();
        let owner = owner(OWNER_RAW);
        assert!(driver_reserve(owner));
        assert!(driver_publish_reserved(owner, LOCAL_CID, VIRTIO_VSOCK_F_SEQPACKET_MASK,
            TEST_TX_PAYLOAD_LIMIT, tx_capture, rx_noop));
        assert!(driver_supports_seqpacket());
        assert!(driver_supports_seqpacket_for(owner));
        let conn = VsockConn::new_with_filter_type(owner, LOCAL_CID, LOCAL_PORT, PEER_CID,
            PEER_PORT, VsockState::Connected, VsockTransportType::Seqpacket,
            alloc::sync::Arc::new(crate::bpf_filter::SocketFilter::new()));
        conn.tx.lock().credit.observe_peer(PEER_WINDOW, 0);
        assert_eq!(send_seqpacket(&conn, RECORD, true), Ok(RECORD.len()));
        let frames = FRAMES.lock().unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].typ, VIRTIO_VSOCK_TYPE_SEQPACKET);
        assert_eq!(frames[0].flags, VIRTIO_VSOCK_SEQ_EOM | VIRTIO_VSOCK_SEQ_EOR);
        drop(frames);
        assert!(driver_uninstall(owner));
    });
}

#[test]
fn seqpacket_truncation_retires_full_record_credit() {
    with_vsock_state(|| {
        let conn = VsockConn::new_with_filter_type(owner(OWNER_RAW), LOCAL_CID, LOCAL_PORT,
            PEER_CID, PEER_PORT, VsockState::Connected, VsockTransportType::Seqpacket,
            alloc::sync::Arc::new(crate::bpf_filter::SocketFilter::new()));
        conn.seq_rx.lock().push_fragment(RECORD, VIRTIO_VSOCK_SEQ_EOM);
        let received = recv_seqpacket_with(&conn, SMALL_CAPACITY, false,
            |bytes| Ok::<_, ()>(bytes.to_vec())).expect("record receive");
        assert!(matches!(received, SeqpacketRecvWith::Data(ref bytes, delivery)
            if bytes == &RECORD[..SMALL_CAPACITY] && delivery.truncated));
        assert_eq!(conn.tx.lock().credit.fwd_cnt, RECORD.len() as u32);
    });
}

#[test]
fn unnegotiated_endpoint_resets_inbound_seqpacket_without_accepting() {
    with_vsock_state(|| {
        FRAMES.lock().unwrap().clear();
        let owner = owner(OWNER_RAW);
        assert!(driver_reserve(owner));
        assert!(driver_publish_reserved(owner, LOCAL_CID, 0, TEST_TX_PAYLOAD_LIMIT,
            tx_capture, rx_noop));
        assert!(!driver_supports_seqpacket_for(owner));
        TABLE.add_listener(Some(owner), LISTENER_PORT).expect("listener registration");
        let request = VsockHdr {
            src_cid: PEER_CID, dst_cid: LOCAL_CID, src_port: PEER_PORT,
            dst_port: LISTENER_PORT, len: 0, typ: VIRTIO_VSOCK_TYPE_SEQPACKET,
            op: VIRTIO_VSOCK_OP_REQUEST, flags: 0, buf_alloc: PEER_WINDOW, fwd_cnt: 0,
        };
        deliver_rx_from(owner, &request, &[]);
        assert!(TABLE.pop_accept(Some(owner), LISTENER_PORT).is_none());
        let frames = FRAMES.lock().unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].op, VIRTIO_VSOCK_OP_RST);
        assert_eq!(frames[0].typ, VIRTIO_VSOCK_TYPE_SEQPACKET);
        drop(frames);
        assert!(driver_uninstall(owner));
    });
}
