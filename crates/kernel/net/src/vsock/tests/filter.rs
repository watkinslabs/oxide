use super::*;
use crate::bpf_filter::{FilterKind, FilterProgram, install_bpf_filter_runner};

fn verdict_runner(_kind: FilterKind, insns: &[u8], _packet: &[u8]) -> u32 {
    u32::from_ne_bytes(insns.try_into().unwrap())
}

fn attach(conn: &VsockConn, verdict: u32) {
    conn.bpf_filter.attach(FilterProgram {
        kind: FilterKind::Ebpf, insns: verdict.to_ne_bytes().to_vec(),
    }).unwrap();
}

fn rw(port: u32, len: usize) -> VsockHdr {
    VsockHdr {
        src_cid: 2, dst_cid: 3, src_port: 1234, dst_port: port,
        len: len as u32, typ: VIRTIO_VSOCK_TYPE_STREAM,
        op: VIRTIO_VSOCK_OP_RW, flags: 0, buf_alloc: 4096, fwd_cnt: 0,
    }
}

#[test]
fn receive_filter_sees_payload_drops_zero_and_truncates_positive() {
    install_bpf_filter_runner(verdict_runner);
    with_driver(owner(81), 3, || {
        let conn = alloc::sync::Arc::new(
            VsockConn::new(owner(81), 3, 2081, 2, 1234, VsockState::Connected));
        attach(&conn, 3);
        assert!(TABLE.insert(conn.clone()));
        deliver_rx(&rw(2081, 6), b"abcdef");
        let mut buf = [0u8; 16];
        assert_eq!(recv(&conn, &mut buf), Ok(3));
        assert_eq!(&buf[..3], b"abc");

        attach(&conn, 0);
        deliver_rx(&rw(2081, 7), b"dropped");
        assert!(conn.rx.lock().is_empty());
        TABLE.remove_conn(&conn);
    });
}

#[test]
fn outbound_connection_shares_live_socket_filter_state() {
    with_driver(owner(82), 3, || {
        let socket = alloc::sync::Arc::new(crate::vsock_socket::VsockSocket::new());
        let conn = prepare_connect_owned(Some(owner(82)), Some(2082), 2, 1234,
            Some(alloc::sync::Arc::downgrade(&socket))).unwrap();
        assert!(alloc::sync::Arc::ptr_eq(&socket.bpf_filter, &conn.bpf_filter));
        socket.bpf_filter.attach(FilterProgram {
            kind: FilterKind::Ebpf, insns: 3u32.to_ne_bytes().to_vec(),
        }).unwrap();
        assert!(conn.bpf_filter.is_attached());
    });
}
