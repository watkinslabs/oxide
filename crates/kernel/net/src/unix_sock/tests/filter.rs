use super::*;
use alloc::vec::Vec;
use crate::bpf_filter::{FilterKind, FilterProgram, SocketFilter, install_bpf_filter_runner};

fn verdict_runner(_kind: FilterKind, insns: &[u8], _packet: &[u8]) -> u32 {
    u32::from_ne_bytes(insns.try_into().unwrap())
}

fn filter(verdict: u32) -> alloc::sync::Arc<SocketFilter> {
    let filter = alloc::sync::Arc::new(SocketFilter::new());
    filter.attach(FilterProgram {
        kind: FilterKind::Ebpf, insns: verdict.to_ne_bytes().to_vec(),
    }).unwrap();
    filter
}

#[test]
fn pathname_datagram_filter_sees_payload_drops_zero_and_truncates_positive() {
    let _guard = test_guard();
    install_bpf_filter_runner(verdict_runner);
    let filter = filter(3);
    let queue = UnixDgramQueue::new_with_filter(filter.clone());
    queue.try_push(UnixDgram { payload: b"abcdef".to_vec(), creds: (1, 2, 3), fds: Vec::new() })
        .unwrap();
    assert_eq!(queue.pop().unwrap().payload, b"abc");

    filter.attach(FilterProgram {
        kind: FilterKind::Ebpf, insns: 0u32.to_ne_bytes().to_vec(),
    }).unwrap();
    assert_eq!(queue.try_push_from_with_rights_bounded(
        UnixDgram { payload: b"oversized".to_vec(), creds: (1, 2, 3), fds: Vec::new() }, None,
        GcRights::from_files(Vec::new()), 3), Err(crate::NetError::Emsgsize));
    queue.try_push(UnixDgram { payload: b"dropped".to_vec(), creds: (1, 2, 3), fds: Vec::new() })
        .unwrap();
    assert!(queue.pop().is_none());
}

#[test]
fn socketpair_datagram_and_seqpacket_filters_apply_receiver_state() {
    let _guard = test_guard();
    install_bpf_filter_runner(verdict_runner);
    for pair in [UnixMsgPair::new_datagram(), UnixMsgPair::new()] {
        let receiver = filter(3);
        pair.attach_end_filter(UnixEnd::B, &receiver);
        assert_eq!(pair.send(UnixEnd::A, b"abcdef"), Ok(6));
        assert_eq!(pair.recv(UnixEnd::B, 64).unwrap(), b"abc");

        receiver.attach(FilterProgram {
            kind: FilterKind::Ebpf, insns: 0u32.to_ne_bytes().to_vec(),
        }).unwrap();
        assert_eq!(pair.send_bounded(UnixEnd::A, b"oversized", 3),
            Err(UnixMsgSendError::MessageTooLarge));
        assert_eq!(pair.send(UnixEnd::A, b"dropped"), Ok(7));
        assert!(pair.recv(UnixEnd::B, 64).is_none());
    }
}
