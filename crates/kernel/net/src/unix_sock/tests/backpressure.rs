use super::*;

#[test]
fn stream_capacity_is_partial_and_reusable_after_dequeue() {
    let _serial = test_guard();
    let pair = UnixPair::new();

    assert_eq!(pair.write_bounded(UnixEnd::A, b"abcdef", 4), Ok(4));
    assert_eq!(pair.write_bounded(UnixEnd::A, b"ef", 4),
        Err(UnixStreamSendError::WouldBlock));
    assert_eq!(pair.read(UnixEnd::B, 2), b"ab");
    assert_eq!(pair.write_bounded(UnixEnd::A, b"ef", 4), Ok(2));
    assert_eq!(pair.read(UnixEnd::B, 8), b"cdef");
}

fn atomic_pair_capacity(kind: UnixMsgKind) {
    let pair = match kind {
        UnixMsgKind::Datagram => UnixMsgPair::new_datagram(),
        UnixMsgKind::SeqPacket => UnixMsgPair::new(),
    };

    assert_eq!(pair.send_bounded(UnixEnd::A, b"abc", 5), Ok(3));
    assert_eq!(pair.send_bounded(UnixEnd::A, b"def", 5),
        Err(UnixMsgSendError::WouldBlock));
    assert_eq!(pair.recv(UnixEnd::B, 8).unwrap(), b"abc");
    assert_eq!(pair.send_bounded(UnixEnd::A, b"def", 5), Ok(3));
    assert_eq!(pair.recv(UnixEnd::B, 8).unwrap(), b"def");
    assert_eq!(pair.send_bounded(UnixEnd::A, b"123456", 5),
        Err(UnixMsgSendError::MessageTooLarge));
    assert!(pair.recv(UnixEnd::B, 8).is_none());
}

#[test]
fn seqpacket_capacity_is_atomic() {
    let _serial = test_guard();
    atomic_pair_capacity(UnixMsgKind::SeqPacket);
}

#[test]
fn socketpair_datagram_capacity_is_atomic() {
    let _serial = test_guard();
    atomic_pair_capacity(UnixMsgKind::Datagram);
}

fn datagram(payload: &[u8]) -> UnixDgram {
    UnixDgram { payload: payload.to_vec(), creds: (1, 2, 3), fds: alloc::vec::Vec::new() }
}

#[test]
fn pathname_datagram_capacity_is_atomic_and_accounted() {
    let _serial = test_guard();
    let queue = UnixDgramQueue::new();

    assert_eq!(queue.try_push_from_with_rights_bounded(datagram(b"abc"), None,
        GcRights::from_files(alloc::vec::Vec::new()), 5), Ok(()));
    assert_eq!(queue.queued_bytes(), 3);
    assert_eq!(queue.try_push_from_with_rights_bounded(datagram(b"def"), None,
        GcRights::from_files(alloc::vec::Vec::new()), 5), Err(crate::NetError::Eagain));
    assert_eq!(queue.queued_bytes(), 3);
    assert_eq!(queue.pop().unwrap().payload, b"abc");
    assert_eq!(queue.queued_bytes(), 0);
    assert_eq!(queue.try_push_from_with_rights_bounded(datagram(b"def"), None,
        GcRights::from_files(alloc::vec::Vec::new()), 5), Ok(()));
    assert_eq!(queue.pop().unwrap().payload, b"def");
    assert_eq!(queue.try_push_from_with_rights_bounded(datagram(b"123456"), None,
        GcRights::from_files(alloc::vec::Vec::new()), 5), Err(crate::NetError::Emsgsize));
}

#[test]
fn datagram_shutdown_transition_has_one_generation() {
    let _serial = test_guard();
    let pair = UnixMsgPair::new_datagram();
    let pair_generation = pair.shutdown_generation(UnixEnd::B);
    pair.shutdown_reader(UnixEnd::B);
    assert_eq!(pair.shutdown_generation(UnixEnd::B), pair_generation.wrapping_add(1));
    pair.shutdown_reader(UnixEnd::B);
    assert_eq!(pair.shutdown_generation(UnixEnd::B), pair_generation.wrapping_add(1));

    let queue = UnixDgramQueue::new();
    let queue_generation = queue.shutdown_generation();
    queue.shutdown_reader();
    assert_eq!(queue.shutdown_generation(), queue_generation.wrapping_add(1));
    queue.shutdown_reader();
    assert_eq!(queue.shutdown_generation(), queue_generation.wrapping_add(1));
}
