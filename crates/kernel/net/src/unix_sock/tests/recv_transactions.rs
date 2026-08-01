use super::*;

struct NullOps;
impl vfs::FileOps for NullOps {
    fn read(&self, _i: &vfs::inode::Inode, _o: u64, b: &mut [u8]) -> vfs::KResult<usize> { Ok(b.len()) }
    fn write(&self, _i: &vfs::inode::Inode, _o: u64, b: &[u8]) -> vfs::KResult<usize> { Ok(b.len()) }
}

fn anon_file() -> alloc::sync::Arc<vfs::File> {
    let ino = vfs::InodeBuilder::new(0xB816, vfs::mk_mode(vfs::FileType::Socket, 0o600),
        vfs::default_inode_ops(), alloc::sync::Arc::new(NullOps)).build();
    let d = vfs::Dentry::new(None, "rx".into(), alloc::sync::Arc::clone(&ino));
    vfs::File::new_at(ino, d, vfs::OpenFlags::O_RDWR, 0, vfs::FileCred::root())
}

#[test]
fn stream_callback_error_rolls_back_payload_and_rights() {
    let _serial = test_guard();
    let pair = UnixPair::new();
    let file = anon_file();
    pair.write_with_fds(UnixEnd::A, b"stream", alloc::vec![file.clone()]).unwrap();
    let failed = pair.read_stream_with(UnixEnd::B, 64, |data, rights, _| {
        assert_eq!(data, b"stream");
        assert_eq!(rights, 1);
        Err::<((), usize), _>(7u8)
    });
    assert!(matches!(failed, Err(7)));
    let (data, files, _) = pair.read_stream(UnixEnd::B, 64);
    assert_eq!(data, b"stream");
    assert_eq!(files.len(), 1);
    assert!(alloc::sync::Arc::ptr_eq(&files[0], &file));
}

#[test]
fn stream_peek_clones_rights_without_consuming_queue() {
    let _serial = test_guard();
    let pair = UnixPair::new();
    let file = anon_file();
    pair.write_with_fds(UnixEnd::A, b"peek", alloc::vec![file.clone()]).unwrap();
    let (_, peeked, _) = pair.read_stream_with_opts(UnixEnd::B, 64, true, |data, rights, _| {
        assert_eq!(data, b"peek");
        assert_eq!(rights, 1);
        Ok::<_, ()>((data.len(), data.len()))
    }).unwrap().unwrap();
    assert_eq!(peeked.len(), 1);
    assert!(alloc::sync::Arc::ptr_eq(&peeked[0], &file));
    let (data, consumed, _) = pair.read_stream(UnixEnd::B, 64);
    assert_eq!(data, b"peek");
    assert_eq!(consumed.len(), 1);
}

#[test]
fn stream_partial_copy_commits_only_copied_prefix() {
    let _serial = test_guard();
    let pair = UnixPair::new();
    pair.write(UnixEnd::A, b"transaction").unwrap();
    let copied = pair.read_stream_with(UnixEnd::B, 64, |data, _, _| {
        Ok::<_, ()>((data[..4].to_vec(), 4))
    }).unwrap().unwrap().0;
    assert_eq!(copied, b"tran");
    assert_eq!(pair.read(UnixEnd::B, 64), b"saction");
}

#[test]
fn stream_peek_offset_reads_waitall_suffix_without_consuming() {
    let _serial = test_guard();
    let pair = UnixPair::new();
    pair.write(UnixEnd::A, b"abcdef").unwrap();
    let first = pair.read_stream_with_offset(UnixEnd::B, 3, true, 0, false, None, false,
        |data, _, _| Ok::<_, ()>((data.to_vec(), 0))).unwrap().unwrap().0;
    let second = pair.read_stream_with_offset(UnixEnd::B, 3, true, 3, false, None, false,
        |data, _, _| Ok::<_, ()>((data.to_vec(), 0))).unwrap().unwrap().0;
    assert_eq!(first, b"abc");
    assert_eq!(second, b"def");
    assert_eq!(pair.read(UnixEnd::B, 6), b"abcdef");
}

#[test]
fn msgpair_callback_error_consumes_record() {
    let _serial = test_guard();
    let pair = UnixMsgPair::new();
    pair.send(UnixEnd::A, b"first").unwrap();
    pair.send(UnixEnd::A, b"second").unwrap();
    let failed = pair.recv_msg_with(UnixEnd::B, 64, false, |data, _, _, _| {
        assert_eq!(data, b"first");
        Err::<(), _>(9u8)
    });
    assert!(matches!(failed, Err(9)));
    assert_eq!(pair.recv(UnixEnd::B, 64).unwrap(), b"second");
}

#[test]
fn msgpair_peek_error_preserves_record() {
    let _serial = test_guard();
    let pair = UnixMsgPair::new_datagram();
    pair.send(UnixEnd::A, b"peek").unwrap();
    assert!(matches!(pair.recv_msg_with(UnixEnd::B, 64, true, |_, _, _, _| Err::<(), _>(3u8)), Err(3)));
    assert_eq!(pair.recv(UnixEnd::B, 64).unwrap(), b"peek");
}

#[test]
fn dgram_record_keeps_rights_and_sender_in_one_queue_entry() {
    let _serial = test_guard();
    let queue = UnixDgramQueue::new();
    let file = anon_file();
    let sender = UnixAddr::from_sockaddr_path(b"\0sender".to_vec());
    let msg = UnixDgram { payload: b"record".to_vec(), creds: crate::unix_sock::MsgCred::from_ids((1, 2, 3)), fds: alloc::vec::Vec::new() };
    queue.try_push_from_with_rights(msg, Some(sender.clone()), GcRights::from_files(alloc::vec![file.clone()])).unwrap();
    assert!(matches!(queue.recv_with(true, |msg, source, rights| {
        assert_eq!(msg.payload, b"record");
        assert_eq!(source.map(|addr| addr.display.as_slice()), Some(sender.display.as_slice()));
        assert_eq!(rights, 1);
        Err::<(), _>(4u8)
    }), Err(4)));
    let (_, msg, source) = queue.recv_with(false, |_, _, rights| Ok::<_, ()>(rights)).unwrap().unwrap();
    assert_eq!(source.map(|addr| addr.display), Some(sender.display));
    assert_eq!(msg.fds.len(), 1);
    assert!(alloc::sync::Arc::ptr_eq(&msg.fds[0], &file));
    assert!(queue.pop().is_none());
}


#[test]
fn dgram_peek_returns_rights_without_consuming_record() {
    let _serial = test_guard();
    let queue = UnixDgramQueue::new();
    let file = anon_file();
    let msg = UnixDgram { payload: b"peek".to_vec(), creds: crate::unix_sock::MsgCred::from_ids((1, 2, 3)), fds: alloc::vec![file.clone()] };
    queue.try_push(msg).unwrap();
    let (_, peeked, _) = queue.recv_with(true, |_, _, rights| Ok::<_, ()>(rights)).unwrap().unwrap();
    assert_eq!(peeked.fds.len(), 1);
    assert!(alloc::sync::Arc::ptr_eq(&peeked.fds[0], &file));
    let (_, consumed, _) = queue.recv_with(false, |_, _, rights| Ok::<_, ()>(rights)).unwrap().unwrap();
    assert_eq!(consumed.fds.len(), 1);
}

// --- receive-loop continuation (Linux `unix_stream_read_generic`) ---

#[test]
fn a_receive_without_waitall_never_asks_for_more() {
    use crate::unix_sock::stream_recv_continues;
    assert!(!stream_recv_continues(false, false, 4, 64, false));
    assert!(!stream_recv_continues(false, true, 4, 64, false));
}

#[test]
fn waitall_keeps_gluing_until_the_buffer_fills_or_a_boundary_ends_the_run() {
    use crate::unix_sock::stream_recv_continues;
    assert!(stream_recv_continues(true, false, 4, 64, false));
    assert!(!stream_recv_continues(true, false, 64, 64, false), "the buffer is full");
    assert!(!stream_recv_continues(true, false, 4, 64, true), "a control boundary ended the run");
    assert!(stream_recv_continues(true, false, 0, 64, false), "nothing copied yet: still waiting");
}

#[test]
fn a_peek_that_copied_something_never_waits_for_more() {
    use crate::unix_sock::stream_recv_continues;
    // A peeking receive walks off the end of the queue and returns what it has;
    // it does not sleep for a writer the way a consuming MSG_WAITALL does.
    assert!(!stream_recv_continues(true, true, 4, 64, false));
    assert!(stream_recv_continues(true, true, 0, 64, false),
        "a peek that copied nothing still waits for its first bytes");
}
