use super::*;

use alloc::sync::Arc;

fn socket_file(kind: crate::sock::SockKind, receiver: &GcNode)
    -> (Arc<vfs::File>, Arc<crate::sock::InetSocket>)
{
    let socket = Arc::new(crate::sock::InetSocket::new_unix());
    *socket.kind.lock() = kind;
    let inode = crate::sock::make_inet_socket_inode(socket.clone());
    let dentry = vfs::Dentry::new(None, "socket".into(), inode.clone());
    let file = vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR);
    register_file(&file, receiver);
    (file, socket)
}

fn self_cycle() -> (Arc<vfs::File>, alloc::sync::Weak<vfs::File>) {
    let pair = UnixPair::new();
    let (file, _) = socket_file(crate::sock::SockKind::Unix(pair.clone(), UnixEnd::A),
        &pair.gc_node(UnixEnd::A));
    let weak = Arc::downgrade(&file);
    pair.write_with_rights(UnixEnd::B, b"cycle",
        classify_files(alloc::vec![file.clone()])).unwrap();
    (file, weak)
}

fn assert_rooted(weak: &alloc::sync::Weak<vfs::File>) {
    collect_scm_rights();
    assert!(weak.upgrade().is_some(), "queued external edge roots the cycle");
}

#[test]
fn direct_stream_release_collects_discarded_rights() {
    let _guard = test_guard();
    let root = UnixPair::new();
    let (root_file, _) = socket_file(crate::sock::SockKind::Unix(root.clone(), UnixEnd::A),
        &root.gc_node(UnixEnd::A));
    let (cycle_file, weak) = self_cycle();
    root.write_with_rights(UnixEnd::B, b"root",
        classify_files(alloc::vec![cycle_file.clone()])).unwrap();
    drop(cycle_file);
    assert_rooted(&weak);

    root.release_end(UnixEnd::A);

    assert!(weak.upgrade().is_none(), "direct stream release collects without a file-drop hook");
    drop(root_file);
}

#[test]
fn direct_unaccepted_abort_collects_discarded_rights() {
    let _guard = test_guard();
    let pending = UnixPair::new();
    let (root_file, _) = socket_file(crate::sock::SockKind::Unix(pending.clone(), UnixEnd::A),
        &pending.gc_node(UnixEnd::A));
    let (cycle_file, weak) = self_cycle();
    pending.write_with_rights(UnixEnd::B, b"root",
        classify_files(alloc::vec![cycle_file.clone()])).unwrap();
    drop(cycle_file);
    assert_rooted(&weak);

    pending.abort_unaccepted();

    assert!(weak.upgrade().is_none(), "direct unaccepted abort collects without listener fput");
    drop(root_file);
}

fn direct_message_release(kind: UnixMsgKind) {
    let root = match kind {
        UnixMsgKind::Datagram => UnixMsgPair::new_datagram(),
        UnixMsgKind::SeqPacket => UnixMsgPair::new(),
    };
    let (root_file, _) = socket_file(
        crate::sock::SockKind::UnixMsgPair(root.clone(), UnixEnd::A), &root.gc_node(UnixEnd::A));
    let (cycle_file, weak) = self_cycle();
    root.send_with_rights(UnixEnd::B, b"root",
        classify_files(alloc::vec![cycle_file.clone()])).unwrap();
    drop(cycle_file);
    assert_rooted(&weak);

    root.release_end(UnixEnd::A);

    assert!(weak.upgrade().is_none(), "direct message release collects without a file-drop hook");
    drop(root_file);
}

#[test]
fn direct_seqpacket_release_collects_discarded_rights() {
    let _guard = test_guard();
    direct_message_release(UnixMsgKind::SeqPacket);
}

#[test]
fn direct_datagram_pair_release_collects_discarded_rights() {
    let _guard = test_guard();
    direct_message_release(UnixMsgKind::Datagram);
}

#[test]
fn direct_datagram_queue_release_collects_discarded_rights() {
    let _guard = test_guard();
    let root = UnixDgramQueue::new();
    let (root_file, _) = socket_file(crate::sock::SockKind::UnixDgram(root.clone()),
        &root.gc_node());
    let (cycle_file, weak) = self_cycle();
    let message = UnixDgram { payload: b"root".to_vec(), creds: crate::unix_sock::MsgCred::from_ids((0, 0, 0)), fds: alloc::vec![] };
    root.try_push_with_rights(message, classify_files(alloc::vec![cycle_file.clone()])).unwrap();
    drop(cycle_file);
    assert_rooted(&weak);

    root.release();

    assert!(weak.upgrade().is_none(), "direct datagram release collects without a file-drop hook");
    drop(root_file);
}
