use alloc::{sync::Arc, vec};
use super::{capability::Capability, TransportError};
use syscall::nt_compositor::SOCKET_CAP;
use sched::{thread_group::ThreadGroup, pid::PidIdentity};

fn group(pid: u32) -> Arc<ThreadGroup> { Arc::new(ThreadGroup::new(Arc::new(PidIdentity::new(pid)))) }
fn file(socket: Arc<net::sock::InetSocket>) -> Arc<vfs::File> {
    let inode = net::sock::make_inet_socket_inode(socket);
    let dentry = vfs::Dentry::new(None, "compositor".into(), inode.clone());
    vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR)
}
fn endpoint(owner: &Arc<ThreadGroup>) -> Capability {
    let pair = net::UnixPair::new();
    let socket = Arc::new(net::sock::InetSocket::new_unix_pair_end_in(net::net_ns::current_namespace(), pair, net::UnixEnd::A));
    Capability::pin(owner, file(socket)).unwrap()
}

#[test]
fn canonical_group_identity_rejects_reused_pid_and_does_not_pin_process() {
    let owner = group(40000); let cap = endpoint(&owner); let other = group(40000);
    assert!(cap.belongs_to(&owner)); assert!(!cap.belongs_to(&other));
    assert!(cap.owner_live()); owner.group_exit(0); assert!(!cap.owner_live());
    assert_eq!(Arc::strong_count(&owner), 1);
    drop(owner); assert!(cap.group.upgrade().is_none()); assert!(!cap.belongs_to(&other));
}

#[test]
fn file_pin_survives_cloexec_close_and_fd_reuse() {
    let owner = group(40001); let cap = endpoint(&owner); let files = vfs::FdTable::new();
    let fd = files.install_limit(cap._file.clone(), vfs::OpenFlags::O_CLOEXEC, 10).unwrap();
    let pin = Arc::downgrade(&cap._file);
    files.close_on_exec(); assert!(files.get(fd).is_err());
    let unrelated = file(Arc::new(net::sock::InetSocket::new_udp()));
    let reused = files.install_limit(unrelated.clone(), vfs::OpenFlags::empty(), 10).unwrap(); assert_eq!(reused, fd);
    assert!(pin.upgrade().is_some()); assert_eq!(cap.write_bounded(b"retained"), Ok(8));
    assert_eq!(cap.pair.read(net::UnixEnd::B, 8), b"retained");
    drop(cap); assert!(pin.upgrade().is_none()); assert!(Arc::ptr_eq(&files.get(fd).unwrap(), &unrelated));
}

#[test]
fn real_socket_buffer_is_bounded_and_consumer_releases_capacity() {
    let owner = group(40002); let cap = endpoint(&owner); let bytes = vec![0xa5; SOCKET_CAP + 1];
    assert_eq!(cap.write_bounded(&bytes), Ok(SOCKET_CAP));
    assert_eq!(cap.write_bounded(b"x"), Err(TransportError::Full));
    assert_eq!(cap.pair.read(net::UnixEnd::B, 1), vec![0xa5]);
    assert_eq!(cap.write_bounded(b"x"), Ok(1));
    assert_eq!(cap.write_bounded(b"y"), Err(TransportError::Full));
}

#[test]
fn capability_shutdown_terminates_both_directions_and_wakes_reader() {
    let owner = group(40003); let cap = endpoint(&owner);
    let wait = cap.pair.reader_waiters(cap.end);
    // SAFETY: hosted wait registration is local to this test thread; shutdown
    // on this same capability is the production transition that wakes it.
    unsafe { wait.prepare_to_wait_interruptible_with_deadline(0); }
    cap.shutdown();
    // SAFETY: capability_shutdown has already published shutdown and wake;
    // this consumes the registration established by this hosted test thread.
    unsafe { wait.wait(); }
    wait.remove_current();
    assert!(cap.pair.is_eof(cap.end)); assert!(cap.pair.is_eof(net::UnixEnd::B));
    assert_eq!(cap.write_bounded(b"x"), Err(TransportError::Disconnected));
    assert!(cap.pair.write(net::UnixEnd::B, b"x").is_err());
}

#[test]
fn wrong_protocol_and_closed_stream_are_rejected_before_binding() {
    let owner = group(40004);
    assert!(matches!(Capability::pin(&owner, file(Arc::new(net::sock::InetSocket::new_udp()))), Err(TransportError::Invalid)));
    assert!(matches!(Capability::pin(&owner, file(Arc::new(net::sock::InetSocket::new_unix()))), Err(TransportError::Invalid)));
    let cap = endpoint(&owner); cap.shutdown();
    assert!(matches!(Capability::pin(&owner, cap._file.clone()), Err(TransportError::Disconnected)));
}
