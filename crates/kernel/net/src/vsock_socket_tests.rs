use super::*;
use crate::vsock::{ConnKey, VsockState};

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn owner(raw: u32) -> vsock::VsockOwner {
    vsock::VsockOwner::from_raw(raw).expect("test owner is nonzero")
}

fn namespace() -> network_namespace::NetworkNamespaceRef {
    crate::net_ns::install_final_drop_pending_notifier().expect("install notifier");
    network_namespace::allocate(0).expect("allocate namespace")
}

fn file(sock: Arc<VsockSocket>) -> Arc<vfs::File> {
    let inode = make_vsock_socket_inode(sock);
    let dentry = vfs::Dentry::new(None, alloc::string::String::from("socket"), inode.clone());
    vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR)
}

fn connection(raw_owner: u32, port: u32) -> (ConnKey, Arc<VsockConn>) {
    let owner = owner(raw_owner);
    let key = ConnKey { owner, local_cid: 3, local_port: port, peer_cid: 2, peer_port: 1024 };
    vsock::TABLE.remove(key);
    let conn = Arc::new(VsockConn::new(owner, key.local_cid, key.local_port,
        key.peer_cid, key.peer_port, VsockState::Connected));
    assert!(vsock::TABLE.insert(conn.clone()));
    (key, conn)
}

#[test]
fn socket_retains_concrete_namespace_owner() {
    let namespace = namespace();
    let id = namespace.id();
    let sock = VsockSocket::new_type_in(crate::socket_args::SOCK_STREAM, namespace.clone());
    drop(namespace);
    assert!(network_namespace::lookup(id).is_some(), "socket pins namespace lifetime");
    drop(sock);
    assert!(network_namespace::lookup(id).is_none(), "last socket drop releases namespace");
}

#[test]
fn accepted_socket_clones_listener_namespace_owner() {
    let namespace = namespace();
    let listener = VsockSocket::new_type_in(crate::socket_args::SOCK_STREAM, namespace.clone());
    let accepted = VsockSocket::new_accepted(&listener);
    assert!(Arc::ptr_eq(&listener.net_namespace, &accepted.net_namespace));
    drop(namespace); drop(listener);
    assert!(network_namespace::lookup(accepted.net_namespace.id()).is_some());
}

#[test]
fn drop_listener_removes_vsock_listener() {
    let _guard = SERIAL.lock().unwrap();
    let owner = Some(owner(0x0a00_0001));
    let port = 61_001;
    let _ = vsock::TABLE.remove_listener(owner, port);
    let listener = vsock::TABLE.add_listener(owner, port).expect("listener registration");
    let (key, conn) = connection(owner.unwrap().raw(), port);
    vsock::TABLE.queue_accept(owner.unwrap(), port, key);
    assert!(vsock::TABLE.is_listening(owner.unwrap(), port));
    assert!(vsock::TABLE.pop_accept_peek(owner, port));

    let sock = Arc::new(VsockSocket::new());
    *sock.kind.lock() = VsockKind::Listener(listener);
    drop(sock);

    assert!(!vsock::TABLE.is_listening(owner.unwrap(), port));
    assert_eq!(*conn.st.lock(), VsockState::Closed);
    assert!(vsock::TABLE.find(key).is_none());
    assert!(!vsock::TABLE.remove_listener(owner, port));
}

#[test]
fn drop_connected_socket_closes_connection_record() {
    let _guard = SERIAL.lock().unwrap();
    let (key, conn) = connection(0x0a00_0002, 61_002);
    let sock = Arc::new(VsockSocket::new());
    *sock.kind.lock() = VsockKind::Conn(conn.clone());
    drop(sock);
    assert_eq!(*conn.st.lock(), VsockState::Closed);
    assert!(vsock::TABLE.find(key).is_none());
}

#[test]
fn final_file_release_removes_listener_before_socket_object_drop() {
    let _guard = SERIAL.lock().unwrap();
    let owner = Some(owner(0x0a00_0003));
    let port = 61_003;
    let _ = vsock::TABLE.remove_listener(owner, port);
    let listener = vsock::TABLE.add_listener(owner, port).expect("listener registration");
    let sock = Arc::new(VsockSocket::new());
    *sock.kind.lock() = VsockKind::Listener(listener);
    let fdt = vfs::FdTable::new();
    let fd = fdt.alloc(file(sock.clone())).unwrap();
    let dup = fdt.dup(fd).unwrap();

    fdt.close(fd).unwrap();
    assert!(vsock::TABLE.is_listening(owner.unwrap(), port));
    fdt.close(dup).unwrap();

    assert!(!vsock::TABLE.is_listening(owner.unwrap(), port));
    sock.release_file();
    assert!(!vsock::TABLE.remove_listener(owner, port));
}

#[test]
fn final_file_release_closes_connection_before_socket_object_drop() {
    let _guard = SERIAL.lock().unwrap();
    let (key, conn) = connection(0x0a00_0004, 61_004);
    let sock = Arc::new(VsockSocket::new());
    *sock.kind.lock() = VsockKind::Conn(conn.clone());
    let fdt = vfs::FdTable::new();
    let fd = fdt.alloc(file(sock.clone())).unwrap();
    let dup = fdt.dup(fd).unwrap();

    fdt.close(fd).unwrap();
    assert_eq!(*conn.st.lock(), VsockState::Connected);
    assert!(vsock::TABLE.find(key).is_some());
    fdt.close(dup).unwrap();

    assert_eq!(*conn.st.lock(), VsockState::Closed);
    assert!(vsock::TABLE.find(key).is_none());
    sock.release_file();
    assert_eq!(*conn.st.lock(), VsockState::Closed);
}

#[test]
fn failed_fd_install_releases_unpublished_connection() {
    let _guard = SERIAL.lock().unwrap();
    let (key, conn) = connection(0x0a00_0005, 61_005);
    let sock = Arc::new(VsockSocket::new());
    *sock.kind.lock() = VsockKind::Conn(conn.clone());
    let fdt = vfs::FdTable::new();

    assert_eq!(fdt.install_limit(file(sock.clone()), vfs::OpenFlags::empty(), 0),
        Err(vfs::VfsError::Emfile));

    assert_eq!(*conn.st.lock(), VsockState::Closed);
    assert!(vsock::TABLE.find(key).is_none());
    sock.release_file();
}

#[test]
fn pending_recv_error_overwrites_with_latest_positive_errno() {
    let sock = VsockSocket::new();
    assert_eq!(sock.take_pending_recv_error(), 0);
    assert!(!sock.set_pending_recv_error(0));
    assert!(!sock.set_pending_recv_error(-5));
    assert!(sock.set_pending_recv_error(111));
    assert!(sock.set_pending_recv_error(104));
    assert_eq!(sock.take_pending_recv_error(), 104);
    assert_eq!(sock.take_pending_recv_error(), 0);
}
