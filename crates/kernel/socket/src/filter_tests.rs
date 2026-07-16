use alloc::sync::Arc;

use super::{FilterError, FilterFile};
use net::bpf_filter::{FilterKind, FilterProgram};

fn file(inode: vfs::InodeRef) -> Arc<vfs::File> {
    let dentry = vfs::Dentry::new(None, alloc::string::String::from("filter"), inode.clone());
    vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR)
}

fn inet_file(socket: Arc<net::sock::InetSocket>) -> Arc<vfs::File> {
    file(net::sock::make_inet_socket_inode(socket))
}

fn netlink_file(socket: Arc<netlink::NetlinkSocket>) -> Arc<vfs::File> {
    file(netlink::make_netlink_socket_inode(socket))
}

fn vsock_file(socket: Arc<net::vsock_socket::VsockSocket>) -> Arc<vfs::File> {
    file(net::vsock_socket::make_vsock_socket_inode(socket))
}

fn program(byte: u8) -> FilterProgram {
    FilterProgram { kind: FilterKind::Ebpf, insns: alloc::vec![byte] }
}

#[test]
fn common_target_mutates_unix_netlink_and_vsock_filter_state() {
    let unix = Arc::new(net::sock::InetSocket::new_unix());
    let netlink = Arc::new(netlink::NetlinkSocket::new(netlink::proto::NETLINK_ROUTE,
        &network_namespace::initial()));
    let vsock = Arc::new(net::vsock_socket::VsockSocket::new());
    let targets = [
        (FilterFile::from_file(inet_file(unix.clone())).unwrap(), unix.bpf_filter.clone()),
        (FilterFile::from_file(netlink_file(netlink.clone())).unwrap(), netlink.bpf_filter.clone()),
        (FilterFile::from_file(vsock_file(vsock.clone())).unwrap(), vsock.bpf_filter.clone()),
    ];

    for (target, filter) in targets {
        assert_eq!(target.detach(), Err(FilterError::NotAttached));
        target.attach(program(1)).unwrap();
        assert!(filter.is_attached());
        target.set_lock(true).unwrap();
        assert!(target.is_locked());
        assert_eq!(target.ensure_mutable(), Err(FilterError::Locked));
        assert_eq!(target.detach(), Err(FilterError::Locked));
        assert_eq!(target.attach(program(2)), Err(FilterError::Locked));
        assert_eq!(target.set_lock(false), Err(FilterError::Locked));
    }
}

#[test]
fn common_target_retains_original_file_across_close_and_reuse() {
    let table = vfs::FdTable::new();
    let original = Arc::new(net::vsock_socket::VsockSocket::new());
    let fd = table.alloc(vsock_file(original.clone())).unwrap();
    let target = FilterFile::from_file(table.get(fd).unwrap()).unwrap();
    table.close(fd).unwrap();
    let replacement = Arc::new(net::vsock_socket::VsockSocket::new());
    assert_eq!(table.alloc(vsock_file(replacement.clone())).unwrap(), fd);

    target.attach(program(1)).unwrap();
    assert!(original.bpf_filter.is_attached());
    assert!(!replacement.bpf_filter.is_attached());
}
