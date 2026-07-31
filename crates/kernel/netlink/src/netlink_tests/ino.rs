//! Inode NUMBERS for netlink sockets. The id used to be `Arc::as_ptr(&sock)`,
//! which the heap allocator hands back the moment a socket is freed, so two
//! live netlink sockets could report the same `st_ino` — the key `ss` and
//! `lsof` identify a socket by.

use super::*;

fn a_netlink_socket() -> alloc::sync::Arc<NetlinkSocket> {
    alloc::sync::Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE, &network_namespace::initial()))
}

#[test]
fn two_live_netlink_sockets_get_different_inode_numbers() {
    let a = make_netlink_socket_inode(a_netlink_socket());
    let b = make_netlink_socket_inode(a_netlink_socket());
    assert_ne!(a.ino(), b.ino());
}

/// The case the pointer-derived id could not survive: each socket is dropped
/// before the next is built, so the allocator may place them at one address.
#[test]
fn netlink_numbers_are_not_reused_after_a_socket_is_freed() {
    let mut seen = alloc::collections::BTreeSet::new();
    for _ in 0..256 {
        let ino = make_netlink_socket_inode(a_netlink_socket()).ino();
        assert!(vfs::pseudo_ino::NETLINK.contains(ino), "{ino:#x} left the netlink region");
        assert!(seen.insert(ino), "reused st_ino {ino:#x}");
    }
}

/// Identity still comes from `i_private`, not the number.
#[test]
fn netlink_identity_still_comes_from_the_private_socket() {
    let sock = a_netlink_socket();
    let inode = make_netlink_socket_inode(alloc::sync::Arc::clone(&sock));
    let got = netlink_arc_from_inode(&inode).expect("socket resolves from i_private");
    assert!(alloc::sync::Arc::ptr_eq(&got, &sock));
}
