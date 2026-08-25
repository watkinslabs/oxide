#![allow(unpredictable_function_pointer_comparisons, reason = "the assertion is `the hook I just installed came back`; both sides are the same non-generic fn item in the same codegen unit, so the lint's address-uniqueness caveat cannot apply")]
use core::sync::atomic::Ordering;

use crate::*;

// Module manifest: `creds` owns SO_PASSCRED and per-datagram credentials;
// `uevent` owns raw, cooked, and unicast uevent delivery tests.
mod creds;
mod uevent;
mod user_multicast;

fn namespace_dropped() {}

fn deny_shutdown(_context: security::network::Context) -> security::network::Verdict {
    security::network::Verdict::Deny
}

/// Allocate one isolated hosted namespace fixture. # C: O(1)
pub(crate) fn test_namespace() -> network_namespace::NetworkNamespaceRef {
    // The registry refuses to publish a child before the initial namespace
    // exists, and a hosted test binary has no boot to create it. Whichever
    // test runs first would otherwise decide whether the suite passes.
    let _init = network_namespace::initial();
    network_namespace::install_final_drop_callback(namespace_dropped).unwrap();
    network_namespace::allocate(namespace_identity::initial(
        namespace_identity::NamespaceKind::User)).unwrap()
}

fn socket_file(flags: vfs::OpenFlags) -> (alloc::sync::Weak<NetlinkSocket>, alloc::sync::Arc<vfs::File>) {
    use alloc::sync::Arc;
    let socket = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE, &network_namespace::initial()));
    let weak = Arc::downgrade(&socket);
    let inode = make_netlink_socket_inode(socket);
    let dentry = vfs::Dentry::new(None, "netlink".into(), inode.clone());
    (weak, vfs::File::new(inode, dentry, flags))
}


#[path = "netlink_tests/tests/core.rs"]
mod core_tests;
#[path = "netlink_tests/tests/multicast.rs"]
mod multicast;
#[path = "netlink_tests/ino.rs"]
mod ino;
