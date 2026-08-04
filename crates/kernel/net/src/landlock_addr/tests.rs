// Enforcement, not storage. Each test drives the same decision the socket
// layer calls, so a right that is handled but consulted by nothing fails here.

use super::*;
use alloc::vec::Vec;

use landlock::abi::RulesetAttr;
use landlock::uapi::{ACCESS_FS_RESOLVE_UNIX, ACCESS_NET_CONNECT_SEND_UDP,
                     ACCESS_NET_CONNECT_TCP, ACCESS_NET_BIND_TCP, ACCESS_NET_BIND_UDP};
use landlock::uapi::AccessMask;
use landlock::Ruleset;
use vfs::{default_file_ops, default_inode_ops, mk_mode, Dentry, FileType, InodeBuilder,
          InodeRef, VfsPath};

const AF_INET_WIRE:  u16 = 2;
const AF_INET6_WIRE: u16 = 10;
const SOCKADDR_IN_WIRE_LEN: usize = 16;
const NO_RULE_FLAGS: u32 = 0;

/// `sockaddr_in` naming `port`, in the shape the check parses. # C: O(1)
fn sockaddr_in(port: u16) -> Vec<u8> {
    let mut bytes = alloc::vec![0u8; SOCKADDR_IN_WIRE_LEN];
    bytes[..2].copy_from_slice(&AF_INET_WIRE.to_le_bytes());
    bytes[2..4].copy_from_slice(&port.to_be_bytes());
    bytes[4] = 127; bytes[7] = 1;
    bytes
}

/// Unspecified-family address, the "drop the association" shape. # C: O(1)
fn sockaddr_unspec() -> Vec<u8> { alloc::vec![0u8; SOCKADDR_IN_WIRE_LEN] }

fn net_domain(handled_net: AccessMask, ports: &[(u16, AccessMask)]) -> Arc<Domain> {
    let rs = Ruleset::new(&RulesetAttr { handled_net, ..Default::default() });
    for (port, allowed) in ports {
        rs.add_net(*port as u64, *allowed, NO_RULE_FLAGS).expect("port rule");
    }
    Domain::merge(None, &rs).expect("layer budget")
}

// --- port rights on a datagram send -----------------------------------------

#[test]
fn a_udp_send_to_an_explicit_recipient_asks_for_the_connect_send_right() {
    let d = net_domain(ACCESS_NET_CONNECT_SEND_UDP, &[(53, ACCESS_NET_CONNECT_SEND_UDP)]);
    assert_eq!(addr_verdict(Some(&d), Proto::Udp, Op::Send, &sockaddr_in(53), AF_INET_WIRE),
               Ok(()));
    assert_eq!(addr_verdict(Some(&d), Proto::Udp, Op::Send, &sockaddr_in(54), AF_INET_WIRE),
               Err(NetError::Eacces));
}

#[test]
fn an_implicit_udp_bind_asks_for_the_bind_zero_right() {
    let d = net_domain(ACCESS_NET_BIND_UDP, &[(0, ACCESS_NET_BIND_UDP)]);
    assert_eq!(addr_verdict(Some(&d), Proto::Udp, Op::Bind, &sockaddr_in(0), AF_INET_WIRE),
               Ok(()));
    let denied = net_domain(ACCESS_NET_BIND_UDP, &[(53, ACCESS_NET_BIND_UDP)]);
    assert_eq!(addr_verdict(Some(&denied), Proto::Udp, Op::Bind, &sockaddr_in(0), AF_INET_WIRE),
               Err(NetError::Eacces));
}

#[test]
fn udp_autobind_checks_the_bind_right_before_allocating_a_port() {
    let source = include_str!("../sock/lifecycle.rs");
    let unbound = source.find("if let Some(port) = *local_port { return Ok(port); }")
        .expect("the lifecycle checks whether allocation is needed");
    let check = source.find("crate::landlock_addr::check_autobind_udp(self)?;")
        .expect("autobind asks for the UDP bind right");
    let allocate = source.find("alloc_ephemeral_udp4_owned(")
        .expect("the lifecycle allocates an ephemeral UDP endpoint");
    assert!(unbound < check && check < allocate);
}

#[test]
fn a_send_on_a_tcp_socket_asks_for_the_tcp_connect_right() {
    // The UDP right does not stand in for the TCP one: a policy that named
    // only UDP ports must not confine a TCP send, and vice versa.
    let udp_only = net_domain(ACCESS_NET_CONNECT_SEND_UDP,
                              &[(53, ACCESS_NET_CONNECT_SEND_UDP)]);
    assert_eq!(addr_verdict(Some(&udp_only), Proto::Tcp, Op::Send, &sockaddr_in(54),
                            AF_INET_WIRE), Ok(()));
    let tcp = net_domain(ACCESS_NET_CONNECT_TCP, &[(443, ACCESS_NET_CONNECT_TCP)]);
    assert_eq!(addr_verdict(Some(&tcp), Proto::Tcp, Op::Send, &sockaddr_in(443), AF_INET_WIRE),
               Ok(()));
    assert_eq!(addr_verdict(Some(&tcp), Proto::Tcp, Op::Send, &sockaddr_in(80), AF_INET_WIRE),
               Err(NetError::Eacces));
}

#[test]
fn a_transport_with_no_port_rights_is_never_filtered_on_send() {
    let d = net_domain(ACCESS_NET_CONNECT_SEND_UDP, &[]);
    assert_eq!(addr_verdict(Some(&d), Proto::Other, Op::Send, &sockaddr_in(53), AF_INET_WIRE),
               Ok(()));
}

#[test]
fn an_unconfined_sender_is_never_checked() {
    assert_eq!(addr_verdict(None, Proto::Udp, Op::Send, &sockaddr_in(53), AF_INET_WIRE), Ok(()));
}

#[test]
fn a_domain_that_filters_no_port_right_does_not_parse_the_send_address() {
    // A sandbox that names only filesystem rights must not turn a send into an
    // argument error the network stack would never have produced.
    let rs = Ruleset::new(&RulesetAttr { handled_fs: ACCESS_FS_RESOLVE_UNIX,
                                         ..Default::default() });
    let d = Domain::merge(None, &rs).expect("layer budget");
    assert_eq!(addr_verdict(Some(&d), Proto::Udp, Op::Send, &[0u8], AF_INET_WIRE), Ok(()));
    // Same for a domain that handles a port right this operation never asks for.
    let bind_only = net_domain(ACCESS_NET_BIND_TCP, &[]);
    assert_eq!(addr_verdict(Some(&bind_only), Proto::Udp, Op::Send, &[0u8], AF_INET_WIRE),
               Ok(()));
}

#[test]
fn a_send_address_too_short_to_hold_a_family_is_an_argument_error() {
    let d = net_domain(ACCESS_NET_CONNECT_SEND_UDP, &[]);
    assert_eq!(addr_verdict(Some(&d), Proto::Udp, Op::Send, &[0u8], AF_INET_WIRE),
               Err(NetError::Einval));
}

#[test]
fn a_send_to_an_unspecified_family_splits_by_socket_family() {
    // An IPv4 socket reads the unspecified address as a real destination, so
    // its port is checked; an IPv6 socket's family can change under the check,
    // so it is refused outright.
    let d = net_domain(ACCESS_NET_CONNECT_SEND_UDP, &[]);
    assert_eq!(addr_verdict(Some(&d), Proto::Udp, Op::Send, &sockaddr_unspec(), AF_INET_WIRE),
               Err(NetError::Eacces));
    assert_eq!(addr_verdict(Some(&d), Proto::Udp, Op::Send, &sockaddr_unspec(), AF_INET6_WIRE),
               Err(NetError::Eacces));
    // Dropping the association through connect stays allowed either way.
    assert_eq!(addr_verdict(Some(&d), Proto::Udp, Op::Connect, &sockaddr_unspec(),
                            AF_INET6_WIRE), Ok(()));
}

// --- pathname AF_UNIX resolve ------------------------------------------------

fn dir_inode(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755),
                      default_inode_ops(), default_file_ops()).build()
}

fn sock_inode(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Socket, 0o755),
                      default_inode_ops(), default_file_ops()).build()
}

fn path_of(dentry: Arc<Dentry>) -> VfsPath {
    let inode = dentry.inode().expect("test dentry inode");
    VfsPath { mnt_id: 1, dentry, inode, last_component: None }
}

fn resolve_domain(parent: Option<&Arc<Domain>>, rules: &[InodeRef]) -> Arc<Domain> {
    let rs = Ruleset::new(&RulesetAttr { handled_fs: ACCESS_FS_RESOLVE_UNIX,
                                         ..Default::default() });
    for inode in rules {
        rs.add_fs(inode.clone(), true, ACCESS_FS_RESOLVE_UNIX, NO_RULE_FLAGS).expect("fs rule");
    }
    Domain::merge(parent, &rs).expect("layer budget")
}

/// Bind a pathname listener at a private inode and hand back its address and
/// the socket's own path. # C: O(log N_bindings)
fn published(ino: u64, owner: Option<Arc<Domain>>) -> (crate::UnixAddr, VfsPath, Arc<Dentry>) {
    let root = Dentry::new_root(dir_inode(ino));
    let run  = vfs::d_add(&root, "run", dir_inode(ino + 1));
    let node = vfs::d_add(&run, "sock", sock_inode(ino + 2));
    let inode = node.inode().expect("socket inode");
    let addr = crate::UnixAddr::from_inode_bytes(alloc::vec![b'/', b's'], &inode);
    let listener = crate::sock::UNIX_REGISTRY.bind_addr(addr.clone()).expect("free address");
    listener.set_owner_domain(owner);
    (addr, path_of(node), run)
}

#[test]
fn a_pathname_socket_published_outside_the_domain_needs_a_hierarchy_rule() {
    let (addr, path, run) = published(1000, None);
    let client = resolve_domain(None, &[]);
    assert_eq!(unix_resolve_verdict(Some(&client), &path, &addr), Err(NetError::Eacces));
    // A rule on a directory above the socket admits it.
    let allowed = resolve_domain(None, &[run.inode().unwrap()]);
    assert_eq!(unix_resolve_verdict(Some(&allowed), &path, &addr), Ok(()));
}

#[test]
fn a_pathname_socket_published_inside_the_domain_stays_reachable() {
    let client = resolve_domain(None, &[]);
    let (addr, path, _run) = published(1010, Some(client.clone()));
    assert_eq!(unix_resolve_verdict(Some(&client), &path, &addr), Ok(()));
    // A server published deeper than the client is still inside it.
    let (deep_addr, deep_path, _) = published(1020, Some(resolve_domain(Some(&client), &[])));
    assert_eq!(unix_resolve_verdict(Some(&client), &deep_path, &deep_addr), Ok(()));
    // The nested client cannot reach back out to the outer domain's server.
    let nested = resolve_domain(Some(&client), &[]);
    assert_eq!(unix_resolve_verdict(Some(&nested), &path, &addr), Err(NetError::Eacces));
}

#[test]
fn an_unconfined_client_resolves_any_pathname_socket() {
    let (addr, path, _run) = published(1030, Some(resolve_domain(None, &[])));
    assert_eq!(unix_resolve_verdict(None, &path, &addr), Ok(()));
}

#[test]
fn an_address_nobody_has_bound_is_not_a_denial() {
    // The operation fails on its own terms; reporting a sandbox denial for a
    // name with no server would leak which names are in use.
    let root = Dentry::new_root(dir_inode(1040));
    let node = vfs::d_add(&root, "sock", sock_inode(1041));
    let addr = crate::UnixAddr::from_inode_bytes(alloc::vec![b'/', b's'],
                                                 &node.inode().unwrap());
    assert!(pathname_unix_owner(&addr).is_none());
    let client = resolve_domain(None, &[]);
    assert_eq!(unix_resolve_verdict(Some(&client), &path_of(node), &addr), Ok(()));
}

#[test]
fn an_abstract_address_never_reaches_the_hierarchy_check() {
    // Abstract names carry no filesystem object to anchor a rule on and are
    // governed by the scope flag instead.
    let addr = crate::UnixAddr::from_sockaddr_path(alloc::vec![0u8, b'l', b'l']);
    assert!(pathname_unix_owner(&addr).is_none());
    let root = Dentry::new_root(dir_inode(1050));
    let client = resolve_domain(None, &[]);
    assert_eq!(unix_resolve_verdict(Some(&client), &path_of(root), &addr), Ok(()));
}

#[test]
fn a_datagram_queue_publisher_is_found_like_a_listener() {
    let root = Dentry::new_root(dir_inode(1060));
    let node = vfs::d_add(&root, "sock", sock_inode(1061));
    let addr = crate::UnixAddr::from_inode_bytes(alloc::vec![b'/', b's'],
                                                 &node.inode().unwrap());
    let queue = crate::UnixDgramQueue::new();
    let owner = resolve_domain(None, &[]);
    queue.set_owner_domain(Some(owner.clone()));
    crate::sock::UNIX_REGISTRY.dgram_bind_addr(addr.clone(), queue).expect("free address");
    assert_eq!(unix_resolve_verdict(Some(&owner), &path_of(node.clone()), &addr), Ok(()));
    assert_eq!(unix_resolve_verdict(Some(&resolve_domain(None, &[])), &path_of(node), &addr),
               Err(NetError::Eacces));
}
