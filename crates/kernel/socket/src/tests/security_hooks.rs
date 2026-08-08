// The send path's one security hook, driven where it must sit.
//
// `net::socket_security` carries the decision's own coverage; what these pin is
// that the send path REACHES it — for every family, once, and ahead of the
// family validation whose error would otherwise mask a refusal. Deleting the
// call from `send::prepare` turns every test here red.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use landlock::abi::RulesetAttr;
use landlock::uapi::ACCESS_NET_CONNECT_SEND_UDP;
use landlock::{Domain, Ruleset};
use security::network::{self, Context, Operation, Verdict};

use crate::{Error, Message, SendContext, SendFile};

/// The namespace every hosted send target is built in, with its policy cleared
/// and this thread holding the crate's one right to install policy there —
/// which the send path's hook call site checks, so a sibling test that drives a
/// send here without any claim fails rather than corrupting these counters.
/// # C: O(1)
fn fixture() -> (crate::test_support::PolicyControl, network_namespace::NetworkNamespaceRef, u64) {
    let guard = crate::test_support::policy_control();
    let owner = network_namespace::initial();
    (guard, owner, crate::test_support::initial_namespace())
}

fn deny(_context: Context) -> Verdict { Verdict::Deny }

fn task(tid: u32) -> sched::Task {
    sched::Task::new(tid, "send-hook", sched::SchedClass::Normal { weight: 1024 })
}

/// A retained send target over one UDP socket in `namespace`. # C: O(1)
fn udp_target(namespace: &network_namespace::NetworkNamespaceRef) -> SendFile {
    let socket = Arc::new(net::sock::InetSocket::new_udp_in(namespace.clone()));
    let inode = net::sock::make_inet_socket_inode(socket);
    let dentry = vfs::Dentry::new(None, String::from("udp"), inode.clone());
    SendFile::new(vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR))
}

/// A retained send target over one NETLINK socket in `namespace`. # C: O(1)
fn netlink_target(namespace: &network_namespace::NetworkNamespaceRef) -> SendFile {
    let socket = Arc::new(netlink::NetlinkSocket::new(netlink::proto::NETLINK_ROUTE, namespace));
    let inode = netlink::make_netlink_socket_inode(socket);
    let dentry = vfs::Dentry::new(None, String::from("netlink"), inode.clone());
    SendFile::new(vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR))
}

/// A `sockaddr_in` naming `port`. # C: O(1)
fn addr4(port: u16) -> Vec<u8> {
    let mut bytes = alloc::vec![0u8; 16];
    bytes[..2].copy_from_slice(&2u16.to_le_bytes());
    bytes[2..4].copy_from_slice(&port.to_be_bytes());
    bytes
}

fn message(name: Option<Vec<u8>>, len: usize) -> Message {
    Message { requested_len: len, payload: alloc::vec![0u8; len], name, ..Message::default() }
}

#[test]
fn an_internet_send_reaches_the_message_hook() {
    let (_guard, owner, namespace) = fixture();
    assert!(network::install(namespace, Operation::Send, deny).is_none());
    let task = task(701);
    let ctx = SendContext::with_sandbox(&task, None);
    let target = udp_target(&owner);
    assert_eq!(crate::send::prepare(&ctx, &target, &message(None, 4), 0).err(), Some(Error::Eacces));
    assert_eq!(network::counters(namespace, Operation::Send), Some((0, 1)));
    assert_eq!(network::remove_namespace(namespace), 1);
}

#[test]
fn a_netlink_send_reaches_the_same_message_hook() {
    let (_guard, owner, namespace) = fixture();
    assert!(network::install(namespace, Operation::Send, deny).is_none());
    let task = task(702);
    let ctx = SendContext::with_sandbox(&task, None);
    let target = netlink_target(&owner);
    assert_eq!(crate::send::prepare(&ctx, &target, &message(None, 16), 0).err(),
        Some(Error::Eacces));
    assert_eq!(network::remove_namespace(namespace), 1);
}

#[test]
fn the_hook_precedes_every_family_validation_it_could_be_masked_by() {
    let (_guard, owner, namespace) = fixture();
    assert!(network::install(namespace, Operation::Send, deny).is_none());
    let task = task(703);
    let ctx = SendContext::with_sandbox(&task, None);
    let netlink = netlink_target(&owner);
    // A zero-length netlink send is ENODATA and an out-of-band one is
    // EOPNOTSUPP; both are the protocol's answer and both come after.
    assert_eq!(crate::send::prepare(&ctx, &netlink, &message(None, 0), 0).err(),
        Some(Error::Eacces));
    assert_eq!(crate::send::prepare(&ctx, &netlink, &message(None, 16),
        net::uapi::MSG_OOB as u32).err(), Some(Error::Eacces));
    // A malformed destination is EINVAL from the address parse, which the hook
    // also precedes.
    let udp = udp_target(&owner);
    assert_eq!(crate::send::prepare(&ctx, &udp, &message(Some(alloc::vec![0u8]), 4), 0).err(),
        Some(Error::Eacces));
    assert_eq!(network::remove_namespace(namespace), 1);
}

#[test]
fn one_send_asks_the_hook_exactly_once() {
    let (_guard, owner, namespace) = fixture();
    assert!(network::install(namespace, Operation::Send, |_| Verdict::Allow).is_none());
    let task = task(705);
    let ctx = SendContext::with_sandbox(&task, None);
    let target = udp_target(&owner);
    assert!(crate::send::prepare(&ctx, &target, &message(None, 4), 0).is_ok());
    assert_eq!(network::counters(namespace, Operation::Send), Some((1, 0)));
    assert_eq!(network::remove_namespace(namespace), 1);
}

#[test]
fn a_sandboxed_send_is_judged_against_the_snapshot_the_context_retained() {
    let rules = Ruleset::new(&RulesetAttr { handled_net: ACCESS_NET_CONNECT_SEND_UDP,
        ..Default::default() });
    let domain = Domain::merge(None, &rules).unwrap();
    let (_guard, owner, _namespace) = fixture();
    let task = task(704);
    let target = udp_target(&owner);
    // The sandbox travels in the context, not in the running task: a send
    // built with no snapshot is unconfined even though the domain exists.
    let unconfined = SendContext::with_sandbox(&task, None);
    assert!(crate::send::prepare(&unconfined, &target, &message(Some(addr4(53)), 4), 0).is_ok());
    let confined = SendContext::with_sandbox(&task, Some(domain));
    assert_eq!(crate::send::prepare(&confined, &target, &message(Some(addr4(53)), 4), 0).err(),
        Some(Error::Eacces));
    // No named recipient, no port settled, nothing refused.
    assert!(crate::send::prepare(&confined, &target, &message(None, 4), 0).is_ok());
}
