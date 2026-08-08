// The one socket-message security boundary, driven as a decision.
//
// These pin what a send and a receive ask for, what they do NOT ask for, and
// which module answers first when both would refuse. The composition is the
// contract: a call site that asks the wrong question, or asks two questions in
// the wrong order, changes an errno a sandboxed program sees.

use alloc::sync::Arc;
use alloc::vec::Vec;

use landlock::abi::RulesetAttr;
use landlock::netcheck::Proto;
use landlock::uapi::{ACCESS_NET_CONNECT_SEND_UDP, ACCESS_NET_CONNECT_TCP};
use landlock::{Domain, Ruleset};
use security::network::{self, Context, Operation, Verdict};

use super::*;

/// Sandbox that handles one right and grants it on no port at all.
/// # C: O(1)
fn sandbox(handled: landlock::uapi::AccessMask) -> Arc<Domain> {
    let rules = Ruleset::new(&RulesetAttr { handled_net: handled, ..Default::default() });
    Domain::merge(None, &rules).unwrap()
}

/// A `sockaddr_in` naming `port`. # C: O(1)
fn addr4(port: u16) -> Vec<u8> {
    let mut bytes = alloc::vec![0u8; landlock::netcheck::SOCKADDR_IN_LEN];
    bytes[..2].copy_from_slice(&landlock::netcheck::AF_INET.to_le_bytes());
    bytes[2..4].copy_from_slice(&port.to_be_bytes());
    bytes
}

fn deny(_context: Context) -> Verdict { Verdict::Deny }

const NS_UDP_ADDR: u64 = 4_100;
const NS_TCP_PLAIN: u64 = 4_101;
const NS_ORDER: u64 = 4_102;
const NS_REGISTRY: u64 = 4_103;
const NS_RECV: u64 = 4_104;
const NS_FASTOPEN: u64 = 4_105;
const NS_UNCONFINED: u64 = 4_106;

fn udp(namespace: u64) -> MsgSock {
    MsgSock { namespace, family: landlock::netcheck::AF_INET, proto: Proto::Udp }
}

fn tcp(namespace: u64) -> MsgSock {
    MsgSock { namespace, family: landlock::netcheck::AF_INET, proto: Proto::Tcp }
}

#[test]
fn a_datagram_send_that_names_a_recipient_asks_for_that_ports_send_right() {
    let domain = sandbox(ACCESS_NET_CONNECT_SEND_UDP);
    let name = addr4(53);
    assert_eq!(sendmsg(Some(&domain), udp(NS_UDP_ADDR), Some(&name), 0), Err(NetError::Eacces));
    // A send that names nothing settles no port and asks for nothing.
    assert_eq!(sendmsg(Some(&domain), udp(NS_UDP_ADDR), None, 0), Ok(()));
    // An unconfined sender is never asked.
    assert_eq!(sendmsg(None, udp(NS_UNCONFINED), Some(&name), 0), Ok(()));
}

#[test]
fn a_plain_stream_send_asks_for_no_port_right_even_when_it_names_an_address() {
    // A stream send rides an association a connect already settled; naming an
    // address on it settles no new port, so the connect right is not asked for
    // again. Asking would deny a send a sandboxed program is allowed to make.
    let domain = sandbox(ACCESS_NET_CONNECT_TCP);
    let name = addr4(443);
    assert_eq!(sendmsg(Some(&domain), tcp(NS_TCP_PLAIN), Some(&name), 0), Ok(()));
    // The same domain refuses the same address when the send opens the
    // connection itself, which is what makes the case above a real exemption
    // rather than an unhandled right.
    assert_eq!(sendmsg(Some(&domain), tcp(NS_FASTOPEN), Some(&name), crate::uapi::MSG_FASTOPEN),
        Err(NetError::Eacces));
    // A connection-opening send that names nothing opens nothing.
    assert_eq!(sendmsg(Some(&domain), tcp(NS_FASTOPEN), None, crate::uapi::MSG_FASTOPEN), Ok(()));
    // The connection-opening flag on a datagram socket is not a connect.
    assert_eq!(sendmsg(Some(&domain), udp(NS_FASTOPEN), Some(&name), crate::uapi::MSG_FASTOPEN),
        Ok(()));
}

#[test]
fn a_family_with_no_port_rules_is_never_parsed_for_one() {
    let domain = sandbox(ACCESS_NET_CONNECT_SEND_UDP);
    // A two-byte name is too short for any internet address; a boundary that
    // reached the classifier for this family would report EINVAL from a policy
    // that has nothing to say about it.
    let stub = alloc::vec![0u8, 0];
    assert_eq!(sendmsg(Some(&domain), other(NS_UNCONFINED, 1), Some(&stub), 0), Ok(()));
}

#[test]
fn the_sandbox_answers_before_the_module_registry() {
    let _ = network::remove_namespace(NS_ORDER);
    assert!(network::install(NS_ORDER, Operation::Send, deny).is_none());
    let domain = sandbox(ACCESS_NET_CONNECT_SEND_UDP);
    let name = addr4(53);
    assert_eq!(sendmsg(Some(&domain), udp(NS_ORDER), Some(&name), 0), Err(NetError::Eacces));
    // Both would refuse; only one was asked, so the registry never counted it.
    assert_eq!(network::counters(NS_ORDER, Operation::Send), Some((0, 0)));
    // With the sandbox satisfied the registry is asked, and counts.
    assert_eq!(sendmsg(Some(&domain), udp(NS_ORDER), None, 0), Err(NetError::Eacces));
    assert_eq!(network::counters(NS_ORDER, Operation::Send), Some((0, 1)));
    assert_eq!(network::remove_namespace(NS_ORDER), 1);
}

#[test]
fn an_unsandboxed_send_still_faces_the_module_registry() {
    let _ = network::remove_namespace(NS_REGISTRY);
    assert!(network::install(NS_REGISTRY, Operation::Send, deny).is_none());
    assert_eq!(sendmsg(None, udp(NS_REGISTRY), None, 0), Err(NetError::Eacces));
    assert_eq!(network::counters(NS_REGISTRY, Operation::Send), Some((0, 1)));
    assert_eq!(network::remove_namespace(NS_REGISTRY), 1);
}

#[test]
fn a_receive_asks_the_module_registry_and_nothing_else() {
    let _ = network::remove_namespace(NS_RECV);
    assert!(network::install(NS_RECV, Operation::Receive, deny).is_none());
    assert_eq!(recvmsg(udp(NS_RECV), 0), Err(NetError::Eacces));
    assert_eq!(network::counters(NS_RECV, Operation::Receive), Some((0, 1)));
    // A send policy is not a receive policy and vice versa.
    assert_eq!(sendmsg(None, udp(NS_RECV), None, 0), Ok(()));
    // The sandbox writes no receive rules: a domain that refuses every port
    // still does not refuse a receive.
    let domain = sandbox(ACCESS_NET_CONNECT_SEND_UDP);
    assert_eq!(sendmsg(Some(&domain), udp(NS_UNCONFINED), Some(&addr4(53)), 0),
        Err(NetError::Eacces));
    assert_eq!(recvmsg(udp(NS_UNCONFINED), 0), Ok(()));
    assert_eq!(network::remove_namespace(NS_RECV), 1);
}

