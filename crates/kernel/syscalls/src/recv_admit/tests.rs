// No receive reaches a protocol unadmitted.
//
// The route is only obtainable from the admitting call, so these drive that
// call for every family and every diversion and assert both halves: that a
// refused receive yields an errno and no route at all, and that an admitted one
// lands on the owner the reference sends it to.

use landlock::netcheck::Proto;
use net::socket_security::MsgSock;
use net::uapi::{MSG_ERRQUEUE, MSG_PEEK};
use security::network::{self, Context, Operation, Verdict};
use syscall::errno::Errno;

use super::*;

const NS_DENIED: u64 = 7_300;
const NS_ROUTE: u64 = 7_301;
const NS_ERRQ: u64 = 7_302;
const NS_ONCE: u64 = 7_303;

const AF_INET: u16 = 2;

fn deny(_context: Context) -> Verdict { Verdict::Deny }

fn sock(namespace: u64) -> MsgSock {
    MsgSock { namespace, family: AF_INET, proto: Proto::Udp }
}

const FAMILIES: [RecvFamily; 4] = [
    RecvFamily::Inet { unix: false }, RecvFamily::Inet { unix: true },
    RecvFamily::Netlink, RecvFamily::Vsock,
];

#[test]
fn a_refused_receive_yields_an_errno_and_no_route_for_any_family_or_flag() {
    let _ = network::remove_namespace(NS_DENIED);
    assert!(network::install(NS_DENIED, Operation::Receive, deny).is_none());
    let mut asked = 0u64;
    for family in FAMILIES {
        for flags in [0, MSG_PEEK, MSG_ERRQUEUE] {
            assert_eq!(admit_and_route(sock(NS_DENIED), family, flags),
                Err(-(Errno::Eacces.as_i32() as i64)));
            asked += 1;
        }
    }
    assert_eq!(network::counters(NS_DENIED, Operation::Receive), Some((0, asked)));
    assert_eq!(network::remove_namespace(NS_DENIED), 1);
}

#[test]
fn an_admitted_receive_lands_on_its_protocol_owner() {
    let _ = network::remove_namespace(NS_ROUTE);
    assert_eq!(admit_and_route(sock(NS_ROUTE), RecvFamily::Netlink, 0), Ok(RecvRoute::Netlink));
    assert_eq!(admit_and_route(sock(NS_ROUTE), RecvFamily::Vsock, 0), Ok(RecvRoute::Vsock));
    assert_eq!(admit_and_route(sock(NS_ROUTE), RecvFamily::Inet { unix: true }, 0),
        Ok(RecvRoute::Unix));
    assert_eq!(admit_and_route(sock(NS_ROUTE), RecvFamily::Inet { unix: false }, 0),
        Ok(RecvRoute::Inet));
}

#[test]
fn only_a_non_unix_internet_socket_diverts_to_its_error_queue() {
    let _ = network::remove_namespace(NS_ERRQ);
    assert_eq!(admit_and_route(sock(NS_ERRQ), RecvFamily::Inet { unix: false }, MSG_ERRQUEUE),
        Ok(RecvRoute::InetErrqueue));
    // AF_UNIX shares the internet socket object but keeps no error queue: the
    // flag is left for its own receive to answer.
    assert_eq!(admit_and_route(sock(NS_ERRQ), RecvFamily::Inet { unix: true }, MSG_ERRQUEUE),
        Ok(RecvRoute::Unix));
    // Netlink and VSOCK own their queue inside their own receive.
    assert_eq!(admit_and_route(sock(NS_ERRQ), RecvFamily::Netlink, MSG_ERRQUEUE),
        Ok(RecvRoute::Netlink));
    assert_eq!(admit_and_route(sock(NS_ERRQ), RecvFamily::Vsock, MSG_ERRQUEUE),
        Ok(RecvRoute::Vsock));
}

#[test]
fn a_receive_is_admitted_exactly_once_per_transaction() {
    let _ = network::remove_namespace(NS_ONCE);
    assert!(network::install(NS_ONCE, Operation::Receive, |_| Verdict::Allow).is_none());
    assert!(admit_and_route(sock(NS_ONCE), RecvFamily::Inet { unix: false }, 0).is_ok());
    assert_eq!(network::counters(NS_ONCE, Operation::Receive), Some((1, 0)));
    assert_eq!(network::remove_namespace(NS_ONCE), 1);
}
