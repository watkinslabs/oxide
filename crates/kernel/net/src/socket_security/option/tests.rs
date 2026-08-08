// The socket-option security decision, driven as a decision.
//
// Two contracts are pinned here: a write and a read are separately registered
// (a module that refuses changes still publishes state), and the decision
// carries the level and option number, so a module can refuse ONE option
// rather than the whole interface.

use core::sync::atomic::{AtomicI32, Ordering};

use security::network::{self, Context, Operation, Verdict};
use sync::Spinlock;

use super::*;

const NS_SET: u64 = 4_200;
const NS_GET: u64 = 4_201;
const NS_WHICH: u64 = 4_202;
const NS_OTHER_OP: u64 = 4_203;
const NS_IDENTITY: u64 = 4_204;

/// The level/optname of the one option a test module refuses. # C: O(1)
static REFUSED: (AtomicI32, AtomicI32) = (AtomicI32::new(0), AtomicI32::new(0));

/// The last context a hook was handed. # C: O(1)
static SEEN: Spinlock<Option<Context>, sync::Namespace> = Spinlock::new(None);

fn deny(context: Context) -> Verdict { *SEEN.lock() = Some(context); Verdict::Deny }

fn record(context: Context) -> Verdict { *SEEN.lock() = Some(context); Verdict::Allow }

/// A module with an opinion about one option only. # C: O(1)
fn deny_one(context: Context) -> Verdict {
    let refused = (REFUSED.0.load(Ordering::Acquire), REFUSED.1.load(Ordering::Acquire));
    if (context.option.level, context.option.optname) == refused { Verdict::Deny }
    else { Verdict::Allow }
}

fn sock(namespace: u64) -> OptSock {
    OptSock { namespace, family: 2, socket_type: 2, protocol: 17 }
}

#[test]
fn refusing_writes_leaves_reads_answerable() {
    let _ = network::remove_namespace(NS_SET);
    assert_eq!(network::install(NS_SET, Operation::SetOption, deny), None);
    assert_eq!(setsockopt(sock(NS_SET), 1, 8), Err(crate::NetError::Eacces));
    assert_eq!(getsockopt(sock(NS_SET), 1, 8), Ok(()));
    assert_eq!(network::remove_namespace(NS_SET), 1);
}

#[test]
fn refusing_reads_leaves_writes_permitted() {
    let _ = network::remove_namespace(NS_GET);
    assert_eq!(network::install(NS_GET, Operation::GetOption, deny), None);
    assert_eq!(getsockopt(sock(NS_GET), 1, 8), Err(crate::NetError::Eacces));
    assert_eq!(setsockopt(sock(NS_GET), 1, 8), Ok(()));
    assert_eq!(network::remove_namespace(NS_GET), 1);
}

#[test]
fn the_decision_names_the_option_and_the_socket() {
    let _ = network::remove_namespace(NS_WHICH);
    assert_eq!(network::install(NS_WHICH, Operation::SetOption, record), None);
    let target = sock(NS_WHICH);
    assert_eq!(setsockopt(target, 6, 12), Ok(()));
    let seen = SEEN.lock().expect("the option hook was not consulted");
    assert_eq!(seen.operation, Operation::SetOption);
    assert_eq!((seen.option.level, seen.option.optname), (6, 12));
    assert_eq!((seen.namespace, seen.family), (target.namespace, target.family));
    assert_eq!((seen.socket_type, seen.protocol), (target.socket_type, target.protocol));
    assert_eq!(network::remove_namespace(NS_WHICH), 1);
}

#[test]
fn a_module_can_refuse_one_option_without_refusing_the_interface() {
    let _ = network::remove_namespace(NS_WHICH);
    REFUSED.0.store(1, Ordering::Release);
    REFUSED.1.store(9, Ordering::Release);
    assert_eq!(network::install(NS_WHICH, Operation::SetOption, deny_one), None);
    assert_eq!(setsockopt(sock(NS_WHICH), 1, 9), Err(crate::NetError::Eacces));
    assert_eq!(setsockopt(sock(NS_WHICH), 1, 10), Ok(()));
    assert_eq!(setsockopt(sock(NS_WHICH), 6, 9), Ok(()));
    assert_eq!(network::remove_namespace(NS_WHICH), 1);
}

#[test]
fn an_operation_that_names_no_option_carries_no_option_number() {
    let _ = network::remove_namespace(NS_OTHER_OP);
    assert_eq!(network::install(NS_OTHER_OP, Operation::Bind, record), None);
    assert_eq!(crate::security_admission::check(NS_OTHER_OP, 2, Operation::Bind), Ok(()));
    let seen = SEEN.lock().expect("the bind hook was not consulted");
    assert_eq!(seen.option, security::network::OptionId::NONE);
    assert_ne!(seen.option, security::network::OptionId { level: 0, optname: 0 });
    assert_eq!(network::remove_namespace(NS_OTHER_OP), 1);
}

#[test]
fn the_hook_sees_the_type_and_protocol_the_socket_reports_about_itself() {
    use crate::sock_opts::identity;
    let _ = network::remove_namespace(NS_IDENTITY);
    let socket = crate::sock::InetSocket::new_udp6();
    let described = inet(&socket);
    assert_eq!(described.socket_type as i32, identity::socket_type(&socket));
    assert_eq!(described.protocol as i32, identity::socket_protocol(&socket));
    assert_eq!(described.socket_type, crate::socket_args::SOCK_DGRAM);
    assert_eq!(described.protocol, crate::socket_args::IPPROTO_UDP);

    let unix = crate::sock::InetSocket::new_unix();
    assert_eq!(inet(&unix).socket_type, crate::socket_args::SOCK_STREAM);
    // An AF_UNIX socket carries no protocol number.
    assert_eq!(inet(&unix).protocol, 0);
}
