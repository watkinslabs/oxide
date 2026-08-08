// NETLINK_AUDIT transport: framing, the registration handshake, and record
// delivery to the registered consumer's port.

use alloc::sync::Arc;
use alloc::vec::Vec;

use ::audit::uapi::{AUDIT_FANOTIFY, AUDIT_STATUS_LEN, AUDIT_STATUS_PID};
use ::audit::wire::Status;

use super::*;
use crate::netlink_tests::test_namespace;
use crate::ports::register_port_id;

/// The hosted caller's process id, the only one it may register.
const HOSTED_PID: u32 = 1;

fn request(ty: u16, body: &[u8]) -> (Nlmsghdr, Vec<u8>) {
    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len: total as u32, nlmsg_type: ty,
        nlmsg_flags: crate::flags::NLM_F_REQUEST, nlmsg_seq: 3, nlmsg_pid: HOSTED_PID,
    };
    let mut msg = alloc::vec![0u8; total];
    hdr.write_to(&mut msg);
    msg[Nlmsghdr::SIZE..].copy_from_slice(body);
    (hdr, msg)
}

fn socket() -> Arc<NetlinkSocket> {
    let ns = test_namespace();
    let s = Arc::new(NetlinkSocket::new(crate::proto::NETLINK_AUDIT, &ns));
    register_port_id(&s);
    s
}

/// Leave the audit system as it was found: one consumer registration is global
/// and would refuse the next test's.
fn unregister(sock: &Arc<NetlinkSocket>) {
    let body = Status { mask: AUDIT_STATUS_PID, pid: 0, ..Status::default() }.encode();
    let (hdr, msg) = request(::audit::uapi::AUDIT_SET, &body);
    let _ = handle(sock, &hdr, &msg);
    ::audit::state::with(|s| { while s.backlog.pop().is_some() {} });
}

fn reply_type(reply: &[u8]) -> u16 {
    Nlmsghdr::parse(reply).expect("a reply is a well-formed netlink message").nlmsg_type
}

#[test]
fn a_status_query_answers_with_the_status_struct_under_its_own_type() {
    let _g = crate::test_serial::audit();
    let sock = socket();
    let (hdr, msg) = request(AUDIT_GET, &[]);
    let reply = handle(&sock, &hdr, &msg);
    assert_eq!(reply_type(&reply), AUDIT_GET);
    assert_eq!(reply.len(), Nlmsghdr::SIZE + AUDIT_STATUS_LEN);
    let parsed = Nlmsghdr::parse(&reply).unwrap();
    assert_eq!(parsed.nlmsg_seq, 3, "a reply carries the request's sequence");
}

#[test]
fn a_features_query_answers_with_the_features_struct() {
    let _g = crate::test_serial::audit();
    let sock = socket();
    let (hdr, msg) = request(AUDIT_GET_FEATURE, &[]);
    let reply = handle(&sock, &hdr, &msg);
    assert_eq!(reply_type(&reply), AUDIT_GET_FEATURE);
    assert_eq!(reply.len(), Nlmsghdr::SIZE + ::audit::uapi::AUDIT_FEATURES_LEN);
}

/// An empty rule list must still terminate its dump, or a rule loader's
/// pre-load listing blocks forever.
#[test]
fn an_empty_rule_list_terminates_its_dump() {
    let _g = crate::test_serial::audit();
    let sock = socket();
    let (hdr, msg) = request(AUDIT_LIST_RULES, &[]);
    let reply = handle(&sock, &hdr, &msg);
    assert_eq!(reply_type(&reply), crate::msg::NLMSG_DONE);
}

#[test]
fn a_deprecated_rule_operation_reports_the_interface_not_the_request() {
    let _g = crate::test_serial::audit();
    let sock = socket();
    let (hdr, msg) = request(::audit::uapi::AUDIT_LIST, &[]);
    let reply = handle(&sock, &hdr, &msg);
    assert_eq!(reply_type(&reply), crate::msg::NLMSG_ERROR);
    let err = i32::from_ne_bytes([reply[16], reply[17], reply[18], reply[19]]);
    assert_eq!(err, -(syscall::errno::Errno::Eopnotsupp.as_i32()));
}

/// The whole point of the socket: a record produced by an arbitrary kernel
/// path reaches the registered consumer's receive queue without that consumer
/// having to ask for it.
#[test]
fn a_record_reaches_the_registered_consumers_queue() {
    let _g = crate::test_serial::audit();
    let sock = socket();
    let body = Status { mask: AUDIT_STATUS_PID, pid: HOSTED_PID, ..Status::default() }.encode();
    let (hdr, msg) = request(::audit::uapi::AUDIT_SET, &body);
    let reply = handle(&sock, &hdr, &msg);
    assert_eq!(reply_type(&reply), crate::msg::NLMSG_ERROR);
    assert_eq!(i32::from_ne_bytes([reply[16], reply[17], reply[18], reply[19]]), 0);

    // Drain whatever the registration itself recorded.
    while sock.dequeue().is_some() {}
    let _ = ::audit::log(AUDIT_FANOTIFY, b"resp=2");
    let (bytes, _) = sock.dequeue().expect("the record was delivered unasked");
    let h = Nlmsghdr::parse(&bytes).unwrap();
    assert_eq!(h.nlmsg_type, AUDIT_FANOTIFY);
    assert_eq!(h.nlmsg_seq, 0, "a record answers no request");
    assert_eq!(h.nlmsg_pid, 0);
    let text = core::str::from_utf8(&bytes[Nlmsghdr::SIZE..]).unwrap();
    assert!(text.ends_with("resp=2"), "{text}");
    assert!(text.starts_with("audit("), "{text}");
    unregister(&sock);
}

/// Records produced before any consumer existed are held, and become
/// deliverable the moment one registers.
#[test]
fn a_late_consumer_receives_the_history_it_missed() {
    let _g = crate::test_serial::audit();
    let sock = socket();
    ::audit::state::with(|s| { while s.backlog.pop().is_some() {} });
    let _ = ::audit::log(AUDIT_FANOTIFY, b"resp=1");
    assert!(sock.dequeue().is_none(), "nothing is delivered without a consumer");
    let body = Status { mask: AUDIT_STATUS_PID, pid: HOSTED_PID, ..Status::default() }.encode();
    let (hdr, msg) = request(::audit::uapi::AUDIT_SET, &body);
    handle(&sock, &hdr, &msg);
    let (bytes, _) = sock.dequeue().expect("the held record was released on registration");
    assert_eq!(Nlmsghdr::parse(&bytes).unwrap().nlmsg_type, AUDIT_FANOTIFY);
    unregister(&sock);
}

/// A record for a port nobody owns is refused rather than silently discarded,
/// so the caller can put it back.
#[test]
fn delivery_to_an_unowned_port_reports_failure() {
    let _g = crate::test_serial::audit();
    let ns = test_namespace();
    assert!(!crate::ports::deliver_from_kernel(
        net::net_ns::namespace_id(&ns), crate::proto::NETLINK_AUDIT, 0xdead_beef, b"x"));
}
