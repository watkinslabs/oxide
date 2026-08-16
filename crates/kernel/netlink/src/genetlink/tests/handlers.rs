// A family serving its own commands through its op table.
//
// Without this, a family whose handlers live outside this crate would have to
// be named in the dispatcher's match — a second place that has to agree with
// the registry about which families exist. These pin that the handler runs,
// that it runs only for the request shape it was registered for, and that the
// permission ladder still runs FIRST.

extern crate alloc;

use alloc::vec::Vec;

use syscall::errno::Errno;

use super::harness::*;
use crate::flags;
use crate::genetlink::attr;
use crate::genetlink::dispatch;
use crate::genetlink::family::{GenlCtx, GenlOp};
use crate::genetlink::uapi::*;
use crate::Nlmsghdr;

/// Attribute the probe handlers answer with.
const PROBE_ATTR: u16 = 1;

/// Reply carrying the context the dispatcher handed the handler, so a test can
/// check the handler saw the right request.
fn probe_doit(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    let mut out = crate::genetlink::message::start(hdr.nlmsg_pid, hdr.nlmsg_seq,
        ctx.family_id, 1, 0, 100);
    attr::put_u32(&mut out, PROBE_ATTR, ctx.portid);
    attr::put_u32(&mut out, PROBE_ATTR + 1, attrs.len() as u32);
    attr::put_u32(&mut out, PROBE_ATTR + 2, u32::from(ctx.init_ns_net_admin));
    crate::genetlink::message::end(&mut out, 0);
    out
}

/// A dump handler, answering with a different command number so a test can
/// tell which of the two ran.
fn probe_dumpit(hdr: &Nlmsghdr, _attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    let mut out = crate::genetlink::message::start(hdr.nlmsg_pid, hdr.nlmsg_seq,
        ctx.family_id, 1, 0, 101);
    crate::genetlink::message::end(&mut out, 0);
    out
}

/// The command number carried in a reply's family header.
fn reply_cmd(reply: &[u8]) -> Option<u8> { reply.get(Nlmsghdr::SIZE).copied() }

/// One `u32` attribute out of a reply.
fn reply_u32(reply: &[u8], ty: u16) -> Option<u32> {
    let body = reply.get(Nlmsghdr::SIZE + Genlmsghdr::SIZE..)?;
    let a = attr::find(body, ty)?;
    Some(u32::from_ne_bytes(a.payload.get(..4)?.try_into().ok()?))
}

fn init_ns() -> u64 { crate::genetlink::mcast::initial_net_ns() }

#[test]
fn a_family_with_its_own_handler_serves_its_command() {
    let fam = register_test_family("own", alloc::vec![
        GenlOp::with_handlers(1, op_flags::GENL_CMD_CAP_DO, &[], Some(probe_doit), None),
    ], 0);
    let reply = dispatch::handle(
        &request(fam.id, 1, flags::NLM_F_REQUEST, 7, &[]), init_ns(), root());
    assert_eq!(reply_cmd(&reply), Some(100), "the family's own handler answered");
    assert_eq!(reply_u32(&reply, PROBE_ATTR + 2), Some(1),
        "the ladder's answer reached the handler");
}

#[test]
fn a_command_with_no_handler_of_its_own_still_reports_no_producer() {
    let fam = register_test_family("nohandler", alloc::vec![
        GenlOp { cmd: 1, flags: op_flags::GENL_CMD_CAP_DO, policy: &[], ..GenlOp::EMPTY },
    ], 0);
    let reply = dispatch::handle(
        &request(fam.id, 1, flags::NLM_F_REQUEST, 1, &[]), init_ns(), root());
    assert_eq!(reply_errno(&reply), Some(Errno::Eopnotsupp.as_i32()));
}

#[test]
fn the_dump_handler_serves_a_dump_and_the_plain_handler_serves_the_rest() {
    let fam = register_test_family("both", alloc::vec![
        GenlOp::with_handlers(1, op_flags::GENL_CMD_CAP_DO | op_flags::GENL_CMD_CAP_DUMP,
            &[], Some(probe_doit), Some(probe_dumpit)),
    ], 0);
    let plain = dispatch::handle(
        &request(fam.id, 1, flags::NLM_F_REQUEST, 1, &[]), init_ns(), root());
    assert_eq!(reply_cmd(&plain), Some(100));
    let dumped = dispatch::handle(
        &request(fam.id, 1, flags::NLM_F_REQUEST | flags::NLM_F_DUMP, 1, &[]),
        init_ns(), root());
    assert_eq!(reply_cmd(&dumped), Some(101));
}

#[test]
fn a_command_registered_for_one_direction_only_is_not_served_the_other_way() {
    let fam = register_test_family("doonly", alloc::vec![
        GenlOp::with_handlers(1, op_flags::GENL_CMD_CAP_DO, &[], Some(probe_doit), None),
    ], 0);
    // The op does not advertise the dump capability, so admission refuses it
    // before the absent dump handler could be reached.
    let reply = dispatch::handle(
        &request(fam.id, 1, flags::NLM_F_REQUEST | flags::NLM_F_DUMP, 1, &[]),
        init_ns(), root());
    assert_eq!(reply_errno(&reply), Some(Errno::Eopnotsupp.as_i32()));
}

#[test]
fn the_permission_ladder_runs_before_the_handler() {
    // A handler that ran for an unprivileged caller would act on a request the
    // ladder was there to refuse.
    let fam = register_test_family("perm", alloc::vec![
        GenlOp::with_handlers(1, op_flags::GENL_CMD_CAP_DO | op_flags::GENL_ADMIN_PERM,
            &[], Some(probe_doit), None),
    ], 0);
    let nobody = crate::genetlink::GenlCred::default();
    let reply = dispatch::handle(
        &request(fam.id, 1, flags::NLM_F_REQUEST, 1, &[]), init_ns(), nobody);
    assert_eq!(reply_errno(&reply), Some(Errno::Eperm.as_i32()));
    assert_ne!(reply_cmd(&reply), Some(100), "the handler must not have run");
    let reply = dispatch::handle(
        &request(fam.id, 1, flags::NLM_F_REQUEST, 1, &[]), init_ns(), root());
    assert_eq!(reply_cmd(&reply), Some(100));
}

#[test]
fn the_handler_sees_the_attributes_and_not_the_headers() {
    let fam = register_test_family("attrs", alloc::vec![
        GenlOp::with_handlers(1, op_flags::GENL_CMD_CAP_DO, &[], Some(probe_doit), None),
    ], 0);
    let mut attrs = Vec::new();
    attr::put_u32(&mut attrs, 1, 0xdead_beef);
    let want = attrs.len() as u32;
    let reply = dispatch::handle(
        &request(fam.id, 1, flags::NLM_F_REQUEST, 1, &attrs), init_ns(), root());
    assert_eq!(reply_u32(&reply, PROBE_ATTR + 1), Some(want));
}

#[test]
fn a_handler_reply_still_gets_the_acknowledgement_the_request_asked_for() {
    let fam = register_test_family("ack", alloc::vec![
        GenlOp::with_handlers(1, op_flags::GENL_CMD_CAP_DO, &[], Some(probe_doit), None),
    ], 0);
    let plain = dispatch::handle(
        &request(fam.id, 1, flags::NLM_F_REQUEST, 1, &[]), init_ns(), root());
    let acked = dispatch::handle(
        &request(fam.id, 1, flags::NLM_F_REQUEST | flags::NLM_F_ACK, 1, &[]),
        init_ns(), root());
    assert!(acked.len() > plain.len(), "the acknowledgement follows the reply");
    let tail = Nlmsghdr::parse(&acked[plain.len()..]).unwrap();
    assert_eq!(tail.nlmsg_type, crate::msg::NLMSG_ERROR);
}

#[test]
fn the_handler_is_addressed_by_the_requesting_port() {
    let fam = register_test_family("port", alloc::vec![
        GenlOp::with_handlers(1, op_flags::GENL_CMD_CAP_DO, &[], Some(probe_doit), None),
    ], 0);
    let mut msg = request(fam.id, 1, flags::NLM_F_REQUEST, 1, &[]);
    let mut hdr = Nlmsghdr::parse(&msg).unwrap();
    hdr.nlmsg_pid = 4242;
    hdr.write_to(&mut msg);
    let reply = dispatch::handle(&msg, init_ns(), root());
    assert_eq!(reply_u32(&reply, PROBE_ATTR), Some(4242));
}

#[test]
fn two_ops_of_one_family_reach_their_own_handlers() {
    let fam = register_test_family("two", alloc::vec![
        GenlOp::with_handlers(1, op_flags::GENL_CMD_CAP_DO, &[], Some(probe_doit), None),
        GenlOp::with_handlers(2, op_flags::GENL_CMD_CAP_DO, &[], Some(probe_dumpit), None),
    ], 0);
    assert_eq!(reply_cmd(&dispatch::handle(
        &request(fam.id, 1, flags::NLM_F_REQUEST, 1, &[]), init_ns(), root())), Some(100));
    assert_eq!(reply_cmd(&dispatch::handle(
        &request(fam.id, 2, flags::NLM_F_REQUEST, 1, &[]), init_ns(), root())), Some(101));
}

#[test]
fn ops_are_the_same_command_when_they_agree_on_everything_but_the_address() {
    // Handler addresses are deliberately not compared: a function's address is
    // not stable across codegen units, so comparing them would make equality
    // depend on the build.
    let a = GenlOp::with_handlers(1, op_flags::GENL_CMD_CAP_DO, &[], Some(probe_doit), None);
    let b = GenlOp::with_handlers(1, op_flags::GENL_CMD_CAP_DO, &[], Some(probe_dumpit),
                                  None);
    assert_eq!(a, b);
    // Whether the family serves the command at all is still part of identity.
    let c = GenlOp { cmd: 1, flags: op_flags::GENL_CMD_CAP_DO, policy: &[], ..GenlOp::EMPTY };
    assert_ne!(a, c);
}
