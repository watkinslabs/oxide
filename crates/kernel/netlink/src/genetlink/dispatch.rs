// NETLINK_GENERIC request admission and command dispatch.
//
// Ordering is load-bearing: a client that probes an unregistered family must
// see ENOENT, one that probes a registered family for a command it does not
// implement must see EOPNOTSUPP, and only a command that EXISTS may fail the
// permission ladder with EPERM.

extern crate alloc;

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::{flags, Nlmsghdr};
use super::ctrl;
use super::family::{self, GenlFamily, GenlOp};
use super::message;
use super::tcp_metrics;
use super::uapi::*;

/// Capability answers the permission ladder consumes, resolved against the
/// SENDING socket before dispatch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GenlCred {
    /// `CAP_NET_ADMIN` in the initial user namespace.
    pub init_ns_net_admin: bool,
    /// `CAP_NET_ADMIN` in the network namespace's owning user namespace.
    pub sock_ns_net_admin: bool,
}

/// Netlink message flags a genetlink command may carry once the family opts
/// into strict header validation.
const GENL_ALLOWED_FLAGS: u16 = flags::NLM_F_REQUEST | flags::NLM_F_ACK | flags::NLM_F_ECHO;

/// Request is a dump (`NLM_F_DUMP` is two bits). # C: O(1)
fn is_dump(hdr: &Nlmsghdr) -> bool {
    hdr.nlmsg_flags & flags::NLM_F_DUMP == flags::NLM_F_DUMP
}

/// `genl_header_check`: commands added after strict validation began must zero
/// the `genlmsghdr` reserved field and may only carry core netlink flags.
/// # C: O(1)
fn header_check(fam: &GenlFamily, hdr: &Nlmsghdr, gh: &Genlmsghdr) -> Result<(), Errno> {
    if gh.cmd < fam.resv_start_op { return Ok(()); }
    if gh.reserved != 0 { return Err(Errno::Einval); }
    let mut rest = hdr.nlmsg_flags;
    if is_dump(hdr) { rest &= !flags::NLM_F_DUMP; }
    if rest & !GENL_ALLOWED_FLAGS != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// Select the op serving this request, honoring the do/dump split.
/// # C: O(N ops)
fn select_op<'a>(fam: &'a GenlFamily, cmd: u8, dump: bool) -> Result<&'a GenlOp, Errno> {
    let need = if dump { op_flags::GENL_CMD_CAP_DUMP } else { op_flags::GENL_CMD_CAP_DO };
    match fam.op(cmd) {
        Some(op) if op.flags & need != 0 => Ok(op),
        _ => Err(Errno::Eopnotsupp),
    }
}

/// `GENL_ADMIN_PERM` / `GENL_UNS_ADMIN_PERM` ladder. # C: O(1)
fn check_perm(op: &GenlOp, cred: GenlCred) -> Result<(), Errno> {
    if op.flags & op_flags::GENL_ADMIN_PERM != 0 && !cred.init_ns_net_admin {
        return Err(Errno::Eperm);
    }
    if op.flags & op_flags::GENL_UNS_ADMIN_PERM != 0 && !cred.sock_ns_net_admin {
        return Err(Errno::Eperm);
    }
    Ok(())
}

/// Admit a request as far as the op that will serve it. # C: O(N families + N ops)
fn admit<'a>(
    fam: &'a GenlFamily, hdr: &Nlmsghdr, gh: &Genlmsghdr, msg_len: usize, net_ns: u64,
    cred: GenlCred,
) -> Result<&'a GenlOp, Errno> {
    if !fam.netnsok && net_ns != super::mcast::initial_net_ns() { return Err(Errno::Enoent); }
    let hdrlen = Nlmsghdr::SIZE + Genlmsghdr::SIZE + fam.hdrsize as usize;
    if msg_len < hdrlen || (hdr.nlmsg_len as usize) < hdrlen { return Err(Errno::Einval); }
    header_check(fam, hdr, gh)?;
    let op = select_op(fam, gh.cmd, is_dump(hdr))?;
    check_perm(op, cred)?;
    Ok(op)
}

/// Dispatch one NETLINK_GENERIC message. `full_msg` is the `nlmsghdr`-prefixed
/// request, already length-validated by the socket write path.
/// # C: O(N families + reply size)
pub fn handle(full_msg: &[u8], net_ns: u64, cred: GenlCred) -> Vec<u8> {
    let Some(hdr) = Nlmsghdr::parse(full_msg) else { return Vec::new(); };
    let Some(gh) = Genlmsghdr::parse(&full_msg[Nlmsghdr::SIZE..]) else {
        return message::error(&hdr, Err(Errno::Einval));
    };
    let Some(fam) = family::find_by_id(hdr.nlmsg_type) else {
        return message::error(&hdr, Err(Errno::Enoent));
    };
    if let Err(e) = admit(&fam, &hdr, &gh, full_msg.len(), net_ns, cred) {
        return message::error(&hdr, Err(e));
    }
    let attrs = &full_msg[Nlmsghdr::SIZE + Genlmsghdr::SIZE + fam.hdrsize as usize..];
    let dump = is_dump(&hdr);
    let mut reply = match (fam.id, gh.cmd, dump) {
        (GENL_ID_CTRL, ctrl_cmd::CTRL_CMD_GETFAMILY, false) =>
            ctrl::getfamily(&hdr, attrs, net_ns),
        (GENL_ID_CTRL, ctrl_cmd::CTRL_CMD_GETFAMILY, true) =>
            ctrl::dumpfamily(&hdr, net_ns),
        (GENL_ID_CTRL, ctrl_cmd::CTRL_CMD_GETPOLICY, true) =>
            ctrl::dumppolicy(&hdr, attrs),
        (_, tcp_metrics::cmd::GET, false) if fam.name == tcp_metrics::TCP_METRICS_FAMILY_NAME =>
            tcp_metrics::get(&hdr, attrs, net_ns),
        // A family whose op table admitted the command but whose handler lives
        // outside the controller has no in-kernel producer yet.
        _ => message::error(&hdr, Err(Errno::Eopnotsupp)),
    };
    // A successful request that asked for one still gets its explicit ACK.
    if hdr.nlmsg_flags & flags::NLM_F_ACK != 0 && !is_error_reply(&reply) {
        reply.extend_from_slice(&message::error(&hdr, Ok(())));
    }
    reply
}

/// Reply is a bare `NLMSG_ERROR` carrying a failure. # C: O(1)
fn is_error_reply(reply: &[u8]) -> bool {
    Nlmsghdr::parse(reply).is_some_and(|h| h.nlmsg_type == crate::msg::NLMSG_ERROR)
}
