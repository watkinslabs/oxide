// NETLINK_AUDIT (proto 9) — the control socket the audit daemon binds
// (`docs/25` netlink surface, `docs/27` audit).
//
// This file is the transport half only: it gathers the sender's namespaces and
// capabilities, hands the request to the audit subsystem, frames whatever that
// decides into netlink messages, and carries queued records back out to the
// registered consumer's port. Every decision — admission, configuration,
// registration, backlog accounting — lives in the `audit` crate, ungated and
// unit-tested.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use ::audit::control::{Reply, Request};

use crate::netlink_socket::NetlinkSocket;
use crate::rtnetlink;
use crate::wire::Nlmsghdr;

pub use ::audit::uapi::{AUDIT_GET, AUDIT_GET_FEATURE, AUDIT_LIST_RULES, AUDIT_SET,
    AUDIT_SET_FEATURE};

/// Dispatch one NETLINK_AUDIT request; returns the reply bytes to enqueue.
/// # C: O(payload len)
pub(crate) fn handle(sock: &NetlinkSocket, hdr: &Nlmsghdr, msg: &[u8]) -> Vec<u8> {
    // Registering the transport here rather than from a boot hook keeps the
    // audit crate free of any boot-order slot: the first message on an audit
    // socket is necessarily before any consumer can be registered, so no
    // record can be produced while the sender is still unset.
    ::audit::state::set_sender(deliver);
    let body = if msg.len() > Nlmsghdr::SIZE { &msg[Nlmsghdr::SIZE..] } else { &[][..] };
    let req = Request {
        msg_type: hdr.nlmsg_type,
        data: body,
        caller: caller_facts(),
        caller_pid: caller_pid(),
        port_id: sock.port_id.load(Ordering::Acquire),
        route: sock.net_ns.id().as_u64(),
        realtime_ns: realtime_ns(),
        now_ms: realtime_ns() / NS_PER_MS,
    };
    let reply = ::audit::state::with(|s| ::audit::control::handle(s, &req));
    // A registration may have released a held history; carry it out before the
    // acknowledgement so the daemon sees the backlog it just took ownership of.
    ::audit::state::flush();
    match reply {
        Reply::Status(body) => single_reply(hdr, AUDIT_GET, &body),
        Reply::Features(body) => single_reply(hdr, AUDIT_GET_FEATURE, &body),
        Reply::Done => {
            let mut done = alloc::vec![0u8; Nlmsghdr::SIZE];
            Nlmsghdr::done(hdr.nlmsg_seq, hdr.nlmsg_pid).write_to(&mut done);
            done
        }
        Reply::Ack(v) => rtnetlink::nlmsg_ack_pub(hdr, v),
    }
}

const NS_PER_MS: u64 = 1_000_000;

/// Carry one record to the consumer's netlink port. `false` when no socket
/// owns that port any more, or its receive budget refused the record.
/// # C: O(N live Netlink ports)
fn deliver(route: u64, port_id: u32, ty: u16, text: &[u8]) -> bool {
    let total = Nlmsghdr::SIZE + text.len();
    let mut out = Vec::with_capacity(total);
    let h = Nlmsghdr {
        nlmsg_len: total as u32,
        nlmsg_type: ty,
        nlmsg_flags: 0,
        // A kernel-generated record answers no request: it carries neither a
        // sequence number nor a sender port.
        nlmsg_seq: 0,
        nlmsg_pid: 0,
    };
    let mut hb = [0u8; Nlmsghdr::SIZE];
    h.write_to(&mut hb);
    out.extend_from_slice(&hb);
    out.extend_from_slice(text);
    crate::ports::deliver_from_kernel(route, crate::proto::NETLINK_AUDIT, port_id, &out)
}

/// Build a single netlink reply message: `nlmsghdr(type) + body`.
/// # C: O(body len)
fn single_reply(req: &Nlmsghdr, ty: u16, body: &[u8]) -> Vec<u8> {
    let total = Nlmsghdr::SIZE + body.len();
    let rh = Nlmsghdr {
        nlmsg_len: total as u32,
        nlmsg_type: ty,
        nlmsg_flags: 0,
        nlmsg_seq: req.nlmsg_seq,
        nlmsg_pid: req.nlmsg_pid,
    };
    let mut out = Vec::with_capacity(total);
    let mut hb = [0u8; Nlmsghdr::SIZE];
    rh.write_to(&mut hb);
    out.extend_from_slice(&hb);
    out.extend_from_slice(body);
    out
}

/// The sender's namespaces and audit capabilities.
///
/// Both capabilities are tested against the INITIAL user namespace: the audit
/// system is global, so holding a capability inside a nested namespace must
/// not reach it.
/// # C: O(N_userns_depth)
#[cfg(target_os = "oxide-kernel")]
fn caller_facts() -> ::audit::Caller {
    use namespace_identity::NamespaceKind;
    let Some(cur) = sched::current() else { return ::audit::Caller::default() };
    let init_user = namespace_identity::initial(NamespaceKind::User).pin();
    ::audit::Caller {
        init_user_ns: in_initial(&cur, NamespaceKind::User),
        init_pid_ns: in_initial(&cur, NamespaceKind::Pid),
        cap_audit_control: nscg::proc_ns::has_cap_for(&cur, &init_user,
            sched::cap::AUDIT_CONTROL),
        cap_audit_write: nscg::proc_ns::has_cap_for(&cur, &init_user, sched::cap::AUDIT_WRITE),
    }
}

/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
fn in_initial(cur: &sched::Task, kind: namespace_identity::NamespaceKind) -> bool {
    let Some(own) = cur.namespace_owner(kind) else { return false };
    namespace_identity::NamespacePin::ptr_eq(&own.pin(), &namespace_identity::initial(kind).pin())
}

/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
fn caller_pid() -> u32 { sched::current().map(|t| t.visible_pid()).unwrap_or(0) }

/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
fn realtime_ns() -> u64 { ::audit::clock::realtime_ns() }

/// A hosted build has no task to read namespaces or capabilities from, so it
/// answers as the initial-namespace privileged caller — the same convention
/// every other admission check in this crate uses hosted, and the one that
/// leaves the transport exercisable by the hosted suite.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
fn caller_facts() -> ::audit::Caller {
    ::audit::Caller { init_user_ns: true, init_pid_ns: true,
                      cap_audit_control: true, cap_audit_write: true }
}

/// A hosted build has one notional process, so the transport can still be
/// driven through a registration.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
fn caller_pid() -> u32 { 1 }

/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
fn realtime_ns() -> u64 { ::audit::clock::realtime_ns() }

#[cfg(test)]
#[path = "netlink_tests/audit.rs"]
mod tests;
