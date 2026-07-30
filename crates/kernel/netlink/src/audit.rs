// NETLINK_AUDIT (proto 9) minimal handler (`docs/25` netlink surface).
// Audit rule loaders and PAM session accounting require protocol-specific
// replies rather than a generic acknowledgement: AUDIT_GET returns audit
// status, AUDIT_GET_FEATURE returns audit features, rule/set/user operations
// acknowledge, and AUDIT_LIST_RULES terminates an empty dump.

use alloc::vec::Vec;

use crate::rtnetlink;
use crate::wire::Nlmsghdr;

/// Audit netlink message types.
pub const AUDIT_GET: u16 = 1000;
pub const AUDIT_SET: u16 = 1001;
pub const AUDIT_LIST_RULES: u16 = 1013;
pub const AUDIT_ADD_RULE: u16 = 1011;
pub const AUDIT_DEL_RULE: u16 = 1012;
pub const AUDIT_TRIM: u16 = 1014;
pub const AUDIT_MAKE_EQUIV: u16 = 1015;
pub const AUDIT_SIGNAL_INFO: u16 = 1010;
pub const AUDIT_GET_FEATURE: u16 = 1019;
pub const AUDIT_SET_FEATURE: u16 = 1020;

/// `struct audit_status`: 8 leading u32 + a
/// `version`/`feature_bitmap` union + `backlog_wait_time` = 40 bytes. All zero
/// = audit disabled, no rate/backlog limits, no registered `auditd` (pid 0).
const AUDIT_STATUS_LEN: usize = 40;

/// Dispatch one NETLINK_AUDIT request; returns the reply bytes to enqueue.
/// # C: O(1)
pub fn handle(hdr: &Nlmsghdr, _msg: &[u8]) -> Vec<u8> {
    match hdr.nlmsg_type {
        AUDIT_GET => single_reply(hdr, AUDIT_GET, &[0u8; AUDIT_STATUS_LEN]),
        AUDIT_GET_FEATURE => {
            // `struct audit_features` = { u32 vers; u32 mask; u32 features; u32
            // lock; } — all zero = no optional features enabled/locked.
            single_reply(hdr, AUDIT_GET_FEATURE, &[0u8; 16])
        }
        // No rules are installed (audit disabled) — end the dump cleanly so
        // `auditctl -l` / augenrules' pre-load list returns instead of blocking.
        AUDIT_LIST_RULES => {
            let mut done = alloc::vec![0u8; Nlmsghdr::SIZE];
            Nlmsghdr::done(hdr.nlmsg_seq, hdr.nlmsg_pid).write_to(&mut done);
            done
        }
        // AUDIT_SET, AUDIT_SET_FEATURE, ADD/DEL/TRIM/MAKE_EQUIV rule ops, the
        // SIGNAL_INFO query, and every AUDIT_USER*/message record: accept with a
        // success ack (audit is a no-op sink here, matching a kernel with audit
        // enabled but no rules — the events are simply not recorded).
        _ => rtnetlink::nlmsg_ack_pub(hdr, 0),
    }
}

/// Build a single netlink reply message: `nlmsghdr(type) + body`.
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
