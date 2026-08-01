// RTM_GETRULE policy-rule dump. Linux publishes three default v4/v6 rules even
// without custom policy routing: local, main, default.

extern crate alloc;

use alloc::vec::Vec;

use crate::{flags, nlmsg_align, Nlmsghdr};
use crate::rtnetlink::{
    done_multi, put_nlattr_u32, AF_INET, AF_INET6, RTM_NEWRULE,
};
use net::policy_rule::{PolicyRule as RuleRow, FR_ACT_TO_TBL};

#[cfg(test)]
use net::policy_rule;

pub mod fra {
    pub const FRA_PRIORITY: u16 = 6;
    pub const FRA_TABLE:    u16 = 15;
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FibRuleHdr {
    pub family:  u8,
    pub dst_len: u8,
    pub src_len: u8,
    pub tos:     u8,
    pub table:   u8,
    pub res1:    u8,
    pub res2:    u8,
    pub action:  u8,
    pub flags:   u32,
}

impl FibRuleHdr {
    pub const SIZE: usize = 12;

    /// # C: O(1)
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0] = self.family;
        buf[1] = self.dst_len;
        buf[2] = self.src_len;
        buf[3] = self.tos;
        buf[4] = self.table;
        buf[5] = self.res1;
        buf[6] = self.res2;
        buf[7] = self.action;
        buf[8..12].copy_from_slice(&self.flags.to_ne_bytes());
    }
}

/// Build one RTM_NEWRULE reply.
/// # C: O(N attrs)
pub(crate) fn build_newrule_reply(seq: u32, pid: u32, row: RuleRow, multi: bool) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(32);
    let frh = FibRuleHdr {
        family: row.family,
        dst_len: row.dst_len,
        src_len: row.src_len,
        tos: row.tos,
        table: if row.table <= u8::MAX as u32 { row.table as u8 } else { 0 },
        action: row.action,
        flags: row.flags,
        ..FibRuleHdr::default()
    };
    let mut frh_buf = [0u8; FibRuleHdr::SIZE];
    frh.write_to(&mut frh_buf);
    body.extend_from_slice(&frh_buf);
    put_nlattr_u32(&mut body, fra::FRA_PRIORITY, row.priority);
    put_nlattr_u32(&mut body, fra::FRA_TABLE, row.table);

    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len: total as u32,
        nlmsg_type: RTM_NEWRULE,
        nlmsg_flags: if multi { flags::NLM_F_MULTI } else { 0 },
        nlmsg_seq: seq,
        nlmsg_pid: pid,
    };
    let mut out: Vec<u8> = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&body);
    while out.len() % 4 != 0 { out.push(0); }
    out
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ParseRuleError { Malformed, UnsupportedFamily }

fn parse_rule_attrs(attrs: &[u8]) -> Result<(Option<u32>, Option<u32>), ParseRuleError> {
    let mut priority = None;
    let mut table = None;
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let nla_len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if nla_len < 4 || off + nla_len > attrs.len() { return Err(ParseRuleError::Malformed); }
        let next = off.checked_add(nlmsg_align(nla_len)).ok_or(ParseRuleError::Malformed)?;
        if next > attrs.len() { return Err(ParseRuleError::Malformed); }
        let payload = &attrs[off + 4..off + nla_len];
        if matches!(nla_type, fra::FRA_PRIORITY | fra::FRA_TABLE) {
            if payload.len() != 4 { return Err(ParseRuleError::Malformed); }
            let value = u32::from_ne_bytes(payload[0..4].try_into().unwrap());
            match nla_type {
                fra::FRA_PRIORITY => priority = Some(value),
                fra::FRA_TABLE => table = Some(value),
                _ => {}
            }
        }
        off = next;
    }
    if off != attrs.len() { return Err(ParseRuleError::Malformed); }
    Ok((priority, table))
}

fn parse_rule(net_ns: u64, full_msg: &[u8])
    -> Result<(RuleRow, Option<u32>), ParseRuleError>
{
    let off = Nlmsghdr::SIZE;
    if full_msg.len() < off + FibRuleHdr::SIZE { return Err(ParseRuleError::Malformed); }
    let family = match full_msg[off] {
        AF_INET | AF_INET6 => full_msg[off],
        _ => return Err(ParseRuleError::UnsupportedFamily),
    };
    let attrs = &full_msg[off + FibRuleHdr::SIZE..];
    let (priority, attr_table) = parse_rule_attrs(attrs)?;
    let table = attr_table.unwrap_or(full_msg[off + 4] as u32);
    Ok((RuleRow {
        ns: net_ns,
        family,
        dst_len: full_msg[off + 1],
        src_len: full_msg[off + 2],
        tos: full_msg[off + 3],
        table,
        action: full_msg[off + 7],
        flags: u32::from_ne_bytes(full_msg[off + 8..off + 12].try_into().unwrap()),
        priority: priority.unwrap_or(0),
    }, priority))
}

/// RTM_GETRULE dump of built-in plus custom IPv4/IPv6 policy rules.
/// # C: O(N rules)
pub fn handle_getrule(req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    handle_getrule_in(net::netdev::current_net_ns(), req, full_msg)
}

/// Dump rules from the namespace captured by the netlink socket. # C: O(N rules)
pub fn handle_getrule_in(net_ns: u64, req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    let family = match full_msg.get(Nlmsghdr::SIZE).copied().unwrap_or(AF_INET) {
        0 | AF_INET => AF_INET,
        AF_INET6 => AF_INET6,
        _ => return crate::rtnetlink::nlmsg_ack_pub(req, -97),
    };
    let mut reply: Vec<u8> = Vec::with_capacity(128);
    for row in net::global_stack().policy_rules().snapshot_effective(net_ns, family) {
        reply.extend_from_slice(&build_newrule_reply(req.nlmsg_seq, req.nlmsg_pid, row, true));
    }
    reply.extend_from_slice(&done_multi(req.nlmsg_seq, req.nlmsg_pid));
    reply
}

/// RTM_NEWRULE creates a custom policy rule. # C: O(N rules + attrs)
pub fn handle_newrule(req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    handle_newrule_in(net::netdev::current_net_ns(), req, full_msg)
}

/// Create a rule in the namespace captured by the netlink socket. # C: O(N)
pub fn handle_newrule_in(net_ns: u64, req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    let (mut row, explicit_priority) = match parse_rule(net_ns, full_msg) {
        Ok(v) => v,
        Err(ParseRuleError::UnsupportedFamily) => return crate::rtnetlink::nlmsg_ack_pub(req, -97),
        Err(ParseRuleError::Malformed) => return crate::rtnetlink::nlmsg_ack_pub(req, -22),
    };
    if row.action == 0 { row.action = FR_ACT_TO_TBL; }
    if row.table == 0 { return crate::rtnetlink::nlmsg_ack_pub(req, -22); }
    if row.dst_len != 0 || row.src_len != 0 || row.tos != 0 || row.flags != 0
        || row.action != FR_ACT_TO_TBL {
        return crate::rtnetlink::nlmsg_ack_pub(req, -95);
    }
    let ticket = {
        let stack = net::global_stack();
        let Some(namespace) = network_namespace::lookup_u64(net_ns) else {
            return crate::rtnetlink::nlmsg_ack_pub(req, -19);
        };
        let rtnl = stack.rtnl_lock();
        if explicit_priority.is_none() {
            row.priority = stack.policy_rules().next_priority_rtnl(&rtnl, row.ns, row.family);
        }
        let exists = stack.policy_rules().exists_rtnl(&rtnl, row);
        if exists && (req.nlmsg_flags & flags::NLM_F_EXCL) != 0 {
            return crate::rtnetlink::nlmsg_ack_pub(req, -17);
        }
        let inserted = stack.policy_rules().insert_rtnl(&rtnl, row);
        net::control_event::stage(&rtnl,
            net::control_event::ControlEvent::Rule(net::control_event::RuleEvent {
                kind: net::control_event::EventKind::New,
                namespace: net::control_event::NamespaceOwner::Live(namespace), row: inserted,
            }))
    };
    net::control_event::publish(ticket);
    crate::rtnetlink::nlmsg_ack_pub(req, 0)
}

/// RTM_DELRULE removes custom policy rules. # C: O(N rules + attrs)
pub fn handle_delrule(req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    handle_delrule_in(net::netdev::current_net_ns(), req, full_msg)
}

/// Delete a rule in the namespace captured by the netlink socket. # C: O(N)
pub fn handle_delrule_in(net_ns: u64, req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    let (row, explicit_priority) = match parse_rule(net_ns, full_msg) {
        Ok(v) => v,
        Err(ParseRuleError::UnsupportedFamily) => return crate::rtnetlink::nlmsg_ack_pub(req, -97),
        Err(ParseRuleError::Malformed) => return crate::rtnetlink::nlmsg_ack_pub(req, -22),
    };
    let table = if row.table == 0 { None } else { Some(row.table) };
    if explicit_priority.is_none() && table.is_none() { return crate::rtnetlink::nlmsg_ack_pub(req, -22); }
    let ticket = {
        let stack = net::global_stack();
        let Some(namespace) = network_namespace::lookup_u64(net_ns)
            else { return crate::rtnetlink::nlmsg_ack_pub(req, -19) };
        let rtnl = stack.rtnl_lock();
        let selected = stack.policy_rules().snapshot_effective(row.ns, row.family).into_iter()
            .find(|candidate| candidate.dst_len == row.dst_len && candidate.src_len == row.src_len
                && candidate.tos == row.tos && candidate.flags == row.flags && candidate.action == row.action
                && explicit_priority.is_none_or(|priority| candidate.priority == priority)
                && table.is_none_or(|table| candidate.table == table));
        let Some(selected) = selected else { return crate::rtnetlink::nlmsg_ack_pub(req, -2); };
        let Some(removed) = stack.policy_rules()
            .remove_one_rtnl(&rtnl, row.ns, row.family, Some(selected.priority), Some(selected.table))
            else { return crate::rtnetlink::nlmsg_ack_pub(req, -2) };
        net::control_event::stage(&rtnl,
            net::control_event::ControlEvent::Rule(net::control_event::RuleEvent {
                kind: net::control_event::EventKind::Delete,
                namespace: net::control_event::NamespaceOwner::Live(namespace), row: removed,
            }))
    };
    net::control_event::publish(ticket);
    crate::rtnetlink::nlmsg_ack_pub(req, 0)
}

#[cfg(test)]
#[path = "rtnetlink_rule_edge_tests.rs"]
mod edge_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec;

    #[test]
    fn fib_rule_hdr_size_matches_linux() {
        assert_eq!(FibRuleHdr::SIZE, 12);
    }

    #[test]
    fn build_newrule_reply_has_linux_defaults() {
        let row = policy_rule::builtin_rules(0, AF_INET)[1];
        let bytes = build_newrule_reply(9, 42, row, true);
        let hdr = Nlmsghdr::parse(&bytes).unwrap();
        assert_eq!(hdr.nlmsg_type, RTM_NEWRULE);
        assert_eq!(hdr.nlmsg_flags & flags::NLM_F_MULTI, flags::NLM_F_MULTI);
        assert_eq!((hdr.nlmsg_seq, hdr.nlmsg_pid), (9, 42));
        assert_eq!(bytes[Nlmsghdr::SIZE], AF_INET);
        assert_eq!(bytes[Nlmsghdr::SIZE + 4], crate::rtnetlink::RT_TABLE_MAIN);
        assert_eq!(bytes[Nlmsghdr::SIZE + 7], FR_ACT_TO_TBL);
    }

    #[test]
    fn getrule_dump_has_three_rules_and_done() {
        const NS: u64 = 9239;
        let req = Nlmsghdr {
            nlmsg_len: Nlmsghdr::SIZE as u32,
            nlmsg_type: crate::rtnetlink::RTM_GETRULE,
            nlmsg_flags: flags::NLM_F_DUMP,
            nlmsg_seq: 77,
            nlmsg_pid: 88,
        };
        let mut msg = vec![0u8; Nlmsghdr::SIZE + FibRuleHdr::SIZE];
        req.write_to(&mut msg[..Nlmsghdr::SIZE]);
        msg[Nlmsghdr::SIZE] = AF_INET;
        let reply = handle_getrule_in(NS, &req, &msg);
        let mut off = 0;
        let mut rules = 0;
        loop {
            let hdr = Nlmsghdr::parse(&reply[off..]).unwrap();
            if hdr.nlmsg_type == crate::msg::NLMSG_DONE {
                assert_eq!((hdr.nlmsg_seq, hdr.nlmsg_pid), (77, 88));
                break;
            }
            assert_eq!(hdr.nlmsg_type, RTM_NEWRULE);
            rules += 1;
            off += crate::nlmsg_align(hdr.nlmsg_len as usize);
        }
        assert_eq!(rules, 3);
    }

    #[test]
    fn getrule_dump_honors_ipv6_family() {
        let req = Nlmsghdr {
            nlmsg_len: (Nlmsghdr::SIZE + FibRuleHdr::SIZE) as u32,
            nlmsg_type: crate::rtnetlink::RTM_GETRULE,
            nlmsg_flags: flags::NLM_F_DUMP,
            nlmsg_seq: 1,
            nlmsg_pid: 2,
        };
        let mut msg = vec![0u8; Nlmsghdr::SIZE + FibRuleHdr::SIZE];
        req.write_to(&mut msg[..Nlmsghdr::SIZE]);
        msg[Nlmsghdr::SIZE] = AF_INET6;
        let reply = handle_getrule(&req, &msg);
        assert_eq!(reply[Nlmsghdr::SIZE], AF_INET6);
    }

    fn ack_errno(reply: &[u8]) -> i32 {
        assert_eq!(u16::from_ne_bytes([reply[4], reply[5]]), crate::msg::NLMSG_ERROR);
        i32::from_ne_bytes(reply[Nlmsghdr::SIZE..Nlmsghdr::SIZE + 4].try_into().unwrap())
    }

    fn rule_req(typ: u16, family: u8, priority: u32, table: u32) -> (Nlmsghdr, Vec<u8>) {
        let req = Nlmsghdr {
            nlmsg_len: (Nlmsghdr::SIZE + FibRuleHdr::SIZE) as u32,
            nlmsg_type: typ,
            nlmsg_flags: flags::NLM_F_REQUEST | flags::NLM_F_ACK | flags::NLM_F_CREATE,
            nlmsg_seq: priority,
            nlmsg_pid: 9,
        };
        let mut msg = vec![0u8; Nlmsghdr::SIZE + FibRuleHdr::SIZE];
        req.write_to(&mut msg[..Nlmsghdr::SIZE]);
        msg[Nlmsghdr::SIZE] = family;
        msg[Nlmsghdr::SIZE + 4] = table.min(u8::MAX as u32) as u8;
        msg[Nlmsghdr::SIZE + 7] = FR_ACT_TO_TBL;
        put_nlattr_u32(&mut msg, fra::FRA_PRIORITY, priority);
        put_nlattr_u32(&mut msg, fra::FRA_TABLE, table);
        (req, msg)
    }

    #[test]
    fn newrule_dump_and_delrule_mutate_custom_rules() {
        let (new_hdr, new_msg) = rule_req(crate::rtnetlink::RTM_NEWRULE, AF_INET, 12345, 100);
        assert_eq!(ack_errno(&handle_newrule(&new_hdr, &new_msg)), 0);

        let dump_hdr = Nlmsghdr {
            nlmsg_len: (Nlmsghdr::SIZE + FibRuleHdr::SIZE) as u32,
            nlmsg_type: crate::rtnetlink::RTM_GETRULE,
            nlmsg_flags: flags::NLM_F_DUMP,
            nlmsg_seq: 7,
            nlmsg_pid: 8,
        };
        let mut dump_msg = vec![0u8; Nlmsghdr::SIZE + FibRuleHdr::SIZE];
        dump_hdr.write_to(&mut dump_msg[..Nlmsghdr::SIZE]);
        dump_msg[Nlmsghdr::SIZE] = AF_INET;
        let reply = handle_getrule(&dump_hdr, &dump_msg);
        assert!(reply.windows(4).any(|w| w == 12345u32.to_ne_bytes()));
        assert!(reply.windows(4).any(|w| w == 100u32.to_ne_bytes()));

        let (del_hdr, del_msg) = rule_req(crate::rtnetlink::RTM_DELRULE, AF_INET, 12345, 100);
        assert_eq!(ack_errno(&handle_delrule(&del_hdr, &del_msg)), 0);
        assert_eq!(policy_rule::remove(0, AF_INET, Some(12345), Some(100)), 0);
    }

    #[test]
    fn newrule_excl_rejects_duplicate() {
        let (mut hdr, msg) = rule_req(crate::rtnetlink::RTM_NEWRULE, AF_INET6, 22345, 200);
        assert_eq!(ack_errno(&handle_newrule(&hdr, &msg)), 0);
        hdr.nlmsg_flags |= flags::NLM_F_EXCL;
        assert_eq!(ack_errno(&handle_newrule(&hdr, &msg)), -17);
        assert_eq!(policy_rule::remove(0, AF_INET6, Some(22345), Some(200)), 1);
    }

    #[test]
    fn newrule_excl_allows_equal_priority_distinct_rule() {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let owner = crate::netlink_tests::test_namespace();
        let ns = owner.id().as_u64();
        let (first_hdr, first_msg) = rule_req(
            crate::rtnetlink::RTM_NEWRULE, AF_INET, 25322, 1400);
        assert_eq!(ack_errno(&handle_newrule_in(ns, &first_hdr, &first_msg)), 0);
        let (mut second_hdr, second_msg) = rule_req(
            crate::rtnetlink::RTM_NEWRULE, AF_INET, 25322, 1401);
        second_hdr.nlmsg_flags |= flags::NLM_F_EXCL;
        assert_eq!(ack_errno(&handle_newrule_in(ns, &second_hdr, &second_msg)), 0);
        assert_eq!(policy_rule::remove(ns, AF_INET, Some(25322), None), 2);
    }

    #[test]
    fn newrule_replace_does_not_replace_by_priority() {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let owner = crate::netlink_tests::test_namespace();
        let ns = owner.id().as_u64();
        let (first_hdr, first_msg) = rule_req(
            crate::rtnetlink::RTM_NEWRULE, AF_INET, 25323, 1500);
        assert_eq!(ack_errno(&handle_newrule_in(ns, &first_hdr, &first_msg)), 0);
        let (mut second_hdr, second_msg) = rule_req(
            crate::rtnetlink::RTM_NEWRULE, AF_INET, 25323, 1501);
        second_hdr.nlmsg_flags |= flags::NLM_F_REPLACE;
        assert_eq!(ack_errno(&handle_newrule_in(ns, &second_hdr, &second_msg)), 0);
        let rows = policy_rule::snapshot_custom_ns(ns).into_iter()
            .filter(|row| row.family == AF_INET && row.priority == 25323)
            .collect::<Vec<_>>();
        assert_eq!(rows.iter().map(|row| row.table).collect::<Vec<_>>(), vec![1500, 1501]);
        assert_eq!(policy_rule::remove(ns, AF_INET, Some(25323), None), 2);
    }

    #[test]
    fn delrule_removes_one_match_then_reports_enoent() {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let owner = crate::netlink_tests::test_namespace();
        let ns = owner.id().as_u64();
        let (new_hdr, new_msg) = rule_req(
            crate::rtnetlink::RTM_NEWRULE, AF_INET, 25324, 1600);
        assert_eq!(ack_errno(&handle_newrule_in(ns, &new_hdr, &new_msg)), 0);
        assert_eq!(ack_errno(&handle_newrule_in(ns, &new_hdr, &new_msg)), 0);
        let (del_hdr, del_msg) = rule_req(
            crate::rtnetlink::RTM_DELRULE, AF_INET, 25324, 1600);
        assert_eq!(ack_errno(&handle_delrule_in(ns, &del_hdr, &del_msg)), 0);
        assert_eq!(policy_rule::snapshot_custom_ns(ns).into_iter().filter(|row|
            row.family == AF_INET && row.priority == 25324 && row.table == 1600).count(), 1);
        assert_eq!(ack_errno(&handle_delrule_in(ns, &del_hdr, &del_msg)), 0);
        assert_eq!(ack_errno(&handle_delrule_in(ns, &del_hdr, &del_msg)), -2);
    }

    #[test]
    fn explicit_handlers_keep_rules_in_socket_namespace() {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let owner = crate::netlink_tests::test_namespace();
        let ns = owner.id().as_u64();
        let (new_hdr, new_msg) = rule_req(crate::rtnetlink::RTM_NEWRULE, AF_INET, 24321, 1200);
        assert_eq!(ack_errno(&handle_newrule_in(ns, &new_hdr, &new_msg)), 0);
        assert!(policy_rule::snapshot_custom_ns(ns).iter().any(|row|
            row.priority == 24321 && row.table == 1200));
        assert!(!policy_rule::snapshot_custom_ns(0).iter().any(|row|
            row.priority == 24321 && row.table == 1200));
        let (del_hdr, del_msg) = rule_req(crate::rtnetlink::RTM_DELRULE, AF_INET, 24321, 1200);
        assert_eq!(ack_errno(&handle_delrule_in(ns, &del_hdr, &del_msg)), 0);
    }

    #[test]
    fn rule_notifications_are_exact_family_scoped_and_namespace_qualified() {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let owner = crate::netlink_tests::test_namespace();
        let other = crate::netlink_tests::test_namespace();
        let ns = owner.id().as_u64();
        let listener = Arc::new(crate::NetlinkSocket::new(crate::proto::NETLINK_ROUTE, &owner));
        let v6_listener = Arc::new(crate::NetlinkSocket::new(crate::proto::NETLINK_ROUTE, &owner));
        let other_listener = Arc::new(crate::NetlinkSocket::new(crate::proto::NETLINK_ROUTE, &other));
        let _ = listener.add_membership(crate::mcast::grp::RTNLGRP_IPV4_RULE);
        let _ = v6_listener.add_membership(crate::mcast::grp::RTNLGRP_IPV6_RULE);
        let _ = other_listener.add_membership(crate::mcast::grp::RTNLGRP_IPV4_RULE);
        let _ = other_listener.add_membership(crate::mcast::grp::RTNLGRP_IPV6_RULE);
        crate::register_rtnl_listener(&listener);
        crate::register_rtnl_listener(&v6_listener);
        crate::register_rtnl_listener(&other_listener);

        let (new_hdr, new_msg) = rule_req(crate::rtnetlink::RTM_NEWRULE, AF_INET, 26321, 4100);
        assert_eq!(ack_errno(&handle_newrule_in(ns, &new_hdr, &new_msg)), 0);
        let (notification, source) = listener.dequeue().expect("owning namespace notification");
        assert_eq!(source, 0);
        assert_eq!(Nlmsghdr::parse(&notification).unwrap().nlmsg_type,
            crate::rtnetlink::RTM_NEWRULE);
        let (inserted, priority) = parse_rule(ns, &notification).unwrap();
        assert_eq!((inserted.family, inserted.priority, inserted.table), (AF_INET, 26321, 4100));
        assert_eq!(priority, Some(26321));
        assert!(v6_listener.dequeue().is_none());
        assert!(other_listener.dequeue().is_none());

        let (second_hdr, second_msg) = rule_req(
            crate::rtnetlink::RTM_NEWRULE, AF_INET, 26321, 4200);
        assert_eq!(ack_errno(&handle_newrule_in(ns, &second_hdr, &second_msg)), 0);
        let (notification, _) = listener.dequeue().expect("equal-priority insertion notification");
        let (inserted, _) = parse_rule(ns, &notification).unwrap();
        assert_eq!((inserted.priority, inserted.table), (26321, 4200));
        let same_priority = policy_rule::snapshot_custom_ns(ns).into_iter()
            .filter(|row| row.priority == 26321).collect::<Vec<_>>();
        assert_eq!(same_priority.len(), 2);

        let (del_hdr, del_msg) = rule_req(crate::rtnetlink::RTM_DELRULE, AF_INET, 26321, 4200);
        assert_eq!(ack_errno(&handle_delrule_in(ns, &del_hdr, &del_msg)), 0);
        let (notification, _) = listener.dequeue().expect("deletion notification");
        assert_eq!(Nlmsghdr::parse(&notification).unwrap().nlmsg_type,
            crate::rtnetlink::RTM_DELRULE);
        let (removed, _) = parse_rule(ns, &notification).unwrap();
        assert_eq!((removed.family, removed.priority, removed.table), (AF_INET, 26321, 4200));
        assert!(listener.dequeue().is_none());
        assert!(v6_listener.dequeue().is_none());
        assert!(other_listener.dequeue().is_none());

        let (v6_hdr, v6_msg) = rule_req(crate::rtnetlink::RTM_NEWRULE, AF_INET6, 26322, 4300);
        assert_eq!(ack_errno(&handle_newrule_in(ns, &v6_hdr, &v6_msg)), 0);
        let (notification, _) = v6_listener.dequeue().expect("IPv6 rule-group notification");
        let (inserted, _) = parse_rule(ns, &notification).unwrap();
        assert_eq!((inserted.family, inserted.priority, inserted.table), (AF_INET6, 26322, 4300));
        assert!(listener.dequeue().is_none());
        assert!(other_listener.dequeue().is_none());
        let (v6_del_hdr, v6_del_msg) = rule_req(
            crate::rtnetlink::RTM_DELRULE, AF_INET6, 26322, 4300);
        assert_eq!(ack_errno(&handle_delrule_in(ns, &v6_del_hdr, &v6_del_msg)), 0);
        let (notification, _) = v6_listener.dequeue().expect("IPv6 deletion notification");
        assert_eq!(Nlmsghdr::parse(&notification).unwrap().nlmsg_type,
            crate::rtnetlink::RTM_DELRULE);
    }
}
