use super::*;

use alloc::vec;

fn ack_errno(reply: &[u8]) -> i32 {
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
fn unsupported_rule_families_return_eafnosupport() {
    const FAMILY: u8 = 44;
    for typ in [crate::rtnetlink::RTM_NEWRULE, crate::rtnetlink::RTM_DELRULE] {
        let (req, msg) = rule_req(typ, FAMILY, 25325, 1700);
        let reply = if typ == crate::rtnetlink::RTM_NEWRULE {
            handle_newrule(&req, &msg)
        } else {
            handle_delrule(&req, &msg)
        };
        assert_eq!(ack_errno(&reply), -97);
    }
    let (req, msg) = rule_req(crate::rtnetlink::RTM_GETRULE, FAMILY, 0, 0);
    assert_eq!(ack_errno(&handle_getrule(&req, &msg)), -97);
}

#[test]
fn unsupported_rule_selectors_are_rejected_not_published() {
    const NS: u64 = 9235;
    let (req, mut msg) = rule_req(crate::rtnetlink::RTM_NEWRULE, AF_INET, 25321, 1300);
    msg[Nlmsghdr::SIZE + 1] = 24;
    assert_eq!(ack_errno(&handle_newrule_in(NS, &req, &msg)), -95);
    assert!(!policy_rule::snapshot_custom_ns(NS).iter().any(|row| row.priority == 25321));
}

#[test]
fn malformed_trailing_rule_attrs_are_atomic() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let owner = crate::netlink_tests::test_namespace();
    let ns = owner.id().as_u64();
    let (new_req, mut malformed_new) = rule_req(
        crate::rtnetlink::RTM_NEWRULE, AF_INET, 25326, 1800);
    malformed_new.push(0xaa);
    assert_eq!(ack_errno(&handle_newrule_in(ns, &new_req, &malformed_new)), -22);
    assert!(!policy_rule::snapshot_custom_ns(ns).iter().any(|row| {
        row.family == AF_INET && row.priority == 25326 && row.table == 1800
    }));

    let (new_req, new_msg) = rule_req(
        crate::rtnetlink::RTM_NEWRULE, AF_INET, 25326, 1800);
    assert_eq!(ack_errno(&handle_newrule_in(ns, &new_req, &new_msg)), 0);
    let (del_req, mut malformed_del) = rule_req(
        crate::rtnetlink::RTM_DELRULE, AF_INET, 25326, 1800);
    malformed_del.push(0xbb);
    assert_eq!(ack_errno(&handle_delrule_in(ns, &del_req, &malformed_del)), -22);
    assert!(policy_rule::snapshot_custom_ns(ns).iter().any(|row| {
        row.family == AF_INET && row.priority == 25326 && row.table == 1800
    }));
    assert_eq!(policy_rule::remove(ns, AF_INET, Some(25326), Some(1800)), 1);
}

#[test]
fn delrule_removes_stored_builtin_rule() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let owner = crate::netlink_tests::test_namespace();
    let ns = owner.id().as_u64();
    let stack = net::global_stack();
    assert!(stack.policy_rules().snapshot_effective(ns, AF_INET).iter().any(|row| {
        row.priority == 32766 && row.table == net::policy_rule::RT_TABLE_MAIN
    }));
    let (req, msg) = rule_req(crate::rtnetlink::RTM_DELRULE, AF_INET,
        32766, net::policy_rule::RT_TABLE_MAIN);
    assert_eq!(ack_errno(&handle_delrule_in(ns, &req, &msg)), 0);
    assert!(!stack.policy_rules().snapshot_effective(ns, AF_INET).iter().any(|row| {
        row.priority == 32766 && row.table == net::policy_rule::RT_TABLE_MAIN
    }));
}

#[test]
fn delrule_header_and_attributes_are_exact_selectors() {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let owner = crate::netlink_tests::test_namespace();
    let ns = owner.id().as_u64();
    let priority = 25327;
    let table = 1900;
    let (new_req, new_msg) = rule_req(crate::rtnetlink::RTM_NEWRULE, AF_INET, priority, table);
    assert_eq!(ack_errno(&handle_newrule_in(ns, &new_req, &new_msg)), 0);

    for (offset, bytes) in [
        (1usize, vec![1]), (2, vec![1]), (3, vec![1]), (7, vec![0]), (7, vec![2]),
        (8, 1u32.to_ne_bytes().to_vec()),
    ] {
        let (req, mut msg) = rule_req(crate::rtnetlink::RTM_DELRULE, AF_INET, priority, table);
        let start = Nlmsghdr::SIZE + offset;
        msg[start..start + bytes.len()].copy_from_slice(&bytes);
        assert_eq!(ack_errno(&handle_delrule_in(ns, &req, &msg)), -2);
        assert!(policy_rule::snapshot_custom_ns(ns).iter().any(|row| {
            row.family == AF_INET && row.priority == priority && row.table == table
        }));
    }
    let (wrong_req, wrong_msg) = rule_req(
        crate::rtnetlink::RTM_DELRULE, AF_INET, priority, table + 1);
    assert_eq!(ack_errno(&handle_delrule_in(ns, &wrong_req, &wrong_msg)), -2);
    let (del_req, del_msg) = rule_req(crate::rtnetlink::RTM_DELRULE, AF_INET, priority, table);
    assert_eq!(ack_errno(&handle_delrule_in(ns, &del_req, &del_msg)), 0);
}
