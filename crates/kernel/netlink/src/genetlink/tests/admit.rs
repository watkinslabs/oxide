// Request admission: which failure a client sees, and in which order.

extern crate alloc;

use alloc::vec::Vec;

use syscall::errno::Errno;

use super::harness::*;
use crate::genetlink::dispatch;
use crate::genetlink::family::GenlOp;
use crate::genetlink::uapi::*;
use crate::flags;

fn init_ns() -> u64 { crate::genetlink::mcast::initial_net_ns() }

#[test]
fn an_unregistered_family_id_is_enoent() {
    boot();
    let reply = dispatch::handle(
        &request(GENL_MAX_ID, 1, flags::NLM_F_REQUEST, 1, &[]), init_ns(), root());
    assert_eq!(reply_errno(&reply), Some(Errno::Enoent.as_i32()));
}

#[test]
fn a_registered_family_without_that_command_is_eopnotsupp() {
    let fam = register_test_family("nocmd", Vec::new(), 0);
    let reply = dispatch::handle(
        &request(fam.id, 1, flags::NLM_F_REQUEST, 1, &[]), init_ns(), root());
    assert_eq!(reply_errno(&reply), Some(Errno::Eopnotsupp.as_i32()));
}

#[test]
fn a_do_only_command_refuses_a_dump_and_the_reverse() {
    let fam = register_test_family("split", alloc::vec![
        GenlOp { cmd: 1, flags: op_flags::GENL_CMD_CAP_DO,   policy: &[] },
        GenlOp { cmd: 2, flags: op_flags::GENL_CMD_CAP_DUMP, policy: &[] },
    ], 0);
    let dump = flags::NLM_F_REQUEST | flags::NLM_F_DUMP;
    assert_eq!(reply_errno(&dispatch::handle(
        &request(fam.id, 1, dump, 1, &[]), init_ns(), root())), Some(Errno::Eopnotsupp.as_i32()));
    assert_eq!(reply_errno(&dispatch::handle(
        &request(fam.id, 2, flags::NLM_F_REQUEST, 1, &[]), init_ns(), root())),
        Some(Errno::Eopnotsupp.as_i32()));
}

#[test]
fn admin_perm_is_checked_only_after_the_command_exists() {
    let fam = register_test_family("perm", alloc::vec![
        GenlOp { cmd: 1, flags: op_flags::GENL_CMD_CAP_DO | op_flags::GENL_ADMIN_PERM,
                 policy: &[] },
    ], 0);
    // An unprivileged caller naming a command the family does NOT have still
    // sees EOPNOTSUPP — the permission ladder never runs for a missing op.
    assert_eq!(reply_errno(&dispatch::handle(
        &request(fam.id, 9, flags::NLM_F_REQUEST, 1, &[]), init_ns(), unprivileged())),
        Some(Errno::Eopnotsupp.as_i32()));
    assert_eq!(reply_errno(&dispatch::handle(
        &request(fam.id, 1, flags::NLM_F_REQUEST, 1, &[]), init_ns(), unprivileged())),
        Some(Errno::Eperm.as_i32()));
}

#[test]
fn uns_admin_perm_accepts_the_socket_namespace_capability() {
    let fam = register_test_family("unsperm", alloc::vec![
        GenlOp { cmd: 1, flags: op_flags::GENL_CMD_CAP_DO | op_flags::GENL_UNS_ADMIN_PERM,
                 policy: &[] },
    ], 0);
    let ns_only = crate::genetlink::GenlCred { init_ns_net_admin: false, sock_ns_net_admin: true };
    // Passing the ladder leaves the request at "no in-kernel handler", not EPERM.
    assert_eq!(reply_errno(&dispatch::handle(
        &request(fam.id, 1, flags::NLM_F_REQUEST, 1, &[]), init_ns(), ns_only)),
        Some(Errno::Eopnotsupp.as_i32()));
    assert_eq!(reply_errno(&dispatch::handle(
        &request(fam.id, 1, flags::NLM_F_REQUEST, 1, &[]), init_ns(), unprivileged())),
        Some(Errno::Eperm.as_i32()));
}

#[test]
fn init_ns_admin_perm_is_not_satisfied_by_the_socket_namespace_alone() {
    let fam = register_test_family("initperm", alloc::vec![
        GenlOp { cmd: 1, flags: op_flags::GENL_CMD_CAP_DO | op_flags::GENL_ADMIN_PERM,
                 policy: &[] },
    ], 0);
    let ns_only = crate::genetlink::GenlCred { init_ns_net_admin: false, sock_ns_net_admin: true };
    assert_eq!(reply_errno(&dispatch::handle(
        &request(fam.id, 1, flags::NLM_F_REQUEST, 1, &[]), init_ns(), ns_only)),
        Some(Errno::Eperm.as_i32()));
}

#[test]
fn a_truncated_message_is_einval_before_the_command_lookup() {
    let fam = register_test_family("short", alloc::vec![
        GenlOp { cmd: 1, flags: op_flags::GENL_CMD_CAP_DO, policy: &[] },
    ], 0);
    // A netlink header with no family header behind it.
    let mut truncated: Vec<u8> = alloc::vec![0u8; crate::Nlmsghdr::SIZE];
    crate::Nlmsghdr {
        nlmsg_len: crate::Nlmsghdr::SIZE as u32, nlmsg_type: fam.id,
        nlmsg_flags: flags::NLM_F_REQUEST, nlmsg_seq: 1, nlmsg_pid: 0,
    }.write_to(&mut truncated);
    assert_eq!(reply_errno(&dispatch::handle(&truncated, init_ns(), root())),
        Some(Errno::Einval.as_i32()));
}

#[test]
fn a_family_header_declaring_more_than_the_message_holds_is_einval() {
    boot();
    let fam = crate::genetlink::family::register_family(
        crate::genetlink::family::GenlFamilySpec {
            name: "oxide-t-hdrsize", version: 1, hdrsize: 8, maxattr: 0,
            ops: alloc::vec![GenlOp { cmd: 1, flags: op_flags::GENL_CMD_CAP_DO, policy: &[] }],
            mcgrps: Vec::new(), netnsok: true, resv_start_op: 0,
        }).unwrap();
    // The message carries nlmsghdr + genlmsghdr but not the family's 8-byte
    // private header.
    let msg = request(fam, 1, flags::NLM_F_REQUEST, 1, &[]);
    assert_eq!(reply_errno(&dispatch::handle(&msg, init_ns(), root())),
        Some(Errno::Einval.as_i32()));
    // With the private header present the request reaches command dispatch.
    let msg = request(fam, 1, flags::NLM_F_REQUEST, 1, &[0u8; 8]);
    assert_eq!(reply_errno(&dispatch::handle(&msg, init_ns(), root())),
        Some(Errno::Eopnotsupp.as_i32()));
    crate::genetlink::family::unregister_family(fam).unwrap();
}

#[test]
fn a_strictly_validated_command_rejects_a_dirty_reserved_field() {
    let fam = register_test_family("strict", alloc::vec![
        GenlOp { cmd: 4, flags: op_flags::GENL_CMD_CAP_DO, policy: &[] },
    ], 0);
    let mut msg = request(fam.id, 4, flags::NLM_F_REQUEST, 1, &[]);
    // genlmsghdr.reserved is the two bytes after cmd/version.
    msg[crate::Nlmsghdr::SIZE + 2] = 1;
    assert_eq!(reply_errno(&dispatch::handle(&msg, init_ns(), root())),
        Some(Errno::Einval.as_i32()));
}

#[test]
fn the_controller_still_accepts_legacy_flags_below_its_reserved_start() {
    boot();
    // CTRL_CMD_GETFAMILY predates strict validation, so an old client setting
    // extra flags and a dirty reserved field must still be served.
    let mut attrs = Vec::new();
    crate::genetlink::attr::put_str(&mut attrs, ctrl_attr::CTRL_ATTR_FAMILY_NAME,
        CTRL_FAMILY_NAME);
    let mut msg = request(GENL_ID_CTRL, ctrl_cmd::CTRL_CMD_GETFAMILY,
        flags::NLM_F_REQUEST | flags::NLM_F_ROOT, 1, &attrs);
    msg[crate::Nlmsghdr::SIZE + 2] = 0xFF;
    assert_eq!(reply_cmd(&dispatch::handle(&msg, init_ns(), root())),
        Some(ctrl_cmd::CTRL_CMD_NEWFAMILY));
}

#[test]
fn a_family_outside_its_namespace_does_not_exist() {
    boot();
    let ns = crate::netlink_tests::test_namespace().id().as_u64();
    // VFS_DQUOT is not namespace-aware: it is reachable only from init_net.
    let mut attrs = Vec::new();
    crate::genetlink::attr::put_u16(&mut attrs, ctrl_attr::CTRL_ATTR_FAMILY_ID,
        GENL_ID_VFS_DQUOT);
    let msg = request(GENL_ID_CTRL, ctrl_cmd::CTRL_CMD_GETFAMILY, flags::NLM_F_REQUEST, 1, &attrs);
    assert_eq!(reply_errno(&dispatch::handle(&msg, ns, root())), Some(Errno::Enoent.as_i32()));
    assert_eq!(reply_cmd(&dispatch::handle(&msg, init_ns(), root())),
        Some(ctrl_cmd::CTRL_CMD_NEWFAMILY));
}

#[test]
fn a_successful_request_acknowledges_only_when_asked() {
    boot();
    let mut attrs = Vec::new();
    crate::genetlink::attr::put_str(&mut attrs, ctrl_attr::CTRL_ATTR_FAMILY_NAME,
        CTRL_FAMILY_NAME);
    let plain = dispatch::handle(
        &request(GENL_ID_CTRL, ctrl_cmd::CTRL_CMD_GETFAMILY, flags::NLM_F_REQUEST, 1, &attrs),
        init_ns(), root());
    assert_eq!(split_messages(&plain).len(), 1);
    let acked = dispatch::handle(
        &request(GENL_ID_CTRL, ctrl_cmd::CTRL_CMD_GETFAMILY,
            flags::NLM_F_REQUEST | flags::NLM_F_ACK, 1, &attrs),
        init_ns(), root());
    let msgs = split_messages(&acked);
    assert_eq!(msgs.len(), 2);
    assert_eq!(reply_errno(msgs[1]), Some(0));
}
