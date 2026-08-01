// The discovery path: what `genl_ctrl_resolve` and `genl_ctrl_grp_by_id` see.

extern crate alloc;

use alloc::vec::Vec;

use super::harness::*;
use crate::genetlink::{attr, dispatch, family};
use crate::genetlink::uapi::*;

/// Attribute bytes naming a family by name.
fn by_name(name: &str) -> Vec<u8> {
    let mut a = Vec::new();
    attr::put_str(&mut a, ctrl_attr::CTRL_ATTR_FAMILY_NAME, name);
    a
}

/// Attribute bytes naming a family by id.
fn by_id(id: u16) -> Vec<u8> {
    let mut a = Vec::new();
    attr::put_u16(&mut a, ctrl_attr::CTRL_ATTR_FAMILY_ID, id);
    a
}

fn getfamily(attrs: &[u8]) -> Vec<u8> {
    boot();
    dispatch::handle(
        &request(GENL_ID_CTRL, ctrl_cmd::CTRL_CMD_GETFAMILY, crate::flags::NLM_F_REQUEST, 7, attrs),
        crate::genetlink::mcast::initial_net_ns(), root())
}

/// Walk a `CTRL_ATTR_MCAST_GROUPS` nest into (name, id) pairs.
fn mcast_groups(attrs: &[u8]) -> Vec<(alloc::string::String, u32)> {
    let mut out = Vec::new();
    let Some(nest) = attr::find(attrs, ctrl_attr::CTRL_ATTR_MCAST_GROUPS) else { return out; };
    for one in attr::parse(nest.payload) {
        let mut name = None;
        let mut id = None;
        for field in attr::parse(one.payload) {
            match field.ty {
                ctrl_attr_mcast_grp::CTRL_ATTR_MCAST_GRP_NAME =>
                    name = field.nul_str().map(alloc::string::String::from),
                ctrl_attr_mcast_grp::CTRL_ATTR_MCAST_GRP_ID => id = field.payload.get(..4)
                    .map(|b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]])),
                _ => {}
            }
        }
        if let (Some(name), Some(id)) = (name, id) { out.push((name, id)); }
    }
    out
}

/// Walk a `CTRL_ATTR_OPS` nest into (cmd, flags) pairs.
fn ops(attrs: &[u8]) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let Some(nest) = attr::find(attrs, ctrl_attr::CTRL_ATTR_OPS) else { return out; };
    for one in attr::parse(nest.payload) {
        let mut cmd = None;
        let mut flags = None;
        for field in attr::parse(one.payload) {
            let v = field.payload.get(..4)
                .map(|b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]));
            match field.ty {
                ctrl_attr_op::CTRL_ATTR_OP_ID    => cmd = v,
                ctrl_attr_op::CTRL_ATTR_OP_FLAGS => flags = v,
                _ => {}
            }
        }
        if let (Some(cmd), Some(flags)) = (cmd, flags) { out.push((cmd, flags)); }
    }
    out
}

fn u32_attr(attrs: &[u8], ty: u16) -> Option<u32> {
    attr::find(attrs, ty).and_then(|a| a.payload.get(..4))
        .map(|b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
}

#[test]
fn resolving_a_family_by_name_returns_its_id_version_and_groups() {
    let fam = register_test_family("resolve", Vec::new(), 2);
    let reply = getfamily(&by_name(&fam.name));
    assert_eq!(reply_cmd(&reply), Some(ctrl_cmd::CTRL_CMD_NEWFAMILY));
    let attrs = reply_attrs(&reply);
    assert_eq!(attr::find(attrs, ctrl_attr::CTRL_ATTR_FAMILY_NAME).unwrap().nul_str(),
        Some(fam.name.as_str()));
    assert_eq!(attr::find(attrs, ctrl_attr::CTRL_ATTR_FAMILY_ID).unwrap().u16(), Some(fam.id));
    assert_eq!(u32_attr(attrs, ctrl_attr::CTRL_ATTR_VERSION), Some(1));
    assert_eq!(u32_attr(attrs, ctrl_attr::CTRL_ATTR_HDRSIZE), Some(0));
    assert_eq!(u32_attr(attrs, ctrl_attr::CTRL_ATTR_MAXATTR), Some(4));
    let groups = mcast_groups(attrs);
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0], (alloc::string::String::from("g0"), fam.mcgrp_offset));
    assert_eq!(groups[1], (alloc::string::String::from("g1"), fam.mcgrp_offset + 1));
}

#[test]
fn resolving_by_id_matches_resolving_by_name() {
    let fam = register_test_family("byid", Vec::new(), 1);
    let named = getfamily(&by_name(&fam.name));
    let numbered = getfamily(&by_id(fam.id));
    assert_eq!(named, numbered);
}

#[test]
fn resolving_an_unregistered_family_is_enoent_and_naming_none_is_einval() {
    boot();
    assert_eq!(reply_errno(&getfamily(&by_name("oxide-t-absent"))),
        Some(syscall::errno::Errno::Enoent.as_i32()));
    assert_eq!(reply_errno(&getfamily(&by_id(GENL_MAX_ID))),
        Some(syscall::errno::Errno::Enoent.as_i32()));
    assert_eq!(reply_errno(&getfamily(&[])), Some(syscall::errno::Errno::Einval.as_i32()));
}

#[test]
fn the_controller_describes_itself_with_its_ops_and_notify_group() {
    boot();
    let reply = getfamily(&by_name(CTRL_FAMILY_NAME));
    let attrs = reply_attrs(&reply);
    assert_eq!(attr::find(attrs, ctrl_attr::CTRL_ATTR_FAMILY_ID).unwrap().u16(),
        Some(GENL_ID_CTRL));
    assert_eq!(u32_attr(attrs, ctrl_attr::CTRL_ATTR_VERSION), Some(CTRL_VERSION as u32));
    assert_eq!(mcast_groups(attrs),
        alloc::vec![(alloc::string::String::from(CTRL_GROUP_NOTIFY), GENL_ID_CTRL as u32)]);
    let ops = ops(attrs);
    let getfamily_op = ops.iter().find(|(cmd, _)| *cmd == ctrl_cmd::CTRL_CMD_GETFAMILY as u32)
        .expect("nlctrl must advertise CTRL_CMD_GETFAMILY");
    // GETFAMILY serves both a lookup and a dump, and carries a policy.
    assert_ne!(getfamily_op.1 & op_flags::GENL_CMD_CAP_DO, 0);
    assert_ne!(getfamily_op.1 & op_flags::GENL_CMD_CAP_DUMP, 0);
    assert_ne!(getfamily_op.1 & op_flags::GENL_CMD_CAP_HASPOL, 0);
    let policy_op = ops.iter().find(|(cmd, _)| *cmd == ctrl_cmd::CTRL_CMD_GETPOLICY as u32)
        .expect("nlctrl must advertise CTRL_CMD_GETPOLICY");
    assert_eq!(policy_op.1 & op_flags::GENL_CMD_CAP_DO, 0);
    assert_ne!(policy_op.1 & op_flags::GENL_CMD_CAP_DUMP, 0);
}

#[test]
fn the_quota_family_advertises_its_events_group() {
    boot();
    let reply = getfamily(&by_name(crate::genetlink::quota::QUOTA_FAMILY_NAME));
    let attrs = reply_attrs(&reply);
    assert_eq!(attr::find(attrs, ctrl_attr::CTRL_ATTR_FAMILY_ID).unwrap().u16(),
        Some(GENL_ID_VFS_DQUOT));
    assert_eq!(u32_attr(attrs, ctrl_attr::CTRL_ATTR_MAXATTR),
        Some(crate::genetlink::quota::quota_nl_attr::QUOTA_NL_A_MAX as u32));
    assert_eq!(mcast_groups(attrs), alloc::vec![(
        alloc::string::String::from(crate::genetlink::quota::QUOTA_GROUP_EVENTS),
        GENL_ID_VFS_DQUOT as u32)]);
}

#[test]
fn a_dump_lists_every_family_and_ends_with_nlmsg_done() {
    let fam = register_test_family("dumped", Vec::new(), 1);
    let reply = dispatch::handle(
        &request(GENL_ID_CTRL, ctrl_cmd::CTRL_CMD_GETFAMILY,
            crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_DUMP, 3, &[]),
        crate::genetlink::mcast::initial_net_ns(), root());
    let msgs = split_messages(&reply);
    let last = crate::Nlmsghdr::parse(msgs.last().unwrap()).unwrap();
    assert_eq!(last.nlmsg_type, crate::msg::NLMSG_DONE);
    let mut names = Vec::new();
    for m in &msgs[..msgs.len() - 1] {
        let hdr = crate::Nlmsghdr::parse(m).unwrap();
        assert_eq!(hdr.nlmsg_flags & crate::flags::NLM_F_MULTI, crate::flags::NLM_F_MULTI);
        assert_eq!(reply_cmd(m), Some(ctrl_cmd::CTRL_CMD_NEWFAMILY));
        names.push(alloc::string::String::from(
            attr::find(reply_attrs(m), ctrl_attr::CTRL_ATTR_FAMILY_NAME).unwrap()
                .nul_str().unwrap()));
    }
    assert!(names.iter().any(|n| n == CTRL_FAMILY_NAME));
    assert!(names.iter().any(|n| n == crate::genetlink::quota::QUOTA_FAMILY_NAME));
    assert!(names.contains(&fam.name));
}

#[test]
fn registering_a_family_announces_it_on_the_controller_notify_group() {
    boot();
    // Registration announcements cross every namespace, so no other test may
    // register while this watcher is armed.
    let _serial = crate::test_serial::genl();
    let ns = crate::netlink_tests::test_namespace();
    let watcher = subscriber(&ns, GENL_ID_CTRL as u32);
    let fam = register_unserialised("announce", Vec::new(), 1);

    let new_family = recv(&watcher).expect("CTRL_CMD_NEWFAMILY must be broadcast");
    assert_eq!(reply_cmd(&new_family), Some(ctrl_cmd::CTRL_CMD_NEWFAMILY));
    assert_eq!(attr::find(reply_attrs(&new_family), ctrl_attr::CTRL_ATTR_FAMILY_NAME)
        .unwrap().nul_str(), Some(fam.name.as_str()));

    let new_group = recv(&watcher).expect("CTRL_CMD_NEWMCAST_GRP must be broadcast");
    assert_eq!(reply_cmd(&new_group), Some(ctrl_cmd::CTRL_CMD_NEWMCAST_GRP));
    assert_eq!(mcast_groups(reply_attrs(&new_group)),
        alloc::vec![(alloc::string::String::from("g0"), fam.mcgrp_offset)]);

    family::unregister_family(fam.id).unwrap();
    let del_group = recv(&watcher).expect("CTRL_CMD_DELMCAST_GRP must be broadcast");
    assert_eq!(reply_cmd(&del_group), Some(ctrl_cmd::CTRL_CMD_DELMCAST_GRP));
    let del_family = recv(&watcher).expect("CTRL_CMD_DELFAMILY must be broadcast");
    assert_eq!(reply_cmd(&del_family), Some(ctrl_cmd::CTRL_CMD_DELFAMILY));
}

#[test]
fn a_policy_dump_maps_each_command_to_its_attribute_table() {
    boot();
    let reply = dispatch::handle(
        &request(GENL_ID_CTRL, ctrl_cmd::CTRL_CMD_GETPOLICY,
            crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_DUMP, 9,
            &by_name(CTRL_FAMILY_NAME)),
        crate::genetlink::mcast::initial_net_ns(), root());
    let msgs = split_messages(&reply);
    assert_eq!(crate::Nlmsghdr::parse(msgs.last().unwrap()).unwrap().nlmsg_type,
        crate::msg::NLMSG_DONE);
    let map = reply_attrs(msgs[0]);
    assert_eq!(attr::find(map, ctrl_attr::CTRL_ATTR_FAMILY_ID).unwrap().u16(),
        Some(GENL_ID_CTRL));
    let op_policy = attr::find(map, ctrl_attr::CTRL_ATTR_OP_POLICY).unwrap();
    let cmds: Vec<u16> = attr::parse(op_policy.payload).map(|a| a.ty).collect();
    assert!(cmds.contains(&(ctrl_cmd::CTRL_CMD_GETFAMILY as u16)));
    // The GETFAMILY table names both resolution attributes and their types.
    let table = attr::find(reply_attrs(msgs[1]), ctrl_attr::CTRL_ATTR_POLICY).unwrap();
    let inner = attr::parse(table.payload).next().unwrap();
    let entries: Vec<u16> = attr::parse(inner.payload).map(|a| a.ty).collect();
    assert!(entries.contains(&ctrl_attr::CTRL_ATTR_FAMILY_ID));
    assert!(entries.contains(&ctrl_attr::CTRL_ATTR_FAMILY_NAME));
    let name_entry = attr::parse(inner.payload)
        .find(|a| a.ty == ctrl_attr::CTRL_ATTR_FAMILY_NAME).unwrap();
    assert_eq!(u32_attr(name_entry.payload, policy_attr::NL_POLICY_TYPE_ATTR_TYPE),
        Some(policy_type::NL_ATTR_TYPE_NUL_STRING));
    assert_eq!(u32_attr(name_entry.payload, policy_attr::NL_POLICY_TYPE_ATTR_MAX_LENGTH),
        Some(GENL_NAMSIZ as u32 - 1));
}
