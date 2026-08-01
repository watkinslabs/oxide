// The `nlctrl` controller family (id `GENL_ID_CTRL`).
//
// Every genetlink client starts here: it resolves a family NAME to the id it
// must put in `nlmsg_type`, and learns that family's multicast-group ids so it
// can subscribe. Registration and removal of any family are announced on
// nlctrl's own `notify` group so long-lived clients track the id space.

extern crate alloc;

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::Nlmsghdr;
use super::attr;
use super::family::{self, GenlFamily, GenlFamilySpec, GenlOp, PolicyEntry};
use super::mcast;
use super::message;
use super::uapi::*;

/// `CTRL_CMD_GETFAMILY` attribute policy: resolve by id or by name.
const CTRL_POLICY_FAMILY: &[PolicyEntry] = &[
    PolicyEntry { attr: ctrl_attr::CTRL_ATTR_FAMILY_ID, kind: policy_type::NL_ATTR_TYPE_U16,
                  min_len: 0, max_len: 0 },
    PolicyEntry { attr: ctrl_attr::CTRL_ATTR_FAMILY_NAME,
                  kind: policy_type::NL_ATTR_TYPE_NUL_STRING,
                  min_len: 0, max_len: (GENL_NAMSIZ - 1) as u32 },
];

/// `CTRL_CMD_GETPOLICY` attribute policy.
const CTRL_POLICY_POLICY: &[PolicyEntry] = &[
    PolicyEntry { attr: ctrl_attr::CTRL_ATTR_FAMILY_ID, kind: policy_type::NL_ATTR_TYPE_U16,
                  min_len: 0, max_len: 0 },
    PolicyEntry { attr: ctrl_attr::CTRL_ATTR_FAMILY_NAME,
                  kind: policy_type::NL_ATTR_TYPE_NUL_STRING,
                  min_len: 0, max_len: (GENL_NAMSIZ - 1) as u32 },
    PolicyEntry { attr: ctrl_attr::CTRL_ATTR_OP, kind: policy_type::NL_ATTR_TYPE_U32,
                  min_len: 0, max_len: 0 },
];

/// Group INDEX of nlctrl's `notify` group within its own group table.
const CTRL_NOTIFY_INDEX: usize = 0;

/// Register `nlctrl` itself. Must run before any other family so the
/// registration announcements have a controller to travel on. # C: O(1)
pub fn register() -> Result<u16, family::GenlRegError> {
    family::register_family(GenlFamilySpec {
        name:    CTRL_FAMILY_NAME,
        version: CTRL_VERSION,
        hdrsize: 0,
        maxattr: ctrl_attr::CTRL_ATTR_MAX,
        ops: alloc::vec![
            GenlOp {
                cmd:    ctrl_cmd::CTRL_CMD_GETFAMILY,
                flags:  op_flags::GENL_CMD_CAP_DO | op_flags::GENL_CMD_CAP_DUMP,
                policy: CTRL_POLICY_FAMILY,
            },
            GenlOp {
                cmd:    ctrl_cmd::CTRL_CMD_GETPOLICY,
                flags:  op_flags::GENL_CMD_CAP_DUMP,
                policy: CTRL_POLICY_POLICY,
            },
        ],
        mcgrps:  alloc::vec![CTRL_GROUP_NOTIFY],
        netnsok: true,
        resv_start_op: CTRL_RESV_START_OP,
    })
}

/// The registered controller family. # C: O(N families)
pub fn ctrl_family() -> Option<GenlFamily> { family::find_by_id(GENL_ID_CTRL) }

// ---- reply builders -----------------------------------------------------

/// `ctrl_fill_info`: one `CTRL_CMD_NEWFAMILY`/`DELFAMILY` message describing a
/// family, including its op table and multicast groups. # C: O(ops + groups)
pub fn build_family_msg(fam: &GenlFamily, portid: u32, seq: u32, cmd: u8) -> Vec<u8> {
    let mut out = message::start(portid, seq, GENL_ID_CTRL, CTRL_VERSION, 0, cmd);
    attr::put_str(&mut out, ctrl_attr::CTRL_ATTR_FAMILY_NAME, &fam.name);
    attr::put_u16(&mut out, ctrl_attr::CTRL_ATTR_FAMILY_ID, fam.id);
    attr::put_u32(&mut out, ctrl_attr::CTRL_ATTR_VERSION, fam.version as u32);
    attr::put_u32(&mut out, ctrl_attr::CTRL_ATTR_HDRSIZE, fam.hdrsize as u32);
    attr::put_u32(&mut out, ctrl_attr::CTRL_ATTR_MAXATTR, fam.maxattr as u32);
    if !fam.ops.is_empty() {
        let ops_nest = attr::nest_start(&mut out, ctrl_attr::CTRL_ATTR_OPS);
        for (i, op) in fam.ops.iter().enumerate() {
            // Ops are nested under a 1-based INDEX, not under their command id.
            let one = attr::nest_start(&mut out, (i + 1) as u16);
            let mut flags = op.flags;
            if !op.policy.is_empty() { flags |= op_flags::GENL_CMD_CAP_HASPOL; }
            attr::put_u32(&mut out, ctrl_attr_op::CTRL_ATTR_OP_ID, op.cmd as u32);
            attr::put_u32(&mut out, ctrl_attr_op::CTRL_ATTR_OP_FLAGS, flags);
            attr::nest_end(&mut out, one);
        }
        attr::nest_end(&mut out, ops_nest);
    }
    if !fam.mcgrps.is_empty() {
        let grps_nest = attr::nest_start(&mut out, ctrl_attr::CTRL_ATTR_MCAST_GROUPS);
        for (i, grp) in fam.mcgrps.iter().enumerate() {
            let one = attr::nest_start(&mut out, (i + 1) as u16);
            attr::put_u32(&mut out, ctrl_attr_mcast_grp::CTRL_ATTR_MCAST_GRP_ID, grp.id);
            attr::put_str(&mut out, ctrl_attr_mcast_grp::CTRL_ATTR_MCAST_GRP_NAME, &grp.name);
            attr::nest_end(&mut out, one);
        }
        attr::nest_end(&mut out, grps_nest);
    }
    message::end(&mut out, 0);
    out
}

/// `ctrl_fill_mcgrp_info`: a `CTRL_CMD_NEWMCAST_GRP`/`DELMCAST_GRP` message
/// naming ONE group of a family. # C: O(1)
pub fn build_mcgrp_msg(
    fam: &GenlFamily, index: usize, portid: u32, seq: u32, cmd: u8,
) -> Option<Vec<u8>> {
    let grp = fam.mcgrps.get(index)?;
    let mut out = message::start(portid, seq, GENL_ID_CTRL, CTRL_VERSION, 0, cmd);
    attr::put_str(&mut out, ctrl_attr::CTRL_ATTR_FAMILY_NAME, &fam.name);
    attr::put_u16(&mut out, ctrl_attr::CTRL_ATTR_FAMILY_ID, fam.id);
    let grps_nest = attr::nest_start(&mut out, ctrl_attr::CTRL_ATTR_MCAST_GROUPS);
    let one = attr::nest_start(&mut out, 1);
    attr::put_u32(&mut out, ctrl_attr_mcast_grp::CTRL_ATTR_MCAST_GRP_ID, grp.id);
    attr::put_str(&mut out, ctrl_attr_mcast_grp::CTRL_ATTR_MCAST_GRP_NAME, &grp.name);
    attr::nest_end(&mut out, one);
    attr::nest_end(&mut out, grps_nest);
    message::end(&mut out, 0);
    Some(out)
}

// ---- controller events --------------------------------------------------

/// Broadcast one controller event on nlctrl's `notify` group. A family that is
/// not namespace-aware only announces into the initial namespace.
/// # C: O(N_listeners)
fn notify(fam_netnsok: bool, body: Vec<u8>) {
    let Some(ctrl) = ctrl_family() else { return; };
    let _ = if fam_netnsok {
        mcast::genlmsg_multicast_allns(&ctrl, CTRL_NOTIFY_INDEX, &body, 0)
    } else {
        mcast::genlmsg_multicast_netns(&ctrl, mcast::initial_net_ns(), CTRL_NOTIFY_INDEX, &body, 0)
    };
}

/// `CTRL_CMD_NEWFAMILY` + one `CTRL_CMD_NEWMCAST_GRP` per group, as emitted at
/// the end of a successful registration. # C: O(groups × N_listeners)
pub fn announce_new_family(fam: &GenlFamily) {
    notify(fam.netnsok, build_family_msg(fam, 0, 0, ctrl_cmd::CTRL_CMD_NEWFAMILY));
    for i in 0..fam.mcgrps.len() {
        if let Some(body) = build_mcgrp_msg(fam, i, 0, 0, ctrl_cmd::CTRL_CMD_NEWMCAST_GRP) {
            notify(fam.netnsok, body);
        }
    }
}

/// One `CTRL_CMD_DELMCAST_GRP` per group then `CTRL_CMD_DELFAMILY`, as emitted
/// while unregistering. # C: O(groups × N_listeners)
pub fn announce_del_family(fam: &GenlFamily) {
    for i in 0..fam.mcgrps.len() {
        if let Some(body) = build_mcgrp_msg(fam, i, 0, 0, ctrl_cmd::CTRL_CMD_DELMCAST_GRP) {
            notify(fam.netnsok, body);
        }
    }
    notify(fam.netnsok, build_family_msg(fam, 0, 0, ctrl_cmd::CTRL_CMD_DELFAMILY));
}

// ---- command handlers ---------------------------------------------------

/// Resolve the family a request names, by id and/or by name. Naming neither is
/// `EINVAL`; naming one that does not exist is `ENOENT`. # C: O(N families)
pub fn resolve(attrs: &[u8]) -> Result<GenlFamily, Errno> {
    let mut found: Option<GenlFamily> = None;
    let mut named = false;
    if let Some(a) = attr::find(attrs, ctrl_attr::CTRL_ATTR_FAMILY_ID) {
        named = true;
        found = a.u16().and_then(family::find_by_id);
    }
    if let Some(a) = attr::find(attrs, ctrl_attr::CTRL_ATTR_FAMILY_NAME) {
        named = true;
        found = a.nul_str().and_then(family::find_by_name);
    }
    if !named { return Err(Errno::Einval); }
    found.ok_or(Errno::Enoent)
}

/// `ctrl_getfamily`: reply with the named family's full description.
/// # C: O(N families)
pub fn getfamily(req: &Nlmsghdr, attrs: &[u8], net_ns: u64) -> Vec<u8> {
    let fam = match resolve(attrs) {
        Ok(f) => f,
        Err(e) => return message::error(req, Err(e)),
    };
    // A family that is not namespace-aware does not exist outside init_net.
    if !fam.netnsok && net_ns != mcast::initial_net_ns() {
        return message::error(req, Err(Errno::Enoent));
    }
    build_family_msg(&fam, req.nlmsg_pid, req.nlmsg_seq, ctrl_cmd::CTRL_CMD_NEWFAMILY)
}

/// `ctrl_dumpfamily`: every family visible in `net_ns`, then `NLMSG_DONE`.
/// # C: O(N families)
pub fn dumpfamily(req: &Nlmsghdr, net_ns: u64) -> Vec<u8> {
    let mut reply: Vec<u8> = Vec::new();
    for fam in family::snapshot_families().iter() {
        if !fam.netnsok && net_ns != mcast::initial_net_ns() { continue; }
        message::push_multi(&mut reply,
            build_family_msg(fam, req.nlmsg_pid, req.nlmsg_seq, ctrl_cmd::CTRL_CMD_NEWFAMILY));
    }
    message::push_done(&mut reply, req.nlmsg_seq, req.nlmsg_pid);
    reply
}

/// `ctrl_dumppolicy`: the attribute validation policies of one family — an
/// op → policy-index map plus the indexed policy tables themselves.
/// # C: O(ops × policy entries)
pub fn dumppolicy(req: &Nlmsghdr, attrs: &[u8]) -> Vec<u8> {
    let fam = match resolve(attrs) {
        Ok(f) => f,
        Err(e) => return message::error(req, Err(e)),
    };
    let only_op = attr::find(attrs, ctrl_attr::CTRL_ATTR_OP)
        .and_then(|a| a.payload.get(..4))
        .map(|b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]));
    let ops: Vec<&GenlOp> = fam.ops.iter()
        .filter(|op| only_op.is_none_or(|cmd| cmd == op.cmd as u32))
        .collect();
    let mut reply: Vec<u8> = Vec::new();
    // One message carrying the op → policy-index map.
    let mut body = message::start(req.nlmsg_pid, req.nlmsg_seq, GENL_ID_CTRL, CTRL_VERSION,
        0, ctrl_cmd::CTRL_CMD_GETPOLICY);
    attr::put_u16(&mut body, ctrl_attr::CTRL_ATTR_FAMILY_ID, fam.id);
    let map_nest = attr::nest_start(&mut body, ctrl_attr::CTRL_ATTR_OP_POLICY);
    for (idx, op) in ops.iter().enumerate() {
        let one = attr::nest_start(&mut body, op.cmd as u16);
        let which = if op.flags & op_flags::GENL_CMD_CAP_DO != 0 {
            op_policy_attr::CTRL_ATTR_POLICY_DO
        } else {
            op_policy_attr::CTRL_ATTR_POLICY_DUMP
        };
        attr::put_u32(&mut body, which, idx as u32);
        attr::nest_end(&mut body, one);
    }
    attr::nest_end(&mut body, map_nest);
    message::end(&mut body, 0);
    message::push_multi(&mut reply, body);
    // One message per indexed policy table.
    for (idx, op) in ops.iter().enumerate() {
        let mut body = message::start(req.nlmsg_pid, req.nlmsg_seq, GENL_ID_CTRL, CTRL_VERSION,
            0, ctrl_cmd::CTRL_CMD_GETPOLICY);
        attr::put_u16(&mut body, ctrl_attr::CTRL_ATTR_FAMILY_ID, fam.id);
        let policy_nest = attr::nest_start(&mut body, ctrl_attr::CTRL_ATTR_POLICY);
        let table = attr::nest_start(&mut body, idx as u16);
        for entry in op.policy.iter() {
            let one = attr::nest_start(&mut body, entry.attr);
            attr::put_u32(&mut body, policy_attr::NL_POLICY_TYPE_ATTR_TYPE, entry.kind);
            if entry.min_len != 0 {
                attr::put_u32(&mut body, policy_attr::NL_POLICY_TYPE_ATTR_MIN_LENGTH,
                    entry.min_len);
            }
            if entry.max_len != 0 {
                attr::put_u32(&mut body, policy_attr::NL_POLICY_TYPE_ATTR_MAX_LENGTH,
                    entry.max_len);
            }
            attr::nest_end(&mut body, one);
        }
        attr::nest_end(&mut body, table);
        attr::nest_end(&mut body, policy_nest);
        message::end(&mut body, 0);
        message::push_multi(&mut reply, body);
    }
    message::push_done(&mut reply, req.nlmsg_seq, req.nlmsg_pid);
    reply
}
