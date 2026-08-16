// Registration of the nl80211 family: its op table, its multicast groups, and
// the id userspace resolves through the controller.
//
// Every command names its own handler here. A command listed with no handler
// would be admitted by the dispatcher and then answered by nothing, which
// reads to userspace as a kernel that supports the command and ignores it.

extern crate alloc;

use alloc::vec::Vec;

use core::sync::atomic::{AtomicU16, Ordering};

use netlink::genetlink::family::{self, GenlFamilySpec, GenlOp};
use netlink::genetlink::uapi::op_flags;

use crate::uapi::{attr, cmd, NL80211_FAMILY_NAME, NL80211_FAMILY_VERSION};

use super::{ap_cmd, connect_cmd, iface_cmd, key_cmd, mgmt_cmd, policy, reg_cmd, scan_cmd,
            station_cmd, wiphy_cmd};

/// Multicast group names, in the order they are registered. The index into
/// this list is the family-relative group index a fan-out addresses.
pub const MCAST_GROUPS: &[&str] = &[
    "config", "scan", "regulatory", "mlme", "vendor", "nan", "testmode",
];

/// Group index of the configuration group.
pub const GROUP_CONFIG: usize = 0;
/// Group index of the scan group.
pub const GROUP_SCAN: usize = 1;
/// Group index of the regulatory group.
pub const GROUP_REGULATORY: usize = 2;
/// Group index of the management group.
pub const GROUP_MLME: usize = 3;
/// Group index of the vendor group.
pub const GROUP_VENDOR: usize = 4;
/// Group index of the neighbour-awareness group.
pub const GROUP_NAN: usize = 5;
/// Group index of the test-mode group.
pub const GROUP_TESTMODE: usize = 6;

/// Family id, once registered. Zero means the family is not up.
static FAMILY_ID: AtomicU16 = AtomicU16::new(0);

/// Registered family id. # C: O(1)
pub fn family_id() -> u16 { FAMILY_ID.load(Ordering::Acquire) }

/// Whether the family is registered. # C: O(1)
pub fn is_registered() -> bool { family_id() != 0 }

/// Multicast group id for a family-relative group index. # C: O(N families)
pub fn mcast_group(index: usize) -> Option<u32> {
    family::find_by_id(family_id())?.group_id(index)
}

/// Every command needing the network-administration capability, which is all
/// of them that change state. A query that only reads is not on this list:
/// `iw dev link` runs unprivileged and must keep working.
const ADMIN: u32 = op_flags::GENL_CMD_CAP_DO | op_flags::GENL_ADMIN_PERM
    | op_flags::GENL_CMD_CAP_HASPOL;
/// An unprivileged query.
const QUERY: u32 = op_flags::GENL_CMD_CAP_DO | op_flags::GENL_CMD_CAP_HASPOL;
/// An unprivileged dump.
const DUMP: u32 = op_flags::GENL_CMD_CAP_DUMP | op_flags::GENL_CMD_CAP_HASPOL;
/// A command served both ways, unprivileged.
const QUERY_DUMP: u32 = QUERY | op_flags::GENL_CMD_CAP_DUMP;

fn ops() -> Vec<GenlOp> {
    alloc::vec![
        GenlOp::with_handlers(cmd::GET_WIPHY, QUERY_DUMP, policy::WIPHY,
            Some(wiphy_cmd::get), Some(wiphy_cmd::dump)),
        GenlOp::with_handlers(cmd::SET_WIPHY, ADMIN, policy::WIPHY,
            Some(wiphy_cmd::set), None),
        GenlOp::with_handlers(cmd::GET_PROTOCOL_FEATURES, QUERY, policy::EMPTY,
            Some(wiphy_cmd::get_protocol_features), None),

        GenlOp::with_handlers(cmd::GET_INTERFACE, QUERY_DUMP, policy::IFACE,
            Some(iface_cmd::get), Some(iface_cmd::dump)),
        GenlOp::with_handlers(cmd::NEW_INTERFACE, ADMIN, policy::IFACE,
            Some(iface_cmd::new), None),
        GenlOp::with_handlers(cmd::SET_INTERFACE, ADMIN, policy::IFACE,
            Some(iface_cmd::set), None),
        GenlOp::with_handlers(cmd::DEL_INTERFACE, ADMIN, policy::IFACE,
            Some(iface_cmd::del), None),

        GenlOp::with_handlers(cmd::GET_KEY, ADMIN, policy::KEY, Some(key_cmd::get), None),
        GenlOp::with_handlers(cmd::NEW_KEY, ADMIN, policy::KEY, Some(key_cmd::new), None),
        GenlOp::with_handlers(cmd::SET_KEY, ADMIN, policy::KEY, Some(key_cmd::set), None),
        GenlOp::with_handlers(cmd::DEL_KEY, ADMIN, policy::KEY, Some(key_cmd::del), None),

        GenlOp::with_handlers(cmd::TRIGGER_SCAN, ADMIN, policy::SCAN,
            Some(scan_cmd::trigger), None),
        GenlOp::with_handlers(cmd::ABORT_SCAN, ADMIN, policy::SCAN,
            Some(scan_cmd::abort), None),
        GenlOp::with_handlers(cmd::GET_SCAN, DUMP, policy::SCAN, None, Some(scan_cmd::dump)),
        GenlOp::with_handlers(cmd::GET_SURVEY, DUMP, policy::IFACE, None,
            Some(station_cmd::dump_survey)),

        GenlOp::with_handlers(cmd::CONNECT, ADMIN, policy::CONNECT,
            Some(connect_cmd::connect), None),
        GenlOp::with_handlers(cmd::DISCONNECT, ADMIN, policy::CONNECT,
            Some(connect_cmd::disconnect), None),
        GenlOp::with_handlers(cmd::AUTHENTICATE, ADMIN, policy::CONNECT,
            Some(connect_cmd::authenticate), None),
        GenlOp::with_handlers(cmd::ASSOCIATE, ADMIN, policy::CONNECT,
            Some(connect_cmd::associate), None),
        GenlOp::with_handlers(cmd::DEAUTHENTICATE, ADMIN, policy::CONNECT,
            Some(connect_cmd::deauthenticate), None),
        GenlOp::with_handlers(cmd::DISASSOCIATE, ADMIN, policy::CONNECT,
            Some(connect_cmd::disassociate), None),

        GenlOp::with_handlers(cmd::GET_STATION, QUERY_DUMP, policy::STATION,
            Some(station_cmd::get), Some(station_cmd::dump)),
        GenlOp::with_handlers(cmd::NEW_STATION, ADMIN, policy::STATION,
            Some(station_cmd::new), None),
        GenlOp::with_handlers(cmd::SET_STATION, ADMIN, policy::STATION,
            Some(station_cmd::set), None),
        GenlOp::with_handlers(cmd::DEL_STATION, ADMIN, policy::STATION,
            Some(station_cmd::del), None),

        GenlOp::with_handlers(cmd::GET_REG, QUERY_DUMP, policy::REG,
            Some(reg_cmd::get), Some(reg_cmd::dump)),
        GenlOp::with_handlers(cmd::SET_REG, ADMIN, policy::REG, Some(reg_cmd::set), None),
        GenlOp::with_handlers(cmd::REQ_SET_REG, ADMIN, policy::REG,
            Some(reg_cmd::req_set), None),

        GenlOp::with_handlers(cmd::START_AP, ADMIN, policy::AP, Some(ap_cmd::start), None),
        GenlOp::with_handlers(cmd::STOP_AP, ADMIN, policy::AP, Some(ap_cmd::stop), None),
        GenlOp::with_handlers(cmd::SET_BSS, ADMIN, policy::AP, Some(ap_cmd::set_bss), None),

        GenlOp::with_handlers(cmd::REGISTER_FRAME, QUERY, policy::MGMT,
            Some(mgmt_cmd::register_frame), None),
        GenlOp::with_handlers(cmd::FRAME, ADMIN, policy::MGMT, Some(mgmt_cmd::tx), None),
        GenlOp::with_handlers(cmd::FRAME_WAIT_CANCEL, ADMIN, policy::MGMT,
            Some(mgmt_cmd::tx_cancel_wait), None),

        GenlOp::with_handlers(cmd::SET_POWER_SAVE, ADMIN, policy::IFACE,
            Some(iface_cmd::set_power_save), None),
        GenlOp::with_handlers(cmd::GET_POWER_SAVE, QUERY, policy::IFACE,
            Some(iface_cmd::get_power_save), None),
        GenlOp::with_handlers(cmd::SET_CHANNEL, ADMIN, policy::IFACE,
            Some(iface_cmd::set_channel), None),
        GenlOp::with_handlers(cmd::SET_CQM, ADMIN, policy::IFACE,
            Some(iface_cmd::set_cqm), None),
    ]
}

/// Register the family. Idempotent: a second call while the family is up
/// leaves it alone rather than producing a second id for the same name.
/// # C: O(N ops)
pub fn init() {
    if is_registered() { return; }
    let spec = GenlFamilySpec {
        name: NL80211_FAMILY_NAME,
        version: NL80211_FAMILY_VERSION,
        hdrsize: 0,
        maxattr: attr::MAX,
        ops: ops(),
        mcgrps: MCAST_GROUPS.to_vec(),
        netnsok: true,
        // Every command this build serves predates strict header validation
        // in the reference, so none of them opts into it.
        resv_start_op: u8::MAX,
    };
    if let Ok(id) = family::register_family(spec) { FAMILY_ID.store(id, Ordering::Release); }
}

/// Withdraw the family. Tests only. # C: O(N families)
#[cfg(test)]
pub fn fini() {
    let id = FAMILY_ID.swap(0, Ordering::AcqRel);
    if id != 0 { let _ = family::unregister_family(id); }
}
