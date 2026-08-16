// IFLA_BOND_* attribute parsing. The blob turns into a list of option writes,
// each checked against the option table's dependency rules before any of them
// is applied, so a rejected attribute leaves the bond untouched.

extern crate alloc;
use alloc::vec::Vec;

use syscall::Errno;

use crate::options::{
    check_deps, option_by_id, BondStateView, BOND_OPT_ACTIVE_SLAVE, BOND_OPT_AD_ACTOR_SYSTEM,
    BOND_OPT_AD_ACTOR_SYS_PRIO, BOND_OPT_AD_SELECT, BOND_OPT_AD_USER_PORT_KEY,
    BOND_OPT_ALL_SLAVES_ACTIVE, BOND_OPT_ARP_ALL_TARGETS, BOND_OPT_ARP_INTERVAL,
    BOND_OPT_ARP_TARGETS, BOND_OPT_ARP_VALIDATE, BOND_OPT_BROADCAST_NEIGH,
    BOND_OPT_COUPLED_CONTROL, BOND_OPT_DOWNDELAY, BOND_OPT_FAIL_OVER_MAC,
    BOND_OPT_LACP_ACTIVE, BOND_OPT_LACP_RATE, BOND_OPT_LACP_STRICT, BOND_OPT_LP_INTERVAL,
    BOND_OPT_MIIMON, BOND_OPT_MINLINKS, BOND_OPT_MISSED_MAX, BOND_OPT_MODE,
    BOND_OPT_NS_TARGETS, BOND_OPT_NUM_PEER_NOTIF, BOND_OPT_PACKETS_PER_SLAVE,
    BOND_OPT_PEER_NOTIF_DELAY, BOND_OPT_PRIMARY, BOND_OPT_PRIMARY_RESELECT,
    BOND_OPT_RESEND_IGMP, BOND_OPT_TLB_DYNAMIC_LB, BOND_OPT_UPDELAY, BOND_OPT_USE_CARRIER,
    BOND_OPT_XMIT_HASH,
};
use crate::uapi::*;

/// A parsed attribute: which option it writes and the bytes it carries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OptionWrite {
    pub opt_id: u16,
    /// Integer value for a table-valued option.
    pub value: u64,
    /// Raw payload for an option that parses its own value.
    pub raw: Vec<u8>,
}

/// Netlink attribute header length; payloads start after it and each
/// attribute is padded up to a four-byte boundary.
const NLA_HDRLEN: usize = 4;
const NLA_ALIGNTO: usize = 4;

fn nla_align(len: usize) -> usize { (len + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1) }

/// Option each attribute writes, and how wide its integer payload is.
/// # C: O(1)
fn attr_option(attr: u16) -> Option<(u16, usize)> {
    let r = match attr {
        IFLA_BOND_MODE => (BOND_OPT_MODE, 1),
        IFLA_BOND_ACTIVE_SLAVE => (BOND_OPT_ACTIVE_SLAVE, 4),
        IFLA_BOND_MIIMON => (BOND_OPT_MIIMON, 4),
        IFLA_BOND_UPDELAY => (BOND_OPT_UPDELAY, 4),
        IFLA_BOND_DOWNDELAY => (BOND_OPT_DOWNDELAY, 4),
        IFLA_BOND_USE_CARRIER => (BOND_OPT_USE_CARRIER, 1),
        IFLA_BOND_ARP_INTERVAL => (BOND_OPT_ARP_INTERVAL, 4),
        IFLA_BOND_ARP_IP_TARGET => (BOND_OPT_ARP_TARGETS, 0),
        IFLA_BOND_ARP_VALIDATE => (BOND_OPT_ARP_VALIDATE, 4),
        IFLA_BOND_ARP_ALL_TARGETS => (BOND_OPT_ARP_ALL_TARGETS, 4),
        IFLA_BOND_PRIMARY => (BOND_OPT_PRIMARY, 4),
        IFLA_BOND_PRIMARY_RESELECT => (BOND_OPT_PRIMARY_RESELECT, 1),
        IFLA_BOND_FAIL_OVER_MAC => (BOND_OPT_FAIL_OVER_MAC, 1),
        IFLA_BOND_XMIT_HASH_POLICY => (BOND_OPT_XMIT_HASH, 1),
        IFLA_BOND_RESEND_IGMP => (BOND_OPT_RESEND_IGMP, 4),
        IFLA_BOND_NUM_PEER_NOTIF => (BOND_OPT_NUM_PEER_NOTIF, 1),
        IFLA_BOND_ALL_SLAVES_ACTIVE => (BOND_OPT_ALL_SLAVES_ACTIVE, 1),
        IFLA_BOND_MIN_LINKS => (BOND_OPT_MINLINKS, 4),
        IFLA_BOND_LP_INTERVAL => (BOND_OPT_LP_INTERVAL, 4),
        IFLA_BOND_PACKETS_PER_SLAVE => (BOND_OPT_PACKETS_PER_SLAVE, 4),
        IFLA_BOND_AD_LACP_RATE => (BOND_OPT_LACP_RATE, 1),
        IFLA_BOND_AD_SELECT => (BOND_OPT_AD_SELECT, 1),
        IFLA_BOND_AD_ACTOR_SYS_PRIO => (BOND_OPT_AD_ACTOR_SYS_PRIO, 2),
        IFLA_BOND_AD_USER_PORT_KEY => (BOND_OPT_AD_USER_PORT_KEY, 2),
        IFLA_BOND_AD_ACTOR_SYSTEM => (BOND_OPT_AD_ACTOR_SYSTEM, 0),
        IFLA_BOND_TLB_DYNAMIC_LB => (BOND_OPT_TLB_DYNAMIC_LB, 1),
        IFLA_BOND_PEER_NOTIF_DELAY => (BOND_OPT_PEER_NOTIF_DELAY, 4),
        IFLA_BOND_AD_LACP_ACTIVE => (BOND_OPT_LACP_ACTIVE, 1),
        IFLA_BOND_MISSED_MAX => (BOND_OPT_MISSED_MAX, 1),
        IFLA_BOND_NS_IP6_TARGET => (BOND_OPT_NS_TARGETS, 0),
        IFLA_BOND_COUPLED_CONTROL => (BOND_OPT_COUPLED_CONTROL, 1),
        IFLA_BOND_BROADCAST_NEIGH => (BOND_OPT_BROADCAST_NEIGH, 1),
        IFLA_BOND_LACP_STRICT => (BOND_OPT_LACP_STRICT, 1),
        _ => return None,
    };
    Some(r)
}

fn read_int(payload: &[u8], width: usize) -> Option<u64> {
    if payload.len() < width { return None; }
    let v = match width {
        1 => payload[0] as u64,
        2 => u16::from_ne_bytes([payload[0], payload[1]]) as u64,
        4 => u32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]) as u64,
        _ => return None,
    };
    Some(v)
}

/// Split an `IFLA_BOND_*` blob into option writes. An attribute the bond does
/// not define, or one whose payload is short for its type, fails the parse.
/// # C: O(blob)
pub fn parse(blob: &[u8]) -> Result<Vec<OptionWrite>, Errno> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + NLA_HDRLEN <= blob.len() {
        let len = u16::from_ne_bytes([blob[off], blob[off + 1]]) as usize;
        let typ = u16::from_ne_bytes([blob[off + 2], blob[off + 3]]);
        if len < NLA_HDRLEN || off + len > blob.len() { return Err(Errno::Einval); }
        let payload = &blob[off + NLA_HDRLEN..off + len];

        // The nested aggregation-info block is read-only state, not a write.
        if typ != IFLA_BOND_AD_INFO {
            let (opt_id, width) = attr_option(typ).ok_or(Errno::Einval)?;
            let write = if width == 0 {
                OptionWrite { opt_id, value: 0, raw: payload.to_vec() }
            } else {
                let value = read_int(payload, width).ok_or(Errno::Einval)?;
                OptionWrite { opt_id, value, raw: Vec::new() }
            };
            out.push(write);
        }
        off += nla_align(len);
    }
    Ok(out)
}

/// Range-check one write against the value space its option accepts.
/// # C: O(1)
pub fn validate_value(w: &OptionWrite) -> Result<(), Errno> {
    use crate::limits::{
        AD_ACTOR_SYS_PRIO_MAX, AD_ACTOR_SYS_PRIO_MIN, AD_USER_PORT_KEY_MAX,
        BOND_MISSED_MAX_MAX, BOND_MISSED_MAX_MIN, BOND_NUM_PEER_NOTIF_MAX,
        BOND_RESEND_IGMP_MAX, PACKETS_PER_SLAVE_MAX,
    };
    let ok = match w.opt_id {
        BOND_OPT_MODE => w.value <= BOND_MODE_MAX as u64,
        BOND_OPT_XMIT_HASH => w.value <= BOND_XMIT_POLICY_MAX as u64,
        BOND_OPT_AD_SELECT => w.value <= BOND_AD_PRIO as u64,
        BOND_OPT_PRIMARY_RESELECT => w.value <= BOND_PRI_RESELECT_FAILURE as u64,
        BOND_OPT_FAIL_OVER_MAC => w.value <= BOND_FOM_FOLLOW as u64,
        BOND_OPT_ARP_ALL_TARGETS => w.value <= BOND_ARP_TARGETS_ALL as u64,
        BOND_OPT_ARP_VALIDATE => w.value <= BOND_ARP_FILTER_BACKUP as u64,
        BOND_OPT_LACP_RATE => w.value <= AD_LACP_FAST as u64,
        BOND_OPT_PACKETS_PER_SLAVE => w.value <= PACKETS_PER_SLAVE_MAX as u64,
        BOND_OPT_MISSED_MAX => {
            w.value >= BOND_MISSED_MAX_MIN as u64 && w.value <= BOND_MISSED_MAX_MAX as u64
        }
        BOND_OPT_NUM_PEER_NOTIF => w.value <= BOND_NUM_PEER_NOTIF_MAX as u64,
        BOND_OPT_RESEND_IGMP => w.value <= BOND_RESEND_IGMP_MAX as u64,
        BOND_OPT_AD_ACTOR_SYS_PRIO => {
            w.value >= AD_ACTOR_SYS_PRIO_MIN as u64 && w.value <= AD_ACTOR_SYS_PRIO_MAX as u64
        }
        BOND_OPT_AD_USER_PORT_KEY => w.value <= AD_USER_PORT_KEY_MAX as u64,
        _ => true,
    };
    if ok { Ok(()) } else { Err(Errno::Einval) }
}

/// Check every write against the bond's current state before any is applied.
/// A mode write is evaluated against the mode the bond has now, and the
/// remaining writes against the mode the request leaves behind.
/// # C: O(writes)
pub fn check_all(writes: &[OptionWrite], state: &BondStateView) -> Result<(), Errno> {
    let mut effective = *state;
    if let Some(m) = writes.iter().find(|w| w.opt_id == BOND_OPT_MODE) {
        let opt = option_by_id(BOND_OPT_MODE).ok_or(Errno::Einval)?;
        validate_value(m)?;
        check_deps(opt, state)?;
        effective.mode = m.value as u8;
    }
    for w in writes.iter().filter(|w| w.opt_id != BOND_OPT_MODE) {
        let opt = option_by_id(w.opt_id).ok_or(Errno::Einval)?;
        validate_value(w)?;
        check_deps(opt, &effective)?;
    }
    Ok(())
}

/// Parse and check one attribute blob, yielding the writes to apply.
/// # C: O(blob)
pub fn parse_and_check(blob: &[u8], state: &BondStateView) -> Result<Vec<OptionWrite>, Errno> {
    let writes = parse(blob)?;
    check_all(&writes, state)?;
    Ok(writes)
}
