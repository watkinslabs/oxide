// The bonding option table and its dependency check. The table states which
// modes reject an option and what bond state a write demands; the check turns
// a violation into the errno the write must fail with.

use syscall::Errno;

use crate::flags::{BOND_OPTFLAG_IFDOWN, BOND_OPTFLAG_NOSLAVES, BOND_OPTFLAG_RAWVAL};
use crate::uapi::{
    BOND_MODE_8023AD, BOND_MODE_ACTIVEBACKUP, BOND_MODE_ALB, BOND_MODE_BROADCAST,
    BOND_MODE_MAX, BOND_MODE_ROUNDROBIN, BOND_MODE_TLB, BOND_MODE_XOR,
};

/// Option ids; the bit position of an id is the id itself.
pub const BOND_OPT_MODE:                  u16 = 0;
pub const BOND_OPT_PACKETS_PER_SLAVE:     u16 = 1;
pub const BOND_OPT_XMIT_HASH:             u16 = 2;
pub const BOND_OPT_ARP_VALIDATE:          u16 = 3;
pub const BOND_OPT_ARP_ALL_TARGETS:       u16 = 4;
pub const BOND_OPT_FAIL_OVER_MAC:         u16 = 5;
pub const BOND_OPT_ARP_INTERVAL:          u16 = 6;
pub const BOND_OPT_ARP_TARGETS:           u16 = 7;
pub const BOND_OPT_DOWNDELAY:             u16 = 8;
pub const BOND_OPT_UPDELAY:               u16 = 9;
pub const BOND_OPT_LACP_RATE:             u16 = 10;
pub const BOND_OPT_MINLINKS:              u16 = 11;
pub const BOND_OPT_AD_SELECT:             u16 = 12;
pub const BOND_OPT_NUM_PEER_NOTIF:        u16 = 13;
pub const BOND_OPT_MIIMON:                u16 = 14;
pub const BOND_OPT_PRIMARY:               u16 = 15;
pub const BOND_OPT_PRIMARY_RESELECT:      u16 = 16;
pub const BOND_OPT_USE_CARRIER:           u16 = 17;
pub const BOND_OPT_ACTIVE_SLAVE:          u16 = 18;
pub const BOND_OPT_QUEUE_ID:              u16 = 19;
pub const BOND_OPT_ALL_SLAVES_ACTIVE:     u16 = 20;
pub const BOND_OPT_RESEND_IGMP:           u16 = 21;
pub const BOND_OPT_LP_INTERVAL:           u16 = 22;
pub const BOND_OPT_SLAVES:                u16 = 23;
pub const BOND_OPT_TLB_DYNAMIC_LB:        u16 = 24;
pub const BOND_OPT_AD_ACTOR_SYS_PRIO:     u16 = 25;
pub const BOND_OPT_AD_ACTOR_SYSTEM:       u16 = 26;
pub const BOND_OPT_AD_USER_PORT_KEY:      u16 = 27;
pub const BOND_OPT_NUM_PEER_NOTIF_ALIAS:  u16 = 28;
pub const BOND_OPT_PEER_NOTIF_DELAY:      u16 = 29;
pub const BOND_OPT_LACP_ACTIVE:           u16 = 30;
pub const BOND_OPT_MISSED_MAX:            u16 = 31;
pub const BOND_OPT_NS_TARGETS:            u16 = 32;
pub const BOND_OPT_PRIO:                  u16 = 33;
pub const BOND_OPT_COUPLED_CONTROL:       u16 = 34;
pub const BOND_OPT_BROADCAST_NEIGH:       u16 = 35;
pub const BOND_OPT_ACTOR_PORT_PRIO:       u16 = 36;
pub const BOND_OPT_LACP_STRICT:           u16 = 37;
pub const BOND_OPT_LAST:                  u16 = 38;

const fn bit(mode: u8) -> u32 { 1u32 << mode }
/// Every mode except the listed set — the shape an option-restriction mask takes.
const fn all_modes_except(keep: u32) -> u32 {
    let all = (1u32 << (BOND_MODE_MAX + 1)) - 1;
    all & !keep
}

const RR_ONLY:  u32 = all_modes_except(bit(BOND_MODE_ROUNDROBIN));
const AD_ONLY:  u32 = all_modes_except(bit(BOND_MODE_8023AD));
const LB_ONLY:  u32 = all_modes_except(bit(BOND_MODE_TLB) | bit(BOND_MODE_ALB));
const AB_LB_ONLY: u32 =
    all_modes_except(bit(BOND_MODE_ACTIVEBACKUP) | bit(BOND_MODE_TLB) | bit(BOND_MODE_ALB));
const NO_ARP: u32 = bit(BOND_MODE_8023AD) | bit(BOND_MODE_TLB) | bit(BOND_MODE_ALB);

/// One row of the option table.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BondOption {
    pub id: u16,
    pub name: &'static str,
    /// `BOND_OPTFLAG_*` set.
    pub flags: u32,
    /// Modes in which the option is refused, as a mode-id bitmask.
    pub unsupported_modes: u32,
}

const fn opt(id: u16, name: &'static str, flags: u32, unsupported_modes: u32) -> BondOption {
    BondOption { id, name, flags, unsupported_modes }
}

/// Every writable bonding option, indexed by id.
pub const BOND_OPTS: [BondOption; BOND_OPT_LAST as usize] = [
    opt(BOND_OPT_MODE, "mode", BOND_OPTFLAG_NOSLAVES | BOND_OPTFLAG_IFDOWN, 0),
    opt(BOND_OPT_PACKETS_PER_SLAVE, "packets_per_slave", 0, RR_ONLY),
    opt(BOND_OPT_XMIT_HASH, "xmit_hash_policy", 0, 0),
    opt(BOND_OPT_ARP_VALIDATE, "arp_validate", 0, NO_ARP),
    opt(BOND_OPT_ARP_ALL_TARGETS, "arp_all_targets", 0, 0),
    opt(BOND_OPT_FAIL_OVER_MAC, "fail_over_mac", BOND_OPTFLAG_NOSLAVES, 0),
    opt(BOND_OPT_ARP_INTERVAL, "arp_interval", 0, NO_ARP),
    opt(BOND_OPT_ARP_TARGETS, "arp_ip_target", BOND_OPTFLAG_RAWVAL, 0),
    opt(BOND_OPT_DOWNDELAY, "downdelay", 0, 0),
    opt(BOND_OPT_UPDELAY, "updelay", 0, 0),
    opt(BOND_OPT_LACP_RATE, "lacp_rate", BOND_OPTFLAG_IFDOWN, AD_ONLY),
    opt(BOND_OPT_MINLINKS, "min_links", 0, 0),
    opt(BOND_OPT_AD_SELECT, "ad_select", BOND_OPTFLAG_IFDOWN, 0),
    opt(BOND_OPT_NUM_PEER_NOTIF, "num_unsol_na", 0, 0),
    opt(BOND_OPT_MIIMON, "miimon", 0, 0),
    opt(BOND_OPT_PRIMARY, "primary", BOND_OPTFLAG_RAWVAL, AB_LB_ONLY),
    opt(BOND_OPT_PRIMARY_RESELECT, "primary_reselect", 0, 0),
    opt(BOND_OPT_USE_CARRIER, "use_carrier", 0, 0),
    opt(BOND_OPT_ACTIVE_SLAVE, "active_slave", BOND_OPTFLAG_RAWVAL, AB_LB_ONLY),
    opt(BOND_OPT_QUEUE_ID, "queue_id", BOND_OPTFLAG_RAWVAL, 0),
    opt(BOND_OPT_ALL_SLAVES_ACTIVE, "all_slaves_active", 0, 0),
    opt(BOND_OPT_RESEND_IGMP, "resend_igmp", 0, 0),
    opt(BOND_OPT_LP_INTERVAL, "lp_interval", 0, 0),
    opt(BOND_OPT_SLAVES, "slaves", BOND_OPTFLAG_RAWVAL, 0),
    opt(BOND_OPT_TLB_DYNAMIC_LB, "tlb_dynamic_lb", BOND_OPTFLAG_IFDOWN, LB_ONLY),
    opt(BOND_OPT_AD_ACTOR_SYS_PRIO, "ad_actor_sys_prio", 0, AD_ONLY),
    opt(BOND_OPT_AD_ACTOR_SYSTEM, "ad_actor_system", BOND_OPTFLAG_RAWVAL, AD_ONLY),
    opt(BOND_OPT_AD_USER_PORT_KEY, "ad_user_port_key", BOND_OPTFLAG_IFDOWN, AD_ONLY),
    opt(BOND_OPT_NUM_PEER_NOTIF_ALIAS, "num_grat_arp", 0, 0),
    opt(BOND_OPT_PEER_NOTIF_DELAY, "peer_notif_delay", 0, 0),
    opt(BOND_OPT_LACP_ACTIVE, "lacp_active", BOND_OPTFLAG_IFDOWN, AD_ONLY),
    opt(BOND_OPT_MISSED_MAX, "arp_missed_max", 0, NO_ARP),
    opt(BOND_OPT_NS_TARGETS, "ns_ip6_target", BOND_OPTFLAG_RAWVAL, 0),
    opt(BOND_OPT_PRIO, "prio", BOND_OPTFLAG_RAWVAL, AB_LB_ONLY),
    opt(BOND_OPT_COUPLED_CONTROL, "coupled_control", BOND_OPTFLAG_IFDOWN, AD_ONLY),
    opt(BOND_OPT_BROADCAST_NEIGH, "broadcast_neighbor", 0, AD_ONLY),
    opt(BOND_OPT_ACTOR_PORT_PRIO, "actor_port_prio", BOND_OPTFLAG_RAWVAL, AD_ONLY),
    opt(BOND_OPT_LACP_STRICT, "lacp_strict", 0, AD_ONLY),
];

/// # C: O(1)
pub fn option_by_id(id: u16) -> Option<&'static BondOption> {
    BOND_OPTS.get(id as usize)
}

/// # C: O(options)
pub fn option_by_name(name: &str) -> Option<&'static BondOption> {
    BOND_OPTS.iter().find(|o| o.name == name)
}

/// Bond state a dependency check reads.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct BondStateView {
    pub mode: u8,
    pub has_slaves: bool,
    /// The master device is administratively up.
    pub if_up: bool,
}

/// Whether the write is legal in the bond's current state. An option the mode
/// does not implement is a permission failure; one that demands an empty bond
/// reports the bond is not empty; one that demands a down bond reports busy.
/// # C: O(1)
pub fn check_deps(opt: &BondOption, state: &BondStateView) -> Result<(), Errno> {
    if state.mode <= BOND_MODE_MAX && (opt.unsupported_modes & bit(state.mode)) != 0 {
        return Err(Errno::Eacces);
    }
    if (opt.flags & BOND_OPTFLAG_NOSLAVES) != 0 && state.has_slaves {
        return Err(Errno::Enotempty);
    }
    if (opt.flags & BOND_OPTFLAG_IFDOWN) != 0 && state.if_up {
        return Err(Errno::Ebusy);
    }
    Ok(())
}

/// Whether an option parses its own value rather than taking a table entry.
/// # C: O(1)
pub fn is_rawval(opt: &BondOption) -> bool { (opt.flags & BOND_OPTFLAG_RAWVAL) != 0 }

/// Modes that reject nothing use the whole mode space; this reports whether a
/// mode id is one the bond understands at all.
/// # C: O(1)
pub fn mode_valid(mode: u8) -> bool { mode <= BOND_MODE_MAX }

/// Whether the hash-policy id names a policy.
/// # C: O(1)
pub fn xmit_policy_valid(policy: u8) -> bool { policy <= crate::uapi::BOND_XMIT_POLICY_MAX }

const _: () = {
    // The broadcast and XOR modes carry no option restriction of their own;
    // referencing them keeps the mask constants honest about the mode space.
    assert!(bit(BOND_MODE_BROADCAST) & all_modes_except(0) != 0);
    assert!(bit(BOND_MODE_XOR) & all_modes_except(0) != 0);
};

/// Fold one accepted option write into the parameter set. The write has
/// already passed `check_deps` and `validate_value`, so a value that reaches
/// here is legal for the current mode; an option this crate carries no
/// parameter for (the address lists, the per-slave settings) is a no-op rather
/// than an error, because refusing it here would reject a request the checker
/// already accepted.
/// # C: O(1)
pub fn apply_write(p: &mut crate::master::BondParams, w: &crate::netlink::OptionWrite)
    -> Result<(), syscall::errno::Errno>
{
    let v = w.value;
    match w.opt_id {
        BOND_OPT_MODE                 => p.mode = v as u8,
        BOND_OPT_XMIT_HASH            => p.xmit_policy = v as u8,
        BOND_OPT_PACKETS_PER_SLAVE    => p.packets_per_slave = v as u32,
        BOND_OPT_MIIMON               => p.miimon = v as u32,
        BOND_OPT_UPDELAY              => p.updelay = v as u32,
        BOND_OPT_DOWNDELAY            => p.downdelay = v as u32,
        BOND_OPT_ARP_INTERVAL         => p.arp_interval = v as u32,
        BOND_OPT_ARP_VALIDATE         => p.arp_validate = v as u32,
        BOND_OPT_ARP_ALL_TARGETS      => p.arp_all_targets = v as u32,
        BOND_OPT_MISSED_MAX           => p.missed_max = v as u32,
        BOND_OPT_PRIMARY_RESELECT     => p.primary_reselect = v as u32,
        BOND_OPT_FAIL_OVER_MAC        => p.fail_over_mac = v as u32,
        BOND_OPT_AD_SELECT            => p.ad_select = v as u32,
        BOND_OPT_LACP_RATE            => p.lacp_rate = v as u32,
        BOND_OPT_LACP_ACTIVE          => p.lacp_active = v != 0,
        BOND_OPT_LACP_STRICT          => p.lacp_strict = v != 0,
        BOND_OPT_MINLINKS             => p.min_links = v as u32,
        BOND_OPT_NUM_PEER_NOTIF
        | BOND_OPT_NUM_PEER_NOTIF_ALIAS => p.num_peer_notif = v as u32,
        BOND_OPT_PEER_NOTIF_DELAY     => p.peer_notif_delay = v as u32,
        BOND_OPT_ALL_SLAVES_ACTIVE    => p.all_slaves_active = v != 0,
        BOND_OPT_RESEND_IGMP          => p.resend_igmp = v as u32,
        BOND_OPT_LP_INTERVAL          => p.lp_interval = v as u32,
        BOND_OPT_TLB_DYNAMIC_LB       => p.tlb_dynamic_lb = v != 0,
        BOND_OPT_USE_CARRIER          => p.use_carrier = v != 0,
        BOND_OPT_COUPLED_CONTROL      => p.coupled_control = v != 0,
        BOND_OPT_BROADCAST_NEIGH      => p.broadcast_neighbor = v != 0,
        BOND_OPT_AD_ACTOR_SYS_PRIO    => p.ad_actor_sys_prio = v as u32,
        BOND_OPT_AD_USER_PORT_KEY     => p.ad_user_port_key = v as u32,
        BOND_OPT_AD_ACTOR_SYSTEM      => {
            if w.raw.len() != crate::limits::BOND_MAC_LEN { return Err(syscall::errno::Errno::Einval); }
            p.ad_actor_system.0.copy_from_slice(&w.raw);
        }
        _ => {}
    }
    Ok(())
}
