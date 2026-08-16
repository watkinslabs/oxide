/// Link kind string carried in the rtnetlink `IFLA_INFO_KIND` attribute.
pub const BOND_LINK_KIND: &str = "bond";

// ABI numbers for the bonding master: mode ids, transmit-hash policy ids, the
// netlink attribute space, and the enumerated option value tables. Numbers
// only — no policy, no dispatch.

/// Bond modes, in the order the ABI numbers them.
pub const BOND_MODE_ROUNDROBIN:  u8 = 0;
pub const BOND_MODE_ACTIVEBACKUP: u8 = 1;
pub const BOND_MODE_XOR:         u8 = 2;
pub const BOND_MODE_BROADCAST:   u8 = 3;
pub const BOND_MODE_8023AD:      u8 = 4;
pub const BOND_MODE_TLB:         u8 = 5;
pub const BOND_MODE_ALB:         u8 = 6;
pub const BOND_MODE_MAX:         u8 = BOND_MODE_ALB;

/// Mode name strings, indexed by mode id.
pub const BOND_MODE_NAMES: [&str; 7] = [
    "balance-rr", "active-backup", "balance-xor", "broadcast",
    "802.3ad", "balance-tlb", "balance-alb",
];

/// # C: O(1)
pub fn bond_mode_name(mode: u8) -> Option<&'static str> {
    BOND_MODE_NAMES.get(mode as usize).copied()
}

/// # C: O(modes)
pub fn bond_mode_from_name(name: &str) -> Option<u8> {
    BOND_MODE_NAMES.iter().position(|n| *n == name).map(|i| i as u8)
}

/// Transmit-hash policy ids.
pub const BOND_XMIT_POLICY_LAYER2:      u8 = 0;
pub const BOND_XMIT_POLICY_LAYER34:     u8 = 1;
pub const BOND_XMIT_POLICY_LAYER23:     u8 = 2;
pub const BOND_XMIT_POLICY_ENCAP23:     u8 = 3;
pub const BOND_XMIT_POLICY_ENCAP34:     u8 = 4;
pub const BOND_XMIT_POLICY_VLAN_SRCMAC: u8 = 5;
pub const BOND_XMIT_POLICY_MAX:         u8 = BOND_XMIT_POLICY_VLAN_SRCMAC;

pub const BOND_XMIT_POLICY_NAMES: [&str; 6] = [
    "layer2", "layer3+4", "layer2+3", "encap2+3", "encap3+4", "vlan+srcmac",
];

/// # C: O(1)
pub fn xmit_policy_name(policy: u8) -> Option<&'static str> {
    BOND_XMIT_POLICY_NAMES.get(policy as usize).copied()
}

/// # C: O(policies)
pub fn xmit_policy_from_name(name: &str) -> Option<u8> {
    BOND_XMIT_POLICY_NAMES.iter().position(|n| *n == name).map(|i| i as u8)
}

/// Per-slave duplex encoding shared by reselection and the aggregator.
pub const DUPLEX_HALF: u8 = 0;
pub const DUPLEX_FULL: u8 = 1;

// ---------------------------------------------------------------- arp_validate

pub const BOND_ARP_VALIDATE_NONE:   u32 = 0;
/// Bit position of the ACTIVE slave state in the arp_validate mask.
pub const BOND_STATE_ACTIVE: u32 = 0;
/// Bit position of the BACKUP slave state in the arp_validate mask.
pub const BOND_STATE_BACKUP: u32 = 1;
pub const BOND_ARP_VALIDATE_ACTIVE: u32 = 1 << BOND_STATE_ACTIVE;
pub const BOND_ARP_VALIDATE_BACKUP: u32 = 1 << BOND_STATE_BACKUP;
pub const BOND_ARP_VALIDATE_ALL:    u32 = BOND_ARP_VALIDATE_ACTIVE | BOND_ARP_VALIDATE_BACKUP;
pub const BOND_ARP_FILTER:          u32 = BOND_ARP_VALIDATE_ALL + 1;
pub const BOND_ARP_FILTER_ACTIVE:   u32 = BOND_ARP_VALIDATE_ACTIVE | BOND_ARP_FILTER;
pub const BOND_ARP_FILTER_BACKUP:   u32 = BOND_ARP_VALIDATE_BACKUP | BOND_ARP_FILTER;

pub const ARP_VALIDATE_TBL: [(&str, u32); 7] = [
    ("none", BOND_ARP_VALIDATE_NONE),
    ("active", BOND_ARP_VALIDATE_ACTIVE),
    ("backup", BOND_ARP_VALIDATE_BACKUP),
    ("all", BOND_ARP_VALIDATE_ALL),
    ("filter", BOND_ARP_FILTER),
    ("filter_active", BOND_ARP_FILTER_ACTIVE),
    ("filter_backup", BOND_ARP_FILTER_BACKUP),
];

pub const BOND_ARP_TARGETS_ANY: u32 = 0;
pub const BOND_ARP_TARGETS_ALL: u32 = 1;
pub const ARP_ALL_TARGETS_TBL: [(&str, u32); 2] =
    [("any", BOND_ARP_TARGETS_ANY), ("all", BOND_ARP_TARGETS_ALL)];

// ------------------------------------------------------------- primary_reselect

pub const BOND_PRI_RESELECT_ALWAYS:  u32 = 0;
pub const BOND_PRI_RESELECT_BETTER:  u32 = 1;
pub const BOND_PRI_RESELECT_FAILURE: u32 = 2;
pub const PRIMARY_RESELECT_TBL: [(&str, u32); 3] = [
    ("always", BOND_PRI_RESELECT_ALWAYS),
    ("better", BOND_PRI_RESELECT_BETTER),
    ("failure", BOND_PRI_RESELECT_FAILURE),
];

// ---------------------------------------------------------------- fail_over_mac

pub const BOND_FOM_NONE:   u32 = 0;
pub const BOND_FOM_ACTIVE: u32 = 1;
pub const BOND_FOM_FOLLOW: u32 = 2;
pub const FAIL_OVER_MAC_TBL: [(&str, u32); 3] =
    [("none", BOND_FOM_NONE), ("active", BOND_FOM_ACTIVE), ("follow", BOND_FOM_FOLLOW)];

// -------------------------------------------------------------------- ad_select

pub const BOND_AD_STABLE:    u32 = 0;
pub const BOND_AD_BANDWIDTH: u32 = 1;
pub const BOND_AD_COUNT:     u32 = 2;
pub const BOND_AD_PRIO:      u32 = 3;
pub const AD_SELECT_TBL: [(&str, u32); 4] = [
    ("stable", BOND_AD_STABLE),
    ("bandwidth", BOND_AD_BANDWIDTH),
    ("count", BOND_AD_COUNT),
    ("actor_port_prio", BOND_AD_PRIO),
];

pub const AD_LACP_SLOW: u32 = 0;
pub const AD_LACP_FAST: u32 = 1;
pub const LACP_RATE_TBL: [(&str, u32); 2] = [("slow", AD_LACP_SLOW), ("fast", AD_LACP_FAST)];

/// # C: O(table)
pub fn table_lookup(tbl: &[(&'static str, u32)], name: &str) -> Option<u32> {
    tbl.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

/// # C: O(table)
pub fn table_name(tbl: &[(&'static str, u32)], value: u32) -> Option<&'static str> {
    tbl.iter().find(|(_, v)| *v == value).map(|(n, _)| *n)
}

// ----------------------------------------------------------- IFLA_BOND_* space

pub const IFLA_BOND_UNSPEC:            u16 = 0;
pub const IFLA_BOND_MODE:              u16 = 1;
pub const IFLA_BOND_ACTIVE_SLAVE:      u16 = 2;
pub const IFLA_BOND_MIIMON:            u16 = 3;
pub const IFLA_BOND_UPDELAY:           u16 = 4;
pub const IFLA_BOND_DOWNDELAY:         u16 = 5;
pub const IFLA_BOND_USE_CARRIER:       u16 = 6;
pub const IFLA_BOND_ARP_INTERVAL:      u16 = 7;
pub const IFLA_BOND_ARP_IP_TARGET:     u16 = 8;
pub const IFLA_BOND_ARP_VALIDATE:      u16 = 9;
pub const IFLA_BOND_ARP_ALL_TARGETS:   u16 = 10;
pub const IFLA_BOND_PRIMARY:           u16 = 11;
pub const IFLA_BOND_PRIMARY_RESELECT:  u16 = 12;
pub const IFLA_BOND_FAIL_OVER_MAC:     u16 = 13;
pub const IFLA_BOND_XMIT_HASH_POLICY:  u16 = 14;
pub const IFLA_BOND_RESEND_IGMP:       u16 = 15;
pub const IFLA_BOND_NUM_PEER_NOTIF:    u16 = 16;
pub const IFLA_BOND_ALL_SLAVES_ACTIVE: u16 = 17;
pub const IFLA_BOND_MIN_LINKS:         u16 = 18;
pub const IFLA_BOND_LP_INTERVAL:       u16 = 19;
pub const IFLA_BOND_PACKETS_PER_SLAVE: u16 = 20;
pub const IFLA_BOND_AD_LACP_RATE:      u16 = 21;
pub const IFLA_BOND_AD_SELECT:         u16 = 22;
pub const IFLA_BOND_AD_INFO:           u16 = 23;
pub const IFLA_BOND_AD_ACTOR_SYS_PRIO: u16 = 24;
pub const IFLA_BOND_AD_USER_PORT_KEY:  u16 = 25;
pub const IFLA_BOND_AD_ACTOR_SYSTEM:   u16 = 26;
pub const IFLA_BOND_TLB_DYNAMIC_LB:    u16 = 27;
pub const IFLA_BOND_PEER_NOTIF_DELAY:  u16 = 28;
pub const IFLA_BOND_AD_LACP_ACTIVE:    u16 = 29;
pub const IFLA_BOND_MISSED_MAX:        u16 = 30;
pub const IFLA_BOND_NS_IP6_TARGET:     u16 = 31;
pub const IFLA_BOND_COUPLED_CONTROL:   u16 = 32;
pub const IFLA_BOND_BROADCAST_NEIGH:   u16 = 33;
pub const IFLA_BOND_LACP_STRICT:       u16 = 34;
pub const IFLA_BOND_MAX:               u16 = IFLA_BOND_LACP_STRICT;

pub const IFLA_BOND_AD_INFO_UNSPEC:      u16 = 0;
pub const IFLA_BOND_AD_INFO_AGGREGATOR:  u16 = 1;
pub const IFLA_BOND_AD_INFO_NUM_PORTS:   u16 = 2;
pub const IFLA_BOND_AD_INFO_ACTOR_KEY:   u16 = 3;
pub const IFLA_BOND_AD_INFO_PARTNER_KEY: u16 = 4;
pub const IFLA_BOND_AD_INFO_PARTNER_MAC: u16 = 5;
pub const IFLA_BOND_AD_INFO_MAX:         u16 = IFLA_BOND_AD_INFO_PARTNER_MAC;

pub const IFLA_BOND_SLAVE_UNSPEC:                        u16 = 0;
pub const IFLA_BOND_SLAVE_STATE:                         u16 = 1;
pub const IFLA_BOND_SLAVE_MII_STATUS:                    u16 = 2;
pub const IFLA_BOND_SLAVE_LINK_FAILURE_COUNT:            u16 = 3;
pub const IFLA_BOND_SLAVE_PERM_HWADDR:                   u16 = 4;
pub const IFLA_BOND_SLAVE_QUEUE_ID:                      u16 = 5;
pub const IFLA_BOND_SLAVE_AD_AGGREGATOR_ID:              u16 = 6;
pub const IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE:      u16 = 7;
pub const IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE:    u16 = 8;
pub const IFLA_BOND_SLAVE_PRIO:                          u16 = 9;
pub const IFLA_BOND_SLAVE_ACTOR_PORT_PRIO:               u16 = 10;
pub const IFLA_BOND_SLAVE_AD_CHURN_ACTOR_STATE:          u16 = 11;
pub const IFLA_BOND_SLAVE_AD_CHURN_PARTNER_STATE:        u16 = 12;
pub const IFLA_BOND_SLAVE_MAX: u16 = IFLA_BOND_SLAVE_AD_CHURN_PARTNER_STATE;
