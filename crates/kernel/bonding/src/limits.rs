// Sizes, bounds, defaults, and timer periods owned by the bonding master.

/// Upper bound on ports enslaved to one master, which bounds every per-slave
/// side table the load balancer keeps.
pub const BOND_MAX_SLAVES: usize = 256;

/// TLB transmit hash table entries; the index is a one-byte fold.
pub const TLB_HASH_TABLE_SIZE: usize = 256;
/// RLB receive client table entries; the index is a one-byte fold of client IP.
pub const RLB_HASH_TABLE_SIZE: usize = 256;
/// Sentinel for "no entry" in a TLB/RLB intrusive list link.
pub const TLB_NULL_INDEX: u32 = 0xffff_ffff;
/// Seconds between TLB load-history rebalances.
pub const BOND_TLB_REBALANCE_INTERVAL: u32 = 10;
/// Seconds between ALB learning-packet bursts, by default.
pub const BOND_ALB_DEFAULT_LP_INTERVAL: u32 = 1;

/// `packets_per_slave` bounds; zero means "pick a random slave per packet".
pub const PACKETS_PER_SLAVE_MIN: u32 = 0;
pub const PACKETS_PER_SLAVE_MAX: u32 = 65535;
pub const PACKETS_PER_SLAVE_DEFAULT: u32 = 1;

/// Missed ARP replies tolerated before the link counts as down.
pub const BOND_MISSED_MAX_MIN: u32 = 1;
pub const BOND_MISSED_MAX_MAX: u32 = 255;
pub const BOND_MISSED_MAX_DEFAULT: u32 = 2;

/// Peer notifications sent on a failover event.
pub const BOND_NUM_PEER_NOTIF_MIN: u32 = 0;
pub const BOND_NUM_PEER_NOTIF_MAX: u32 = 255;
pub const BOND_NUM_PEER_NOTIF_DEFAULT: u32 = 1;

/// IGMP membership reports resent after a link failure.
pub const BOND_RESEND_IGMP_MIN: u32 = 0;
pub const BOND_RESEND_IGMP_MAX: u32 = 255;
pub const BOND_RESEND_IGMP_DEFAULT: u32 = 1;

/// Actor system priority range for 802.3ad.
pub const AD_ACTOR_SYS_PRIO_MIN: u32 = 1;
pub const AD_ACTOR_SYS_PRIO_MAX: u32 = 65535;
pub const AD_ACTOR_SYS_PRIO_DEFAULT: u32 = 65535;

/// Actor port priority range for 802.3ad.
pub const AD_ACTOR_PORT_PRIO_MAX: u32 = 65535;
pub const AD_ACTOR_PORT_PRIO_DEFAULT: u32 = 255;

/// User-supplied aggregation key range.
pub const AD_USER_PORT_KEY_MAX: u32 = 1023;

/// LACP periodic transmission periods, in seconds.
pub const AD_FAST_PERIODIC_TIME: u32 = 1;
pub const AD_SLOW_PERIODIC_TIME: u32 = 30;
pub const AD_SHORT_TIMEOUT_TIME: u32 = 3 * AD_FAST_PERIODIC_TIME;
pub const AD_LONG_TIMEOUT_TIME:  u32 = 3 * AD_SLOW_PERIODIC_TIME;
pub const AD_CHURN_DETECTION_TIME: u32 = 60;
pub const AD_AGGREGATE_WAIT_TIME:  u32 = 2;
/// LACPDUs a port may emit within one second.
pub const AD_MAX_TX_IN_SECOND: u32 = 3;
/// Collector maximum delay advertised in the collector TLV.
pub const AD_COLLECTOR_MAX_DELAY: u16 = 0;

/// Short/long partner timeout encodings.
pub const AD_LONG_TIMEOUT:  u8 = 0;
pub const AD_SHORT_TIMEOUT: u8 = 1;

/// Default link-monitor periods, in milliseconds.
pub const BOND_DEFAULT_MIIMON: u32 = 0;
pub const BOND_DEFAULT_UPDELAY: u32 = 0;
pub const BOND_DEFAULT_DOWNDELAY: u32 = 0;
pub const BOND_DEFAULT_ARP_INTERVAL: u32 = 0;
/// Delay between peer notifications, in milliseconds.
pub const BOND_DEFAULT_PEER_NOTIF_DELAY: u32 = 0;

/// Bytes in an LACPDU body following the subtype/version octets, plus the
/// full frame body length the wire format fixes.
pub const LACPDU_LEN: usize = 110;
/// Actor and partner information TLV payload length.
pub const AD_INFO_TLV_LEN: u8 = 0x14;
/// Collector information TLV payload length.
pub const AD_COLLECTOR_TLV_LEN: u8 = 0x10;

/// Ethernet address width, the only width a bond identity may have.
pub const BOND_MAC_LEN: usize = 6;
