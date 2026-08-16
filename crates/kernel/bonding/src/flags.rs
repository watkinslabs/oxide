// Bit flags: LACP actor/partner state bits, LACP port flags, and the option
// dependency flags the option table carries.

/// LACP actor/partner state bits carried in an LACPDU's state octet.
pub const LACP_STATE_LACP_ACTIVITY:  u8 = 0x01;
pub const LACP_STATE_LACP_TIMEOUT:   u8 = 0x02;
pub const LACP_STATE_AGGREGATION:    u8 = 0x04;
pub const LACP_STATE_SYNCHRONIZATION: u8 = 0x08;
pub const LACP_STATE_COLLECTING:     u8 = 0x10;
pub const LACP_STATE_DISTRIBUTING:   u8 = 0x20;
pub const LACP_STATE_DEFAULTED:      u8 = 0x40;
pub const LACP_STATE_EXPIRED:        u8 = 0x80;

/// Port-internal flags tracked alongside the state octet.
pub const AD_PORT_BEGIN:         u16 = 0x1;
pub const AD_PORT_LACP_ENABLED:  u16 = 0x2;
pub const AD_PORT_ACTOR_CHURN:   u16 = 0x4;
pub const AD_PORT_PARTNER_CHURN: u16 = 0x8;
pub const AD_PORT_READY:         u16 = 0x10;
pub const AD_PORT_READY_N:       u16 = 0x20;
pub const AD_PORT_MATCHED:       u16 = 0x40;
pub const AD_PORT_STANDBY:       u16 = 0x80;
pub const AD_PORT_SELECTED:      u16 = 0x100;
pub const AD_PORT_MOVED:         u16 = 0x200;
pub const AD_PORT_CHURNED:       u16 = AD_PORT_ACTOR_CHURN | AD_PORT_PARTNER_CHURN;

/// Partner-system "standby" marker in the aggregation state octet.
pub const AD_STANDBY: u8 = 0x2;

/// Option dependency flags: what state the bond must be in for the write to
/// be legal, and whether the option parses its own value.
pub const BOND_OPTFLAG_NOSLAVES: u32 = 1 << 0;
pub const BOND_OPTFLAG_IFDOWN:   u32 = 1 << 1;
pub const BOND_OPTFLAG_RAWVAL:   u32 = 1 << 2;
