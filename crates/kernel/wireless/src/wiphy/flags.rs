// Immutable radio capability bits.

/// Four-address operation on an access-point VLAN interface.
pub const FOUR_ADDR_AP: u32 = 1 << 5;
/// Four-address operation on a station interface.
pub const FOUR_ADDR_STATION: u32 = 1 << 6;
/// Robust-security keys on an independent basic service set.
pub const IBSS_RSN: u32 = 1 << 8;
/// Direct management-frame transmission away from the operating channel.
pub const OFFCHAN_TX: u32 = 1 << 20;
