// What the virtual radios are configured with.

/// Name the driver reports.
pub const DRIVER_NAME: &str = "mac80211_hwsim";
/// Radios created when nothing asked for a particular number.
pub const DEFAULT_RADIOS: u32 = 2;
/// Radios the driver will create at all.
pub const MAX_RADIOS: u32 = 64;

/// Address prefix every virtual radio's address is built on. The second bit
/// of the first byte marks it locally administered, which is what keeps these
/// addresses out of the space real hardware is assigned from.
pub const ADDR_PREFIX: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];

/// Channel numbers offered in the 2.4 GHz band.
pub const CHANNELS_2GHZ: u32 = 14;
/// Channel numbers offered in the 5 GHz band.
pub const CHANNELS_5GHZ: [i32; 9] = [36, 40, 44, 48, 52, 56, 60, 64, 149];
/// Transmit power ceiling the radios advertise, in dBm.
pub const MAX_POWER_DBM: i32 = 20;

/// Stations one virtual radio will hold.
pub const MAX_STATIONS: u16 = 128;
/// Reorder buffer the radios agree to.
pub const MAX_AGG_SUBFRAMES: u16 = 64;

/// Signal strength, in dBm, every delivered frame is reported with. A real
/// medium varies it with distance; this one has no distance, so a single
/// plausible value is more honest than a fabricated one that changes.
pub const SIGNAL_DBM: i8 = -50;

/// Nanoseconds the medium's clock advances per frame carried, so a sequence
/// of exchanges has a monotonically increasing time even with no timer
/// running. Every deadline in the layer above is expressed against this.
pub const CLOCK_STEP_NS: u64 = 1_000_000;
