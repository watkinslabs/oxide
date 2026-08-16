// One regulatory rule: a frequency range, the power allowed inside it, and
// the restrictions that come with it.
//
// Frequencies are held in kHz throughout, and power in millibel units, both
// because that is what crosses the netlink boundary and because rounding a
// range to megahertz can widen it past what the rule permits.

/// A contiguous span of spectrum a rule covers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreqRange {
    /// Lowest frequency in the range, in kHz.
    pub start_khz: u32,
    /// Highest frequency in the range, in kHz.
    pub end_khz: u32,
    /// Widest channel that may be placed inside the range, in kHz.
    pub max_bandwidth_khz: u32,
}

impl FreqRange {
    /// Whether a channel of `bw_khz` centred on `center_khz` fits entirely
    /// inside the range and does not exceed its bandwidth ceiling. A channel
    /// that merely touches the range is not covered by it. # C: O(1)
    pub fn covers(&self, center_khz: u32, bw_khz: u32) -> bool {
        if bw_khz > self.max_bandwidth_khz { return false; }
        let half = bw_khz / 2;
        center_khz.saturating_sub(half) >= self.start_khz && center_khz + half <= self.end_khz
    }

    /// Overlap of two ranges, if they overlap at all. # C: O(1)
    pub fn intersect(&self, other: &Self) -> Option<Self> {
        let start_khz = self.start_khz.max(other.start_khz);
        let end_khz = self.end_khz.min(other.end_khz);
        if start_khz >= end_khz { return None; }
        Some(Self {
            start_khz, end_khz,
            max_bandwidth_khz: self.max_bandwidth_khz.min(other.max_bandwidth_khz)
                .min(end_khz - start_khz),
        })
    }

    /// Width of the range in kHz. # C: O(1)
    pub fn width_khz(&self) -> u32 { self.end_khz.saturating_sub(self.start_khz) }
}

/// The power ceiling inside a range.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PowerRule {
    /// Highest antenna gain, in millibel-isotropic.
    pub max_antenna_gain_mbi: i32,
    /// Highest effective isotropic radiated power, in millibel-milliwatts.
    pub max_eirp_mbm: i32,
    /// Highest power spectral density, in millibel-milliwatts per megahertz.
    pub max_psd_mbm_mhz: i32,
}

impl PowerRule {
    /// The stricter of two power rules. Intersecting two domains must never
    /// permit more than either allowed on its own. # C: O(1)
    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            max_antenna_gain_mbi: self.max_antenna_gain_mbi.min(other.max_antenna_gain_mbi),
            max_eirp_mbm: self.max_eirp_mbm.min(other.max_eirp_mbm),
            max_psd_mbm_mhz: self.max_psd_mbm_mhz.min(other.max_psd_mbm_mhz),
        }
    }
}

/// One rule of a regulatory domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegRule {
    pub freq_range: FreqRange,
    pub power_rule: PowerRule,
    /// `reg_rule_flags` bits.
    pub flags: u32,
    /// Channel-availability-check time in milliseconds, for a radar range.
    pub dfs_cac_ms: u32,
}

impl RegRule {
    /// A rule over one span with a power ceiling and no restrictions.
    /// # C: O(1)
    pub fn new(start_khz: u32, end_khz: u32, max_bandwidth_khz: u32, max_eirp_mbm: i32,
               flags: u32) -> Self {
        Self {
            freq_range: FreqRange { start_khz, end_khz, max_bandwidth_khz },
            power_rule: PowerRule { max_antenna_gain_mbi: 0, max_eirp_mbm,
                                    max_psd_mbm_mhz: 0 },
            flags, dfs_cac_ms: 0,
        }
    }

    /// Whether the rule covers a channel of a given width. # C: O(1)
    pub fn covers(&self, center_khz: u32, bw_khz: u32) -> bool {
        self.freq_range.covers(center_khz, bw_khz)
    }

    /// The rule that applies where two rules overlap: the narrower range, the
    /// stricter power, and the union of the restrictions. A restriction
    /// present in either domain applies in the intersection — an intersection
    /// that dropped a restriction would authorise transmission neither domain
    /// allowed. # C: O(1)
    pub fn intersect(&self, other: &Self) -> Option<Self> {
        let freq_range = self.freq_range.intersect(&other.freq_range)?;
        Some(Self {
            freq_range,
            power_rule: self.power_rule.intersect(&other.power_rule),
            flags: self.flags | other.flags,
            dfs_cac_ms: self.dfs_cac_ms.max(other.dfs_cac_ms),
        })
    }
}

/// Default availability-check time for a radar channel, in milliseconds.
pub const DEFAULT_DFS_CAC_MS: u32 = 60_000;
/// Availability-check time for the weather-radar sub-band, in milliseconds.
pub const WEATHER_RADAR_CAC_MS: u32 = 600_000;
/// Lowest frequency of the weather-radar sub-band, in kHz.
pub const WEATHER_RADAR_START_KHZ: u32 = 5_600_000;
/// Highest frequency of the weather-radar sub-band, in kHz.
pub const WEATHER_RADAR_END_KHZ: u32 = 5_650_000;

/// Availability-check time a radar range needs. The weather-radar sub-band
/// needs ten times the ordinary check, and a rule that states its own time
/// keeps it. # C: O(1)
pub fn dfs_cac_ms(rule: &RegRule, dfs_region: u8) -> u32 {
    if rule.dfs_cac_ms != 0 { return rule.dfs_cac_ms; }
    let r = &rule.freq_range;
    let overlaps_weather = r.start_khz < WEATHER_RADAR_END_KHZ
        && r.end_khz > WEATHER_RADAR_START_KHZ;
    if dfs_region == crate::uapi::enums::dfs_region::ETSI && overlaps_weather {
        return WEATHER_RADAR_CAC_MS;
    }
    DEFAULT_DFS_CAC_MS
}
