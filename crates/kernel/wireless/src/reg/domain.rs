// A regulatory domain: a country code, a radar region, and the rules.
//
// Three country codes are not countries. `00` is the world domain the stack
// starts in and falls back to; `98` marks a domain produced by intersecting
// two others; `99` marks a domain a driver supplied for itself. A caller that
// treats any of them as a country code will look one up and find nothing.

extern crate alloc;

use alloc::vec::Vec;

use super::rule::{PowerRule, RegRule};
use crate::uapi::enums::{dfs_region, reg_rule_flags, reg_type};

/// The world domain's country code.
pub const ALPHA2_WORLD: [u8; 2] = *b"00";
/// The code a domain built by intersecting two others carries.
pub const ALPHA2_INTERSECTION: [u8; 2] = *b"98";
/// The code a driver-supplied custom domain carries.
pub const ALPHA2_CUSTOM_WORLD: [u8; 2] = *b"99";

/// Whether a code is two letters — a real country code and not one of the
/// three reserved markers. # C: O(1)
pub fn is_an_alpha2(alpha2: [u8; 2]) -> bool {
    alpha2[0].is_ascii_alphabetic() && alpha2[1].is_ascii_alphabetic()
}

/// Whether a code is the world domain. # C: O(1)
pub fn is_world(alpha2: [u8; 2]) -> bool { alpha2 == ALPHA2_WORLD }

/// Normalise a country code to upper case, rejecting anything that is neither
/// two letters nor one of the reserved markers. # C: O(1)
pub fn parse_alpha2(bytes: &[u8]) -> Option<[u8; 2]> {
    let raw: [u8; 2] = bytes.get(..2)?.try_into().ok()?;
    let out = [raw[0].to_ascii_uppercase(), raw[1].to_ascii_uppercase()];
    if is_an_alpha2(out) || out == ALPHA2_WORLD || out == ALPHA2_INTERSECTION
        || out == ALPHA2_CUSTOM_WORLD { Some(out) } else { None }
}

/// A whole regulatory domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegDomain {
    pub alpha2: [u8; 2],
    /// `dfs_region` value, which decides how long a radar check takes.
    pub dfs_region: u8,
    pub rules: Vec<RegRule>,
}

/// One megahertz in kHz, for building rules from channel-plan megahertz.
const MHZ: u32 = 1000;

/// A rule spanning `start_mhz..=end_mhz` inclusive of the guard either side,
/// as a regulatory table states them. # C: O(1)
fn rule(start_mhz: u32, end_mhz: u32, bw_mhz: u32, eirp_dbm: i32, flags: u32) -> RegRule {
    RegRule {
        freq_range: super::rule::FreqRange {
            start_khz: start_mhz * MHZ,
            end_khz: end_mhz * MHZ,
            max_bandwidth_khz: bw_mhz * MHZ,
        },
        power_rule: PowerRule {
            max_antenna_gain_mbi: 600,
            max_eirp_mbm: eirp_dbm * 100,
            max_psd_mbm_mhz: 0,
        },
        flags, dfs_cac_ms: 0,
    }
}

impl RegDomain {
    /// The domain the stack runs in until something tells it a country. Every
    /// channel outside the globally unlicensed 2.4 GHz range is receive-only:
    /// a radio that has not been told where it is may listen anywhere it can
    /// but may only initiate where every regulator agrees. # C: O(1)
    pub fn world() -> Self {
        use reg_rule_flags as f;
        Self {
            alpha2: ALPHA2_WORLD,
            dfs_region: dfs_region::UNSET,
            rules: alloc::vec![
                // Channels 1 to 11, usable everywhere.
                rule(2402, 2472, 40, 20, 0),
                // Channels 12 and 13, receive-only.
                rule(2457, 2482, 20, 20, f::NO_IR | f::AUTO_BW),
                // Channel 14: one regulator permits it, and only without
                // orthogonal frequency division multiplexing.
                rule(2474, 2494, 20, 20, f::NO_IR | f::NO_OFDM),
                // Channels 36 to 48.
                rule(5170, 5250, 80, 20, f::NO_IR | f::AUTO_BW),
                // Channels 52 to 64, radar detection required.
                rule(5250, 5330, 80, 20, f::NO_IR | f::AUTO_BW | f::DFS),
                // Channels 100 to 144, radar detection required.
                rule(5490, 5730, 160, 20, f::NO_IR | f::DFS),
                // Channels 149 to 165.
                rule(5735, 5835, 80, 20, f::NO_IR),
                // Channels 1 to 3 of the 60 GHz band.
                rule(57240, 63720, 2160, 0, 0),
            ],
        }
    }

    /// A domain with a country code and rules, and no radar region stated.
    /// # C: O(1)
    pub fn new(alpha2: [u8; 2], dfs_region: u8, rules: Vec<RegRule>) -> Self {
        Self { alpha2, dfs_region, rules }
    }

    /// What kind of domain this is, as `GET_REG` reports it. # C: O(1)
    pub fn reg_type(&self) -> u32 {
        if is_world(self.alpha2) { reg_type::WORLD }
        else if self.alpha2 == ALPHA2_CUSTOM_WORLD { reg_type::CUSTOM_WORLD }
        else if self.alpha2 == ALPHA2_INTERSECTION { reg_type::INTERSECTION }
        else { reg_type::COUNTRY }
    }

    /// Rule covering a channel of a given width, if the domain has one.
    ///
    /// The widest matching rule does not win: the rule that covers the
    /// channel at the width asked for is the answer, and if the channel does
    /// not fit at that width in any rule, the domain does not permit it.
    /// # C: O(N rules)
    pub fn rule_for(&self, center_khz: u32, bw_khz: u32) -> Option<&RegRule> {
        self.rules.iter().find(|r| r.covers(center_khz, bw_khz))
    }

    /// Rule covering a frequency at the narrowest width any channel uses.
    /// # C: O(N rules)
    pub fn rule_for_freq(&self, center_khz: u32) -> Option<&RegRule> {
        self.rules.iter().find(|r| center_khz >= r.freq_range.start_khz
                               && center_khz <= r.freq_range.end_khz)
    }

    /// The domain permitted by both of two domains. Every pair of rules that
    /// overlaps contributes one rule; a frequency either domain does not
    /// cover is in no rule of the result, and so is not permitted.
    /// # C: O(N rules squared)
    pub fn intersect(&self, other: &Self) -> Self {
        let mut rules: Vec<RegRule> = Vec::new();
        for a in &self.rules {
            for b in &other.rules {
                let Some(merged) = a.intersect(b) else { continue; };
                // Two source rules can produce the same span; keep one.
                if rules.iter().any(|r| r.freq_range == merged.freq_range) { continue; }
                rules.push(merged);
            }
        }
        rules.sort_by_key(|r| r.freq_range.start_khz);
        Self {
            alpha2: ALPHA2_INTERSECTION,
            // A radar region is only meaningful when both sides agree on it.
            dfs_region: if self.dfs_region == other.dfs_region { self.dfs_region }
                        else { dfs_region::UNSET },
            rules,
        }
    }

    /// Whether the domain permits nothing at all. # C: O(1)
    pub fn is_empty(&self) -> bool { self.rules.is_empty() }
}
