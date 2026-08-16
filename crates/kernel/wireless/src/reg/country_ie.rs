// Reading a regulatory domain out of a beacon's country element.
//
// The element is a country string followed by three-byte triplets. A triplet
// is either a subband — first channel, channel count, power ceiling — or, when
// its first byte is at or above the operating-triplet marker, an operating
// class descriptor this parser skips. Reading an operating triplet as a
// subband invents channels that do not exist, which is why the marker is
// checked before every triplet and not only the first.

extern crate alloc;

use alloc::vec::Vec;

use super::domain::{parse_alpha2, RegDomain};
use super::rule::{FreqRange, PowerRule, RegRule};
use crate::chan::{channel_to_freq_khz, mhz_to_khz};
use crate::uapi::enums::{dfs_region, Band};

/// Country string width: two country characters and one environment byte.
pub const COUNTRY_STRING_LEN: usize = 3;
/// Width of one triplet.
pub const TRIPLET_LEN: usize = 3;
/// A triplet whose first byte is at least this is an operating triplet, not a
/// subband.
pub const OPERATING_TRIPLET_MARKER: u8 = 201;
/// Half a channel's width in kHz, the guard a subband rule needs either side.
const CHANNEL_HALF_KHZ: u32 = 10_000;
/// Channel numbers step by this within a subband above 2.4 GHz.
const CHANNEL_STEP_5GHZ: u32 = 4;

/// Environment byte values.
pub mod environment {
    /// Indoor and outdoor both.
    pub const ANY: u8 = b' ';
    pub const OUTDOOR: u8 = b'O';
    pub const INDOOR: u8 = b'I';
    /// Some access points send a NUL, meaning the same as a space.
    pub const UNSPECIFIED: u8 = 0;
}

/// One decoded subband.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Subband {
    pub first_channel: u8,
    pub num_channels: u8,
    /// Power ceiling in dBm.
    pub max_power_dbm: i8,
}

/// A decoded country element.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CountryIe {
    pub alpha2: [u8; 2],
    pub environment: u8,
    pub subbands: Vec<Subband>,
}

/// Decode a country element body.
///
/// A body that is not a whole number of triplets after the country string is
/// rejected: a trailing partial triplet means the element was truncated, and
/// the channels it would have named are unknown rather than absent.
/// # C: O(N triplets)
pub fn parse(body: &[u8]) -> Option<CountryIe> {
    let head = body.get(..COUNTRY_STRING_LEN)?;
    let alpha2 = parse_alpha2(&head[..2])?;
    let environment = head[2];
    let rest = &body[COUNTRY_STRING_LEN..];
    if rest.len() % TRIPLET_LEN != 0 { return None; }
    let mut subbands = Vec::new();
    for t in rest.chunks_exact(TRIPLET_LEN) {
        if t[0] >= OPERATING_TRIPLET_MARKER { continue; }
        if t[1] == 0 { return None; }
        subbands.push(Subband {
            first_channel: t[0], num_channels: t[1], max_power_dbm: t[2] as i8,
        });
    }
    if subbands.is_empty() { return None; }
    Some(CountryIe { alpha2, environment, subbands })
}

/// Band a subband's channel numbers belong to. A country element does not say
/// which band it means, so the band is inferred from the channel numbers, and
/// the numbering ranges do not overlap between the two bands an element can
/// describe. # C: O(1)
pub fn subband_band(first_channel: u8) -> Band {
    if first_channel <= 14 { Band::Band2Ghz } else { Band::Band5Ghz }
}

/// Turn a decoded element into a regulatory domain.
///
/// A subband's channels are contiguous in channel NUMBER, not in frequency:
/// above 2.4 GHz the numbering steps by four, so the span a subband covers is
/// computed from the first and last channel's frequencies and not from the
/// count times twenty megahertz. # C: O(N subbands)
pub fn to_domain(ie: &CountryIe) -> RegDomain {
    let mut rules: Vec<RegRule> = Vec::new();
    for sb in &ie.subbands {
        let band = subband_band(sb.first_channel);
        let step = if band == Band::Band2Ghz { 1 } else { CHANNEL_STEP_5GHZ };
        let last_channel = sb.first_channel as u32 + (sb.num_channels as u32 - 1) * step;
        let start = channel_to_freq_khz(sb.first_channel as i32, band);
        let end = channel_to_freq_khz(last_channel as i32, band);
        if start == 0 || end == 0 || end < start { continue; }
        rules.push(RegRule {
            freq_range: FreqRange {
                start_khz: start - CHANNEL_HALF_KHZ,
                end_khz: end + CHANNEL_HALF_KHZ,
                max_bandwidth_khz: mhz_to_khz(20),
            },
            power_rule: PowerRule {
                max_antenna_gain_mbi: 0,
                max_eirp_mbm: sb.max_power_dbm as i32 * 100,
                max_psd_mbm_mhz: 0,
            },
            // A country element states no restrictions of its own; what it
            // says is where transmission is permitted and at what power.
            flags: 0,
            dfs_cac_ms: 0,
        });
    }
    rules.sort_by_key(|r| r.freq_range.start_khz);
    RegDomain::new(ie.alpha2, dfs_region::UNSET, rules)
}

/// Decode a country element out of a frame's element stream and turn it into
/// a domain. # C: O(N elements + N subbands)
pub fn domain_from_elements(elements: &[u8]) -> Option<RegDomain> {
    let e = crate::ieee80211::elem::find(elements, crate::ieee80211::elem::id::COUNTRY)?;
    Some(to_domain(&parse(e.body)?))
}
