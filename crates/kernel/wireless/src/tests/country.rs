// The country element: reading a regulatory domain out of a beacon.
//
// The two failures this pins are the ones that invent spectrum. A triplet
// whose first byte marks an operating class is not a subband, and reading it
// as one produces channels that do not exist; and a subband's channels are
// contiguous in channel NUMBER, which above 2.4 GHz means the span is four
// times what a count-times-twenty-megahertz reading would give.

extern crate alloc;

use alloc::vec::Vec;

use crate::chan::mhz_to_khz;
use crate::reg::country_ie::{self, environment, OPERATING_TRIPLET_MARKER};
use crate::uapi::enums::Band;

/// Build a country element body: the three-byte country string then triplets.
fn body(alpha2: &[u8; 2], env: u8, triplets: &[(u8, u8, i8)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(alpha2);
    out.push(env);
    for (first, count, power) in triplets {
        out.push(*first);
        out.push(*count);
        out.push(*power as u8);
    }
    out
}

#[test]
fn a_two_point_four_gigahertz_subband_spans_its_channels() {
    let ie = country_ie::parse(&body(b"US", environment::ANY, &[(1, 11, 20)])).unwrap();
    assert_eq!(ie.alpha2, *b"US");
    assert_eq!(ie.environment, environment::ANY);
    assert_eq!(ie.subbands.len(), 1);
    let d = country_ie::to_domain(&ie);
    assert_eq!(d.alpha2, *b"US");
    assert_eq!(d.rules.len(), 1);
    // Channels 1 to 11 run 2412 to 2462, plus ten megahertz of guard each side.
    assert_eq!(d.rules[0].freq_range.start_khz, mhz_to_khz(2402));
    assert_eq!(d.rules[0].freq_range.end_khz, mhz_to_khz(2472));
    assert_eq!(d.rules[0].power_rule.max_eirp_mbm, 2000);
    assert!(d.rule_for(mhz_to_khz(2412), 20_000).is_some());
    assert!(d.rule_for(mhz_to_khz(2467), 20_000).is_none());
}

#[test]
fn a_five_gigahertz_subband_steps_by_four_channel_numbers() {
    // Four channels starting at 36 are 36, 40, 44, 48 — 5180 to 5240, not
    // 5180 to 5200 as a count-times-twenty reading would give.
    let ie = country_ie::parse(&body(b"DE", environment::ANY, &[(36, 4, 23)])).unwrap();
    let d = country_ie::to_domain(&ie);
    assert_eq!(d.rules[0].freq_range.start_khz, mhz_to_khz(5170));
    assert_eq!(d.rules[0].freq_range.end_khz, mhz_to_khz(5250));
    assert!(d.rule_for(mhz_to_khz(5240), 20_000).is_some(),
        "channel 48 is the fourth channel of the subband");
    assert!(d.rule_for(mhz_to_khz(5260), 20_000).is_none());
}

#[test]
fn an_operating_triplet_is_skipped_and_not_read_as_a_subband() {
    // Reading the marker byte as a first channel would invent a subband at a
    // channel number no band has.
    let raw = body(b"US", environment::ANY,
                   &[(1, 11, 20), (OPERATING_TRIPLET_MARKER, 0, 0), (36, 4, 23)]);
    let ie = country_ie::parse(&raw).unwrap();
    assert_eq!(ie.subbands.len(), 2, "the operating triplet contributes no subband");
    assert_eq!(ie.subbands[0].first_channel, 1);
    assert_eq!(ie.subbands[1].first_channel, 36);
    let d = country_ie::to_domain(&ie);
    assert_eq!(d.rules.len(), 2);
}

#[test]
fn a_trailing_partial_triplet_makes_the_element_unreadable() {
    let mut raw = body(b"US", environment::ANY, &[(1, 11, 20)]);
    raw.push(36);
    raw.push(4);
    assert!(country_ie::parse(&raw).is_none(),
        "a truncated element's remaining channels are unknown, not absent");
}

#[test]
fn a_subband_of_no_channels_makes_the_element_unreadable() {
    assert!(country_ie::parse(&body(b"US", environment::ANY, &[(1, 0, 20)])).is_none());
}

#[test]
fn an_element_with_no_subbands_is_not_a_domain() {
    assert!(country_ie::parse(&body(b"US", environment::ANY, &[])).is_none());
    assert!(country_ie::parse(&body(b"US", environment::ANY,
        &[(OPERATING_TRIPLET_MARKER, 1, 1)])).is_none());
}

#[test]
fn a_body_too_short_for_the_country_string_is_unreadable() {
    assert!(country_ie::parse(b"").is_none());
    assert!(country_ie::parse(b"U").is_none());
    assert!(country_ie::parse(b"US").is_none());
}

#[test]
fn a_non_country_code_is_refused() {
    assert!(country_ie::parse(&body(b"00", environment::ANY, &[(1, 11, 20)])).is_some(),
        "the reserved codes still parse as codes");
    assert!(country_ie::parse(&body(b"1X", environment::ANY, &[(1, 11, 20)])).is_none());
}

#[test]
fn a_lower_case_code_is_normalised() {
    let ie = country_ie::parse(&body(b"jp", environment::INDOOR, &[(1, 13, 20)])).unwrap();
    assert_eq!(ie.alpha2, *b"JP");
    assert_eq!(ie.environment, environment::INDOOR);
}

#[test]
fn the_band_is_inferred_from_the_channel_number() {
    assert_eq!(country_ie::subband_band(1), Band::Band2Ghz);
    assert_eq!(country_ie::subband_band(14), Band::Band2Ghz);
    assert_eq!(country_ie::subband_band(36), Band::Band5Ghz);
    assert_eq!(country_ie::subband_band(165), Band::Band5Ghz);
}

#[test]
fn a_negative_power_ceiling_survives_the_conversion() {
    // The power byte is signed; a regulator can state a ceiling below one
    // milliwatt, and reading it unsigned would turn that into a very high one.
    let ie = country_ie::parse(&body(b"US", environment::ANY, &[(1, 11, -3)])).unwrap();
    assert_eq!(ie.subbands[0].max_power_dbm, -3);
    let d = country_ie::to_domain(&ie);
    assert_eq!(d.rules[0].power_rule.max_eirp_mbm, -300);
}

#[test]
fn a_domain_is_read_straight_out_of_an_element_stream() {
    let ie_body = body(b"GB", environment::OUTDOOR, &[(1, 13, 20), (36, 4, 23)]);
    let mut elements = Vec::new();
    elements.push(crate::ieee80211::elem::id::SSID);
    elements.push(3);
    elements.extend_from_slice(b"net");
    elements.push(crate::ieee80211::elem::id::COUNTRY);
    elements.push(ie_body.len() as u8);
    elements.extend_from_slice(&ie_body);
    let d = country_ie::domain_from_elements(&elements).unwrap();
    assert_eq!(d.alpha2, *b"GB");
    assert_eq!(d.rules.len(), 2);
    // Rules come back in frequency order however the element listed them.
    assert!(d.rules[0].freq_range.start_khz < d.rules[1].freq_range.start_khz);

    // A stream with no country element yields no domain.
    assert!(country_ie::domain_from_elements(&elements[..5]).is_none());
}

#[test]
fn the_resulting_domain_states_no_restrictions_of_its_own() {
    // A country element says where transmission is permitted and at what
    // power. It does not say a channel needs radar detection; inventing that
    // restriction here would make a legal channel unusable, and inventing its
    // absence would be worse.
    let ie = country_ie::parse(&body(b"US", environment::ANY, &[(52, 4, 20)])).unwrap();
    let d = country_ie::to_domain(&ie);
    assert_eq!(d.rules[0].flags, 0);
    assert_eq!(d.dfs_region, crate::uapi::enums::dfs_region::UNSET);
}
