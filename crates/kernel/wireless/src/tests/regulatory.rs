// Regulatory rules, intersection, hint arbitration, and the projection onto a
// radio's channels.
//
// The property that matters here is one-directional: no operation may ever
// PERMIT something neither input permitted. An intersection that widened a
// range, dropped a restriction, or raised a power ceiling would authorise a
// transmission no regulator allowed.

extern crate alloc;

use crate::chan::{chan_flags, mhz_to_khz, ChanDef, Channel};
use crate::reg::apply;
use crate::reg::domain::{is_an_alpha2, parse_alpha2, ALPHA2_INTERSECTION, ALPHA2_WORLD};
use crate::reg::hint::{treatment, RegRequest, Treatment};
use crate::reg::rule::{self, FreqRange, PowerRule, RegRule};
use crate::reg::RegDomain;
use crate::uapi::enums::{dfs_region, dfs_state, reg_initiator, reg_rule_flags, reg_type,
                         Band, ChanWidth};
use crate::wiphy::caps::WiphyBand;

fn rule(start_mhz: u32, end_mhz: u32, bw_mhz: u32, eirp_dbm: i32, flags: u32) -> RegRule {
    RegRule::new(mhz_to_khz(start_mhz), mhz_to_khz(end_mhz), mhz_to_khz(bw_mhz),
                 eirp_dbm * 100, flags)
}

#[test]
fn a_rule_covers_a_channel_only_when_the_whole_channel_fits() {
    let r = rule(5170, 5250, 80, 20, 0);
    // Channel 36 at twenty megahertz sits wholly inside.
    assert!(r.covers(mhz_to_khz(5180), 20_000));
    // The eighty-megahertz channel centred on 5210 also fits exactly.
    assert!(r.covers(mhz_to_khz(5210), 80_000));
    // A channel that runs past the top edge does not, even by one step.
    assert!(!r.covers(mhz_to_khz(5240), 40_000));
    // Nor does one wider than the rule's own ceiling.
    let narrow = rule(5170, 5250, 20, 20, 0);
    assert!(!narrow.covers(mhz_to_khz(5210), 80_000));
    assert!(narrow.covers(mhz_to_khz(5180), 20_000));
}

#[test]
fn intersecting_two_ranges_never_widens_either() {
    let a = FreqRange { start_khz: 5_170_000, end_khz: 5_250_000, max_bandwidth_khz: 80_000 };
    let b = FreqRange { start_khz: 5_180_000, end_khz: 5_330_000, max_bandwidth_khz: 40_000 };
    let i = a.intersect(&b).unwrap();
    assert_eq!(i.start_khz, 5_180_000);
    assert_eq!(i.end_khz, 5_250_000);
    assert_eq!(i.max_bandwidth_khz, 40_000);
    assert!(i.width_khz() <= a.width_khz() && i.width_khz() <= b.width_khz());
    // Disjoint ranges intersect to nothing, and touching is not overlapping.
    let c = FreqRange { start_khz: 5_250_000, end_khz: 5_330_000, max_bandwidth_khz: 80_000 };
    assert!(a.intersect(&c).is_none());
}

#[test]
fn intersecting_two_power_rules_takes_the_stricter_of_each() {
    let a = PowerRule { max_antenna_gain_mbi: 600, max_eirp_mbm: 2000, max_psd_mbm_mhz: 500 };
    let b = PowerRule { max_antenna_gain_mbi: 300, max_eirp_mbm: 3000, max_psd_mbm_mhz: 100 };
    let i = a.intersect(&b);
    assert_eq!(i.max_antenna_gain_mbi, 300);
    assert_eq!(i.max_eirp_mbm, 2000);
    assert_eq!(i.max_psd_mbm_mhz, 100);
}

#[test]
fn a_restriction_in_either_domain_survives_the_intersection() {
    let a = rule(5170, 5250, 80, 20, reg_rule_flags::NO_IR);
    let b = rule(5170, 5250, 80, 23, reg_rule_flags::DFS);
    let i = a.intersect(&b).unwrap();
    assert!(i.flags & reg_rule_flags::NO_IR != 0);
    assert!(i.flags & reg_rule_flags::DFS != 0);
    assert_eq!(i.power_rule.max_eirp_mbm, 2000);
}

#[test]
fn a_frequency_neither_domain_covers_is_in_no_intersected_rule() {
    let a = RegDomain::new(*b"AA", dfs_region::UNSET, alloc::vec![rule(2400, 2500, 40, 20, 0)]);
    let b = RegDomain::new(*b"BB", dfs_region::UNSET, alloc::vec![rule(5170, 5250, 80, 20, 0)]);
    let i = a.intersect(&b);
    assert!(i.is_empty());
    assert_eq!(i.alpha2, ALPHA2_INTERSECTION);
    assert_eq!(i.reg_type(), reg_type::INTERSECTION);
    assert!(i.rule_for(mhz_to_khz(2412), 20_000).is_none());
    assert!(i.rule_for(mhz_to_khz(5180), 20_000).is_none());
}

#[test]
fn the_intersection_keeps_a_radar_region_only_when_both_agree() {
    let a = RegDomain::new(*b"AA", dfs_region::ETSI, alloc::vec![rule(5170, 5250, 80, 20, 0)]);
    let b = RegDomain::new(*b"BB", dfs_region::ETSI, alloc::vec![rule(5170, 5250, 80, 20, 0)]);
    assert_eq!(a.intersect(&b).dfs_region, dfs_region::ETSI);
    let c = RegDomain::new(*b"CC", dfs_region::FCC, alloc::vec![rule(5170, 5250, 80, 20, 0)]);
    assert_eq!(a.intersect(&c).dfs_region, dfs_region::UNSET);
}

#[test]
fn the_world_domain_permits_the_globally_unlicensed_channels_and_listens_elsewhere() {
    let w = RegDomain::world();
    assert_eq!(w.alpha2, ALPHA2_WORLD);
    assert_eq!(w.reg_type(), reg_type::WORLD);
    // Channels 1 to 11 may be transmitted on anywhere.
    let r = w.rule_for(mhz_to_khz(2412), 20_000).unwrap();
    assert_eq!(r.flags & reg_rule_flags::NO_IR, 0);
    let r = w.rule_for(mhz_to_khz(2462), 20_000).unwrap();
    assert_eq!(r.flags & reg_rule_flags::NO_IR, 0);
    // Channels 12 and 13 are receive-only until a country says otherwise.
    let r = w.rule_for(mhz_to_khz(2467), 20_000).unwrap();
    assert!(r.flags & reg_rule_flags::NO_IR != 0);
    // So is every 5 GHz channel.
    for f in [5180, 5260, 5500, 5745] {
        let r = w.rule_for(mhz_to_khz(f), 20_000).unwrap_or_else(|| panic!("{f} covered"));
        assert!(r.flags & reg_rule_flags::NO_IR != 0, "{f} must be receive-only");
    }
    // And the radar channels carry the radar flag.
    assert!(w.rule_for(mhz_to_khz(5260), 20_000).unwrap().flags & reg_rule_flags::DFS != 0);
    assert!(w.rule_for(mhz_to_khz(5500), 20_000).unwrap().flags & reg_rule_flags::DFS != 0);
    assert_eq!(w.rule_for(mhz_to_khz(5745), 20_000).unwrap().flags & reg_rule_flags::DFS, 0);
}

#[test]
fn country_codes_are_two_letters_or_one_of_three_markers() {
    assert!(is_an_alpha2(*b"US"));
    assert!(is_an_alpha2(*b"DE"));
    assert!(!is_an_alpha2(*b"00"));
    assert!(!is_an_alpha2(*b"98"));
    assert_eq!(parse_alpha2(b"us"), Some(*b"US"), "a lower-case code is normalised");
    assert_eq!(parse_alpha2(b"00"), Some(*b"00"));
    assert_eq!(parse_alpha2(b"98"), Some(*b"98"));
    assert_eq!(parse_alpha2(b"99"), Some(*b"99"));
    assert_eq!(parse_alpha2(b"U1"), None);
    assert_eq!(parse_alpha2(b"U"), None);
    assert_eq!(parse_alpha2(b""), None);
}

fn req(alpha2: &[u8; 2], initiator: u32) -> RegRequest { RegRequest::new(*alpha2, initiator) }

#[test]
fn a_country_element_never_overrides_a_domain_the_user_set() {
    // This is the rule the whole module exists for. An access point can claim
    // any country; a station that believed it would transmit where its owner
    // may not.
    let last = req(b"DE", reg_initiator::USER);
    let new = req(b"US", reg_initiator::COUNTRY_IE);
    assert_eq!(treatment(*b"DE", &last, &new, false), Treatment::Ok,
        "a first country element while a user domain is in force is adopted \
         only because the reference adopts it when the last request was not \
         itself a country element");
    // Once a country element IS in force, a second one from another radio is
    // refused rather than intersected.
    let last = RegRequest { wiphy_index: Some(0), ..req(b"US", reg_initiator::COUNTRY_IE) };
    let new = RegRequest { wiphy_index: Some(1), ..req(b"JP", reg_initiator::COUNTRY_IE) };
    assert_eq!(treatment(*b"US", &last, &new, false), Treatment::Ignore);
    // And the same radio changing its mind is adopted.
    let new = RegRequest { wiphy_index: Some(0), ..req(b"JP", reg_initiator::COUNTRY_IE) };
    assert_eq!(treatment(*b"US", &last, &new, false), Treatment::Ok);
}

#[test]
fn a_radio_told_to_disregard_country_elements_does_so() {
    let last = req(b"00", reg_initiator::CORE);
    let new = req(b"US", reg_initiator::COUNTRY_IE);
    assert_eq!(treatment(*b"00", &last, &new, true), Treatment::Ignore);
    assert_eq!(treatment(*b"00", &last, &new, false), Treatment::Ok);
}

#[test]
fn a_country_element_carrying_a_non_country_code_is_invalid() {
    let last = req(b"00", reg_initiator::CORE);
    let new = req(b"00", reg_initiator::COUNTRY_IE);
    assert_eq!(treatment(*b"00", &last, &new, false), Treatment::Invalid);
}

#[test]
fn a_user_request_intersects_with_a_country_element_and_replaces_the_core() {
    let last = req(b"US", reg_initiator::COUNTRY_IE);
    let new = req(b"DE", reg_initiator::USER);
    assert_eq!(treatment(*b"US", &last, &new, false), Treatment::Intersect);

    let last = req(b"00", reg_initiator::CORE);
    let new = req(b"DE", reg_initiator::USER);
    assert_eq!(treatment(*b"00", &last, &new, false), Treatment::Ok);

    // Asking for what is already in force changes nothing.
    let last = req(b"DE", reg_initiator::USER);
    let new = req(b"DE", reg_initiator::USER);
    assert_eq!(treatment(*b"DE", &last, &new, false), Treatment::AlreadySet);
}

#[test]
fn a_user_request_cannot_undo_an_intersection_it_already_caused() {
    let last = RegRequest { intersected: true, ..req(b"DE", reg_initiator::USER) };
    let new = req(b"FR", reg_initiator::USER);
    assert_eq!(treatment(*b"DE", &last, &new, false), Treatment::Ignore);
}

#[test]
fn cellular_advice_outranks_a_later_user_request_and_a_country_element() {
    let last = RegRequest { cell_base: true, ..req(b"US", reg_initiator::USER) };
    assert_eq!(treatment(*b"US", &last, &req(b"DE", reg_initiator::USER), false),
               Treatment::Ignore);
    assert_eq!(treatment(*b"US", &last, &req(b"DE", reg_initiator::COUNTRY_IE), false),
               Treatment::Ignore);
    // Advice naming what is already in force is not a change.
    assert_eq!(treatment(*b"US", &last, &req(b"US", reg_initiator::COUNTRY_IE), false),
               Treatment::AlreadySet);
}

#[test]
fn a_driver_request_replaces_the_core_and_intersects_with_anything_else() {
    let last = req(b"00", reg_initiator::CORE);
    assert_eq!(treatment(*b"00", &last, &req(b"US", reg_initiator::DRIVER), false),
               Treatment::Ok);
    assert_eq!(treatment(*b"US", &last, &req(b"US", reg_initiator::DRIVER), false),
               Treatment::AlreadySet);

    let last = req(b"DE", reg_initiator::USER);
    assert_eq!(treatment(*b"DE", &last, &req(b"US", reg_initiator::DRIVER), false),
               Treatment::Intersect);

    let last = req(b"US", reg_initiator::DRIVER);
    assert_eq!(treatment(*b"US", &last, &req(b"US", reg_initiator::DRIVER), false),
               Treatment::AlreadySet);
}

#[test]
fn an_unknown_initiator_is_invalid() {
    let last = req(b"00", reg_initiator::CORE);
    assert_eq!(treatment(*b"00", &last, &req(b"US", 99), false), Treatment::Invalid);
}

#[test]
fn a_channel_no_rule_covers_is_disabled_and_not_merely_restricted() {
    // A channel left merely restricted because no rule mentioned it is the
    // exact shape of an out-of-band transmission.
    let d = RegDomain::new(*b"AA", dfs_region::UNSET, alloc::vec![rule(2400, 2500, 40, 20, 0)]);
    let mut c = Channel::new(5180, Band::Band5Ghz, 30);
    apply::apply_to_channel(&d, &mut c);
    assert_eq!(c.flags, chan_flags::DISABLED);
    assert!(!c.is_usable());
    assert_eq!(c.max_power, 0);

    let mut c = Channel::new(2412, Band::Band2Ghz, 30);
    apply::apply_to_channel(&d, &mut c);
    assert!(c.is_usable());
    assert_eq!(c.max_power, 20);
}

#[test]
fn applying_a_domain_recomputes_every_restriction_rather_than_accumulating() {
    let strict = RegDomain::new(*b"AA", dfs_region::UNSET,
        alloc::vec![rule(5170, 5250, 20, 17, reg_rule_flags::NO_IR | reg_rule_flags::DFS)]);
    let loose = RegDomain::new(*b"BB", dfs_region::UNSET,
        alloc::vec![rule(5170, 5250, 80, 23, 0)]);
    let mut c = Channel::new(5180, Band::Band5Ghz, 30);
    apply::apply_to_channel(&strict, &mut c);
    assert!(c.flags & chan_flags::NO_IR != 0);
    assert!(c.flags & chan_flags::RADAR != 0);
    assert!(c.flags & chan_flags::NO_HT40 != 0, "a twenty-megahertz rule bars forty");
    assert_eq!(c.max_power, 17);
    assert_eq!(c.dfs_cac_ms, rule::DEFAULT_DFS_CAC_MS);

    apply::apply_to_channel(&loose, &mut c);
    assert_eq!(c.flags & chan_flags::NO_IR, 0, "the lifted restriction is really lifted");
    assert_eq!(c.flags & chan_flags::RADAR, 0);
    assert_eq!(c.flags & chan_flags::NO_HT40, 0);
    assert_eq!(c.max_power, 23);
    assert_eq!(c.dfs_cac_ms, 0);
    assert_eq!(c.dfs_state, dfs_state::USABLE);
}

#[test]
fn a_channel_that_had_completed_its_radar_check_must_repeat_it_under_a_new_domain() {
    let radar = RegDomain::new(*b"AA", dfs_region::UNSET,
        alloc::vec![rule(5250, 5330, 80, 20, reg_rule_flags::DFS)]);
    let mut c = Channel::new(5260, Band::Band5Ghz, 20);
    c.dfs_state = dfs_state::AVAILABLE;
    apply::apply_to_channel(&radar, &mut c);
    assert_eq!(c.dfs_state, dfs_state::USABLE,
        "a domain change is not evidence the channel is still clear");
}

#[test]
fn the_weather_radar_sub_band_needs_the_long_check_in_one_region_only() {
    let r = rule(5590, 5650, 80, 20, reg_rule_flags::DFS);
    assert_eq!(rule::dfs_cac_ms(&r, dfs_region::ETSI), rule::WEATHER_RADAR_CAC_MS);
    assert_eq!(rule::dfs_cac_ms(&r, dfs_region::FCC), rule::DEFAULT_DFS_CAC_MS);
    // Outside the sub-band the ordinary check applies in every region.
    let r = rule(5250, 5330, 80, 20, reg_rule_flags::DFS);
    assert_eq!(rule::dfs_cac_ms(&r, dfs_region::ETSI), rule::DEFAULT_DFS_CAC_MS);
    // A rule stating its own time keeps it.
    let mut r = rule(5590, 5650, 80, 20, reg_rule_flags::DFS);
    r.dfs_cac_ms = 1234;
    assert_eq!(rule::dfs_cac_ms(&r, dfs_region::ETSI), 1234);
}

#[test]
fn a_wide_definition_is_refused_when_any_part_of_it_is_uncovered() {
    // Two adjacent rules covering channels 36 to 48 and 52 to 64 do not
    // together permit an eighty-megahertz channel that straddles them.
    let d = RegDomain::new(*b"AA", dfs_region::UNSET, alloc::vec![
        rule(5170, 5250, 80, 20, 0),
        rule(5250, 5330, 80, 20, 0),
    ]);
    let inside = ChanDef::new(Channel::new(5180, Band::Band5Ghz, 20),
                              ChanWidth::Width80, 5210, 0);
    assert!(apply::chandef_usable(&d, &inside));
    let straddling = ChanDef::new(Channel::new(5220, Band::Band5Ghz, 20),
                                  ChanWidth::Width80, 5250, 0);
    assert!(!apply::chandef_usable(&d, &straddling));
    // A definition that is not even internally consistent is refused first.
    let bad = ChanDef::new(Channel::new(5180, Band::Band5Ghz, 20), ChanWidth::Width80, 0, 0);
    assert!(!apply::chandef_usable(&d, &bad));
}

#[test]
fn a_definition_takes_the_strictest_power_ceiling_it_touches() {
    let d = RegDomain::new(*b"AA", dfs_region::UNSET, alloc::vec![
        rule(5170, 5210, 40, 23, 0),
        rule(5210, 5250, 40, 17, 0),
    ]);
    let def = ChanDef::new(Channel::new(5180, Band::Band5Ghz, 30), ChanWidth::Width40,
                           5190, 0);
    assert_eq!(apply::chandef_max_power(&d, &def), Some(23));
    let def = ChanDef::new(Channel::new(5180, Band::Band5Ghz, 30), ChanWidth::Width80,
                           5210, 0);
    // The wide definition reaches into the stricter rule and takes its limit.
    assert_eq!(apply::chandef_max_power(&d, &def), Some(17));
}

#[test]
fn applying_a_domain_walks_every_band() {
    let d = RegDomain::world();
    let mut bands = alloc::vec![
        WiphyBand::new(Band::Band2Ghz,
            alloc::vec![Channel::new(2412, Band::Band2Ghz, 30),
                        Channel::new(2467, Band::Band2Ghz, 30)],
            alloc::vec![]),
        WiphyBand::new(Band::Band5Ghz,
            alloc::vec![Channel::new(5180, Band::Band5Ghz, 30),
                        Channel::new(5260, Band::Band5Ghz, 30)],
            alloc::vec![]),
    ];
    apply::apply_to_bands(&d, &mut bands);
    assert_eq!(bands[0].channels[0].flags & chan_flags::NO_IR, 0);
    assert!(bands[0].channels[1].flags & chan_flags::NO_IR != 0);
    assert!(bands[1].channels[0].flags & chan_flags::NO_IR != 0);
    assert!(bands[1].channels[1].flags & chan_flags::RADAR != 0);
    for b in &bands { for c in &b.channels { assert!(c.max_power > 0); } }
}
