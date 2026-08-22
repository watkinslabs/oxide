// What a radio's advertisement must contain, and what changing its
// configuration is allowed to do.

extern crate alloc;

use syscall::errno::Errno;

use crate::nl80211::tests_support::{children, find, has, radio, u32_of, u8_of, Call, Req};
use crate::nl80211::wiphy_cmd;
use crate::uapi::attr as a;
use crate::uapi::enums::{protocol_features, Band};
use crate::uapi::nested::{band_attr, bitrate_attr, freq_attr};
use crate::uapi::{ciphers::cipher, cmd};

#[test]
fn get_wiphy_carries_every_identity_attribute() {
    let _g = crate::nl80211::tests_support::lock();
    let (w, _ops) = radio();
    let reply = Req::wiphy(&w).call(wiphy_cmd::get);
    assert_eq!(reply.cmd(), Some(cmd::NEW_WIPHY));
    let b = reply.body();
    assert_eq!(u32_of(b, a::WIPHY), Some(w.index));
    assert!(find(b, a::WIPHY_NAME).is_some());
    assert!(u32_of(b, a::GENERATION).is_some());
    for ty in [a::WIPHY_FRAG_THRESHOLD, a::WIPHY_RTS_THRESHOLD, a::MAX_SCAN_IE_LEN,
               a::CIPHER_SUITES, a::MAX_NUM_PMKIDS, a::MAX_REMAIN_ON_CHANNEL_DURATION,
               a::FEATURE_FLAGS, a::EXT_FEATURES, a::SUPPORTED_IFTYPES,
               a::SOFTWARE_IFTYPES, a::SUPPORTED_COMMANDS, a::WIPHY_BANDS,
               a::WIPHY_RETRY_SHORT, a::WIPHY_RETRY_LONG, a::WIPHY_COVERAGE_CLASS,
               a::MAX_NUM_SCAN_SSIDS, a::MAC] {
        assert!(find(b, ty).is_some(), "attribute {ty} missing from GET_WIPHY");
    }
}

#[test]
fn cipher_suites_are_the_advertised_list() {
    let _g = crate::nl80211::tests_support::lock();
    let (w, _ops) = radio();
    let reply = Req::wiphy(&w).call(wiphy_cmd::get);
    let raw = find(reply.body(), a::CIPHER_SUITES).expect("cipher suites");
    let got: alloc::vec::Vec<u32> = raw.chunks_exact(4)
        .map(|c| u32::from_ne_bytes([c[0], c[1], c[2], c[3]])).collect();
    assert_eq!(got, w.caps.cipher_suites);
    assert!(got.contains(&cipher::CCMP));
}

#[test]
fn supported_iftypes_is_a_flag_per_supported_type() {
    let _g = crate::nl80211::tests_support::lock();
    let (w, _ops) = radio();
    let reply = Req::wiphy(&w).call(wiphy_cmd::get);
    let nest = find(reply.body(), a::SUPPORTED_IFTYPES).expect("iftypes");
    for (ty, payload) in children(nest) {
        assert!(payload.is_empty(), "iftype {ty} is a flag and carries no payload");
        assert!(w.caps.interface_modes & (1 << ty as u32) != 0);
    }
    let count = children(nest).len() as u32;
    assert_eq!(count, w.caps.interface_modes.count_ones());
}

#[test]
fn bands_are_numbered_by_band_and_carry_channels_and_rates() {
    let _g = crate::nl80211::tests_support::lock();
    let (w, _ops) = radio();
    let reply = Req::wiphy(&w).call(wiphy_cmd::get);
    let bands = find(reply.body(), a::WIPHY_BANDS).expect("bands");
    let listed = children(bands);
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].0 as u32, Band::Band2Ghz.as_u32());
    assert_eq!(listed[1].0 as u32, Band::Band5Ghz.as_u32());

    let freqs = find(listed[0].1, band_attr::FREQS).expect("freqs");
    assert_eq!(children(freqs).len(), w.caps.bands[0].channels.len());
    let rates = find(listed[0].1, band_attr::RATES).expect("rates");
    let rate_list = children(rates);
    assert_eq!(rate_list.len(), w.caps.bands[0].bitrates.len());
    // The first 2 GHz rate is a direct-sequence rate, so it carries the
    // short-preamble flag; the last is not, so it must not.
    assert!(has(rate_list[0].1, bitrate_attr::SHORTPREAMBLE_2GHZ));
    assert!(!has(rate_list.last().unwrap().1, bitrate_attr::SHORTPREAMBLE_2GHZ));
    assert!(u32_of(rate_list[0].1, bitrate_attr::RATE).is_some());
}

#[test]
fn a_disabled_channel_carries_the_flag_and_an_enabled_one_carries_none() {
    let _g = crate::nl80211::tests_support::lock();
    let (w, _ops) = radio();
    let reply = Req::wiphy(&w).call(wiphy_cmd::get);
    let bands = find(reply.body(), a::WIPHY_BANDS).expect("bands");
    let five = children(bands)[1].1;
    let freqs = children(find(five, band_attr::FREQS).expect("freqs"));

    let enabled = freqs[0].1;
    assert_eq!(u32_of(enabled, freq_attr::FREQ), Some(5180));
    assert!(!has(enabled, freq_attr::DISABLED),
            "an enabled channel must carry no DISABLED flag at all");
    assert!(!has(enabled, freq_attr::RADAR));
    // Power is reported in millibel-milliwatts, not decibel-milliwatts.
    assert_eq!(u32_of(enabled, freq_attr::MAX_TX_POWER), Some(2300));

    let disabled = freqs[4].1;
    assert_eq!(u32_of(disabled, freq_attr::FREQ), Some(5260));
    assert!(has(disabled, freq_attr::DISABLED));

    let radar = freqs[5].1;
    assert!(has(radar, freq_attr::RADAR));
    assert!(has(radar, freq_attr::NO_IR));
    assert_eq!(u32_of(radar, freq_attr::DFS_CAC_TIME), Some(60_000));
    assert!(u32_of(radar, freq_attr::DFS_STATE).is_some());
}

#[test]
fn band_capability_blobs_are_split_into_their_attributes() {
    let _g = crate::nl80211::tests_support::lock();
    let (w, _ops) = radio();
    let reply = Req::wiphy(&w).call(wiphy_cmd::get);
    let bands = find(reply.body(), a::WIPHY_BANDS).expect("bands");
    let five = children(bands)[1].1;
    assert_eq!(find(five, band_attr::HT_MCS_SET).map(<[u8]>::len), Some(16));
    assert!(find(five, band_attr::HT_CAPA).is_some());
    assert_eq!(u8_of(five, band_attr::HT_AMPDU_FACTOR), Some(0));
    assert_eq!(find(five, band_attr::VHT_MCS_SET).map(<[u8]>::len), Some(8));
    assert!(find(five, band_attr::VHT_CAPA).is_some());
    // The 2 GHz band has no very-high-throughput capability, so it reports
    // none rather than an empty one.
    let two = children(bands)[0].1;
    assert!(find(two, band_attr::VHT_CAPA).is_none());
}

#[test]
fn dump_reports_every_radio_and_terminates() {
    let _g = crate::nl80211::tests_support::lock();
    let (a1, _o1) = radio();
    let (a2, _o2) = radio();
    let reply = Req::bare().dump().call(wiphy_cmd::dump);
    let parts = reply.parts();
    assert_eq!(parts.len(), 2);
    assert!(reply.is_done());
    let indexes: alloc::vec::Vec<u32> = parts.iter()
        .filter_map(|p| u32_of(p, a::WIPHY)).collect();
    assert!(indexes.contains(&a1.index) && indexes.contains(&a2.index));
}

#[test]
fn dump_honours_the_radio_filter() {
    let _g = crate::nl80211::tests_support::lock();
    let (a1, _o1) = radio();
    let (_a2, _o2) = radio();
    let reply = Req::wiphy(&a1).dump().call(wiphy_cmd::dump);
    assert_eq!(reply.parts().len(), 1);
}

#[test]
fn get_on_an_absent_radio_reports_no_device() {
    let _g = crate::nl80211::tests_support::lock();
    let mut req = Req::bare();
    req.u32(a::WIPHY, 99);
    assert!(req.call(wiphy_cmd::get).is_err(Errno::Enodev));
}

#[test]
fn get_naming_no_radio_is_a_bad_request() {
    let _g = crate::nl80211::tests_support::lock();
    let _ = radio();
    assert!(Req::bare().call(wiphy_cmd::get).is_err(Errno::Einval));
}

#[test]
fn set_applies_a_valid_configuration_and_calls_the_driver() {
    let _g = crate::nl80211::tests_support::lock();
    let (w, ops) = radio();
    let mut req = Req::wiphy(&w);
    req.u8(a::WIPHY_RETRY_SHORT, 5);
    req.u32(a::WIPHY_RTS_THRESHOLD, 1000);
    let before = w.generation();
    assert!(req.call(wiphy_cmd::set).is_ack());
    assert_eq!(w.config().retry_short, 5);
    assert_eq!(w.config().rts_threshold, 1000);
    assert!(w.generation() > before);
    assert!(ops.calls.lock().unwrap().contains(&Call::SetWiphyParams));
}

#[test]
fn set_renames_the_radio_through_the_live_command_path() {
    let _g = crate::nl80211::tests_support::lock();
    let (w, _ops) = radio();
    let before = w.generation();
    let mut req = Req::wiphy(&w);
    req.text(a::WIPHY_NAME, "lab-radio");
    assert!(req.call(wiphy_cmd::set).is_ack());
    assert_eq!(w.name(), "lab-radio");
    assert!(w.generation() > before);
    let reply = Req::wiphy(&w).call(wiphy_cmd::get);
    assert_eq!(find(reply.body(), a::WIPHY_NAME), Some(&b"lab-radio\0"[..]));
}

#[test]
fn set_refuses_duplicate_reserved_and_overlong_radio_names() {
    let _g = crate::nl80211::tests_support::lock();
    let (first, _ops1) = radio();
    let (second, _ops2) = radio();

    let mut duplicate = Req::wiphy(&second);
    duplicate.text(a::WIPHY_NAME, &first.name());
    assert!(duplicate.call(wiphy_cmd::set).is_err(Errno::Einval));

    let mut reserved = Req::wiphy(&first);
    reserved.text(a::WIPHY_NAME, "phy7");
    assert!(reserved.call(wiphy_cmd::set).is_err(Errno::Einval));

    let mut overlong = Req::wiphy(&first);
    overlong.text(a::WIPHY_NAME, "radio-name-is-too-long");
    assert!(overlong.call(wiphy_cmd::set).is_err(Errno::Einval));
    assert_eq!(first.name(), "phy0");
}

#[test]
fn set_rejects_a_whole_request_when_one_field_is_out_of_range() {
    let _g = crate::nl80211::tests_support::lock();
    let (w, ops) = radio();
    let mut req = Req::wiphy(&w);
    req.u8(a::WIPHY_RETRY_SHORT, 5);
    // A retry limit of zero is not "no retries"; it is out of range.
    req.u8(a::WIPHY_RETRY_LONG, 0);
    assert!(req.call(wiphy_cmd::set).is_err(Errno::Einval));
    assert_eq!(w.config().retry_short, 7, "no field may change when one is refused");
    assert!(!ops.calls.lock().unwrap().contains(&Call::SetWiphyParams));
}

#[test]
fn set_refuses_half_an_antenna_pair() {
    let _g = crate::nl80211::tests_support::lock();
    let (w, _ops) = radio();
    let mut req = Req::wiphy(&w);
    req.u32(a::WIPHY_ANTENNA_TX, 1);
    assert!(req.call(wiphy_cmd::set).is_err(Errno::Einval));
}

#[test]
fn set_refuses_an_antenna_the_radio_does_not_have() {
    let _g = crate::nl80211::tests_support::lock();
    let (w, _ops) = radio();
    let mut req = Req::wiphy(&w);
    req.u32(a::WIPHY_ANTENNA_TX, 0xf);
    req.u32(a::WIPHY_ANTENNA_RX, 1);
    assert!(req.call(wiphy_cmd::set).is_err(Errno::Einval));
}

#[test]
fn protocol_features_reports_the_split_dump() {
    let _g = crate::nl80211::tests_support::lock();
    let reply = Req::bare().call(wiphy_cmd::get_protocol_features);
    assert_eq!(u32_of(reply.body(), a::PROTOCOL_FEATURES),
               Some(protocol_features::SPLIT_WIPHY_DUMP));
}
