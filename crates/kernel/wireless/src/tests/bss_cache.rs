// The scan cache: identity, the hidden-SSID rule, expiry, and holds.
//
// The hidden-network rule is the one that breaks connecting when it is wrong.
// A network that hides its name sends an empty SSID in its beacon and the real
// one in its probe response, so a beacon arriving after a probe response must
// not overwrite the elements that carry the name.

extern crate alloc;

use alloc::vec::Vec;

use crate::ieee80211::{elem, MacAddr};
use crate::scan::{Bss, BssCache, BssUpdate, ScanRequest, SCAN_RESULT_EXPIRE_NS};
use crate::uapi::enums::{scan_flags, ChanWidth};

const AP1: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x11]);
const AP2: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x22]);

fn ies(ssid: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(elem::id::SSID);
    out.push(ssid.len() as u8);
    out.extend_from_slice(ssid);
    out.push(elem::id::DS_PARAMS);
    out.push(1);
    out.push(6);
    out
}

fn bss(bssid: MacAddr, freq: u32, ssid: &[u8], signal_mbm: i32, now_ns: u64) -> Bss {
    Bss {
        bssid, freq, freq_offset: 0, tsf: 0, beacon_interval: 100, capability: 0x0431,
        ies: ies(ssid), beacon_ies: Vec::new(), presp_data: false, signal_mbm,
        last_seen_ns: now_ns, first_seen_ns: now_ns, chan_width: ChanWidth::Width20,
        status: None, hold: 0,
    }
}

#[test]
fn one_network_on_one_channel_is_one_entry_however_many_frames_arrive() {
    let mut c = BssCache::default();
    assert_eq!(c.insert(bss(AP1, 2437, b"net", -4000, 100), false, 100),
               BssUpdate::Inserted);
    assert_eq!(c.insert(bss(AP1, 2437, b"net", -3500, 200), false, 200),
               BssUpdate::Updated);
    assert_eq!(c.len(), 1);
    assert_eq!(c.find(AP1, 2437, b"net").unwrap().signal_mbm, -3500);
    assert_eq!(c.find(AP1, 2437, b"net").unwrap().last_seen_ns, 200);
}

#[test]
fn the_same_address_on_a_different_channel_is_a_different_entry() {
    let mut c = BssCache::default();
    c.insert(bss(AP1, 2437, b"net", -4000, 100), false, 100);
    c.insert(bss(AP1, 5180, b"net", -5000, 100), false, 100);
    assert_eq!(c.len(), 2);
    assert!(c.find(AP1, 2437, b"net").is_some());
    assert!(c.find(AP1, 5180, b"net").is_some());
}

#[test]
fn two_radios_serving_one_network_are_two_entries() {
    let mut c = BssCache::default();
    c.insert(bss(AP1, 2437, b"net", -4000, 100), false, 100);
    c.insert(bss(AP2, 2437, b"net", -6000, 100), false, 100);
    assert_eq!(c.len(), 2);
    // The connect path picks the stronger of them.
    assert_eq!(c.best_for(b"net", None, None).unwrap().bssid, AP1);
    // Pinning an address overrides the signal preference.
    assert_eq!(c.best_for(b"net", Some(AP2), None).unwrap().bssid, AP2);
    // Pinning a channel with no match yields nothing.
    assert!(c.best_for(b"net", None, Some(5180)).is_none());
}

#[test]
fn a_beacon_does_not_overwrite_the_name_a_probe_response_supplied() {
    let mut c = BssCache::default();
    // The beacon hides the name.
    c.insert(bss(AP1, 2437, b"", -4000, 100), false, 100);
    assert!(c.find(AP1, 2437, b"").unwrap().is_hidden());
    // The probe response carries it.
    c.insert(bss(AP1, 2437, b"hidden-net", -4000, 200), true, 200);
    let e = c.find(AP1, 2437, b"hidden-net").unwrap();
    assert_eq!(e.ssid(), b"hidden-net");
    assert!(e.presp_data);
    // A later beacon still hides it — and must not take the name away.
    c.insert(bss(AP1, 2437, b"", -4000, 300), false, 300);
    let e = c.find(AP1, 2437, b"hidden-net").unwrap();
    assert_eq!(e.ssid(), b"hidden-net", "the probe response's name survives the beacon");
    assert_eq!(e.last_seen_ns, 300, "but the beacon still refreshes the entry");
    assert!(!e.beacon_ies.is_empty(), "and its own elements are kept separately");
    assert_eq!(c.len(), 1);
}

#[test]
fn an_all_zero_name_counts_as_hidden() {
    let mut c = BssCache::default();
    c.insert(bss(AP1, 2437, &[0, 0, 0, 0], -4000, 100), false, 100);
    assert!(c.snapshot()[0].is_hidden());
    assert!(c.snapshot()[0].ssid().is_empty());
}

#[test]
fn a_network_never_heard_by_probe_response_reports_its_beacon_elements() {
    let mut c = BssCache::default();
    c.insert(bss(AP1, 2437, b"net", -4000, 100), false, 100);
    let e = c.find(AP1, 2437, b"net").unwrap();
    assert!(!e.presp_data);
    assert_eq!(e.ies, e.beacon_ies);
}

#[test]
fn entries_older_than_the_expiry_are_dropped_and_newer_ones_are_not() {
    let mut c = BssCache::default();
    let now = 10 * SCAN_RESULT_EXPIRE_NS;
    c.insert(bss(AP1, 2437, b"old", -4000, now - SCAN_RESULT_EXPIRE_NS - 1), false,
             now - SCAN_RESULT_EXPIRE_NS - 1);
    c.insert(bss(AP2, 2437, b"new", -4000, now), false, now);
    assert_eq!(c.len(), 2);
    assert_eq!(c.expire_now(now), 1);
    assert_eq!(c.len(), 1);
    assert!(c.find(AP2, 2437, b"new").is_some());
    assert!(c.find(AP1, 2437, b"old").is_none());
}

#[test]
fn an_entry_someone_is_holding_is_not_expired_out_from_under_them() {
    // The connect path resolves a network and then uses it across several
    // steps; an expiry underneath it would leave the attempt pointing at
    // nothing.
    let mut c = BssCache::default();
    let now = 10 * SCAN_RESULT_EXPIRE_NS;
    c.insert(bss(AP1, 2437, b"net", -4000, 0), false, 0);
    assert!(c.hold(AP1, 2437));
    assert_eq!(c.expire_now(now), 0);
    assert!(c.find(AP1, 2437, b"net").is_some());
    c.release(AP1, 2437);
    assert_eq!(c.expire_now(now), 1);
    assert!(c.is_empty());
}

#[test]
fn a_hold_on_a_network_that_is_not_cached_reports_that_it_is_not() {
    let mut c = BssCache::default();
    assert!(!c.hold(AP1, 2437));
    // Releasing one that was never held does not underflow.
    c.release(AP1, 2437);
}

#[test]
fn the_generation_moves_on_every_change_a_reader_can_see() {
    let mut c = BssCache::default();
    let g0 = c.generation;
    c.insert(bss(AP1, 2437, b"net", -4000, 100), false, 100);
    let g1 = c.generation;
    assert_ne!(g0, g1);
    c.insert(bss(AP1, 2437, b"net", -3000, 200), false, 200);
    let g2 = c.generation;
    assert_ne!(g1, g2);
    c.expire_now(200);
    assert_eq!(c.generation, g2, "an expiry that dropped nothing is not a change");
    c.expire_now(200 + SCAN_RESULT_EXPIRE_NS + 1);
    assert_ne!(c.generation, g2);
}

#[test]
fn a_station_is_marked_associated_to_at_most_one_network() {
    use crate::uapi::nested::bss_status;
    let mut c = BssCache::default();
    c.insert(bss(AP1, 2437, b"a", -4000, 100), false, 100);
    c.insert(bss(AP2, 5180, b"b", -4000, 100), false, 100);
    c.set_status(AP1, 2437, Some(bss_status::ASSOCIATED));
    assert_eq!(c.find(AP1, 2437, b"a").unwrap().status, Some(bss_status::ASSOCIATED));
    assert_eq!(c.find(AP2, 5180, b"b").unwrap().status, None);
    // Roaming moves the mark rather than adding a second.
    c.set_status(AP2, 5180, Some(bss_status::ASSOCIATED));
    assert_eq!(c.find(AP1, 2437, b"a").unwrap().status, None);
    assert_eq!(c.find(AP2, 5180, b"b").unwrap().status, Some(bss_status::ASSOCIATED));
    c.set_status(AP2, 5180, None);
    assert_eq!(c.find(AP2, 5180, b"b").unwrap().status, None);
}

#[test]
fn a_snapshot_reports_the_most_recently_heard_first() {
    let mut c = BssCache::default();
    c.insert(bss(AP1, 2437, b"a", -4000, 100), false, 100);
    c.insert(bss(AP2, 5180, b"b", -4000, 500), false, 500);
    let s = c.snapshot();
    assert_eq!(s[0].bssid, AP2);
    assert_eq!(s[1].bssid, AP1);
}

#[test]
fn age_is_reported_in_milliseconds_and_never_runs_backwards() {
    let mut c = BssCache::default();
    c.insert(bss(AP1, 2437, b"net", -4000, 1_000_000_000), false, 1_000_000_000);
    let e = &c.snapshot()[0];
    assert_eq!(e.age_ms(1_000_000_000), 0);
    assert_eq!(e.age_ms(1_500_000_000), 500);
    // A clock that appears to move backwards reports zero, not a huge age.
    assert_eq!(e.age_ms(0), 0);
}

#[test]
fn a_request_says_whether_it_probes_and_whether_it_flushes() {
    let mut r = ScanRequest::default();
    assert!(!r.is_active(), "no names means listen only");
    assert!(!r.flushes());
    r.ssids.push(crate::scan::ScanSsid(Vec::new()));
    assert!(r.is_active(), "one empty name is a wildcard probe, not no probe");
    r.flags = scan_flags::FLUSH;
    assert!(r.flushes());
}

#[test]
fn privacy_is_read_from_the_capability_field() {
    let mut c = BssCache::default();
    let mut b = bss(AP1, 2437, b"open", -4000, 100);
    b.capability = 0x0421;
    c.insert(b, false, 100);
    assert!(!c.find(AP1, 2437, b"open").unwrap().privacy());
    let mut b = bss(AP2, 2437, b"wpa", -4000, 100);
    b.capability = 0x0431;
    c.insert(b, false, 100);
    assert!(c.find(AP2, 2437, b"wpa").unwrap().privacy());
}
