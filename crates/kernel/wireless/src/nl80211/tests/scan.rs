// Scan triggering and the results dump.

extern crate alloc;

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::events::{inform_bss_frame, RxBeacon};
use crate::ieee80211::{fctl, MacAddr};
use crate::nl80211::scan_cmd;
use crate::nl80211::tests_support::{find, has, lock, radio_with, u16_of, u32_of, Call, Req};
use crate::uapi::attr as a;
use crate::uapi::cmd;
use crate::uapi::enums::{scan_flags, IfType};
use crate::uapi::nested::bss;

/// A beacon frame for one network on one channel. # C: O(len)
fn beacon(bssid: MacAddr, ssid: &[u8]) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&0x0123_4567_89ab_cdefu64.to_le_bytes());
    body.extend_from_slice(&100u16.to_le_bytes());
    body.extend_from_slice(&0x0011u16.to_le_bytes());
    body.push(crate::ieee80211::elem::id::SSID);
    body.push(ssid.len() as u8);
    body.extend_from_slice(ssid);
    crate::nl80211::tests_support::mgmt_frame(fctl::mgmt_stype::BEACON, bssid, bssid, &body)
}

struct TestNow;

impl Drop for TestNow {
    fn drop(&mut self) { scan_cmd::set_reference_now_for_test(0); }
}

fn test_now(now_ns: u64) -> TestNow {
    scan_cmd::set_reference_now_for_test(now_ns);
    TestNow
}

#[test]
fn a_bare_trigger_scans_every_channel() {
    let _g = lock();
    let (w, ops, d) = radio_with(IfType::Station);
    assert!(Req::wdev(&d).call(scan_cmd::trigger).is_ack());
    assert_eq!(ops.calls.lock().unwrap()[0],
               Call::Scan { ssids: 0, freqs: Vec::new(), flags: 0 });
    assert!(w.with_state(|s| s.scan.is_some()));
}

#[test]
fn a_second_trigger_while_one_is_live_is_busy() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    assert!(Req::wdev(&d).call(scan_cmd::trigger).is_ack());
    assert!(Req::wdev(&d).call(scan_cmd::trigger).is_err(Errno::Ebusy));
}

#[test]
fn a_driver_refusal_leaves_no_stuck_scan_and_the_next_one_starts() {
    let _g = lock();
    let (w, ops, d) = radio_with(IfType::Station);
    ops.program.lock().unwrap().scan_fails = Some(Errno::Ebusy);
    assert!(Req::wdev(&d).call(scan_cmd::trigger).is_err(Errno::Ebusy));
    assert!(w.with_state(|s| s.scan.is_none()),
            "a refused scan must not leave state that makes every later scan busy");
    ops.program.lock().unwrap().scan_fails = None;
    assert!(Req::wdev(&d).call(scan_cmd::trigger).is_ack());
}

#[test]
fn more_networks_than_the_radio_probes_for_is_a_bad_request() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.nest(a::SCAN_SSIDS, |out| {
        for i in 0..5u16 { netlink::genetlink::attr::put(out, i, b"net"); }
    });
    assert!(req.call(scan_cmd::trigger).is_err(Errno::Einval));
}

#[test]
fn exactly_as_many_networks_as_the_radio_probes_for_is_accepted() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.nest(a::SCAN_SSIDS, |out| {
        for i in 0..4u16 { netlink::genetlink::attr::put(out, i, b"net"); }
    });
    assert!(req.call(scan_cmd::trigger).is_ack());
    assert!(matches!(ops.calls.lock().unwrap()[0], Call::Scan { ssids: 4, .. }));
}

#[test]
fn a_frequency_the_radio_has_no_channel_for_is_a_bad_request() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.nest(a::SCAN_FREQUENCIES, |out| {
        netlink::genetlink::attr::put_u32(out, 0, 2412);
        netlink::genetlink::attr::put_u32(out, 1, 9999);
    });
    assert!(req.call(scan_cmd::trigger).is_err(Errno::Einval));
}

#[test]
fn a_named_channel_list_reaches_the_driver() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.nest(a::SCAN_FREQUENCIES, |out| {
        netlink::genetlink::attr::put_u32(out, 0, 2412);
        netlink::genetlink::attr::put_u32(out, 1, 2437);
    });
    assert!(req.call(scan_cmd::trigger).is_ack());
    assert_eq!(ops.calls.lock().unwrap()[0],
               Call::Scan { ssids: 0, freqs: alloc::vec![2412, 2437], flags: 0 });
}

#[test]
fn an_element_blob_longer_than_the_radio_takes_is_a_bad_request() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    let big = alloc::vec![0u8; 512];
    req.bytes(a::IE, &big);
    assert!(req.call(scan_cmd::trigger).is_err(Errno::Einval));
}

#[test]
fn a_scan_flag_this_build_does_not_know_is_unsupported() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.u32(a::SCAN_FLAGS, 1 << 20);
    assert!(req.call(scan_cmd::trigger).is_err(Errno::Eopnotsupp));
}

#[test]
fn a_known_flag_the_radio_lacks_is_unsupported() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    // The fixture radio advertises no low-span scanning.
    req.u32(a::SCAN_FLAGS, scan_flags::LOW_SPAN);
    assert!(req.call(scan_cmd::trigger).is_err(Errno::Eopnotsupp));
}

#[test]
fn a_randomised_scan_needs_both_halves_of_the_address() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.u32(a::SCAN_FLAGS, scan_flags::RANDOM_ADDR);
    req.mac(a::MAC, MacAddr([0x02, 0, 0, 0, 0, 0]));
    assert!(req.call(scan_cmd::trigger).is_err(Errno::Einval));
}

#[test]
fn a_randomised_address_outside_its_own_mask_is_refused() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.u32(a::SCAN_FLAGS, scan_flags::RANDOM_ADDR);
    req.mac(a::MAC, MacAddr([0x02, 0x11, 0, 0, 0, 0]));
    req.mac(a::MAC_MASK, MacAddr([0xff, 0x00, 0, 0, 0, 0]));
    assert!(req.call(scan_cmd::trigger).is_err(Errno::Einval));
}

#[test]
fn a_well_formed_randomised_scan_is_accepted() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    let mut req = Req::wdev(&d);
    req.u32(a::SCAN_FLAGS, scan_flags::RANDOM_ADDR);
    req.mac(a::MAC, MacAddr([0x02, 0, 0, 0, 0, 0]));
    req.mac(a::MAC_MASK, MacAddr([0xff, 0, 0, 0, 0, 0]));
    assert!(req.call(scan_cmd::trigger).is_ack());
    assert!(matches!(ops.calls.lock().unwrap()[0],
                     Call::Scan { flags, .. } if flags == scan_flags::RANDOM_ADDR));
}

#[test]
fn a_scan_on_an_interface_that_cannot_scan_is_unsupported() {
    let _g = lock();
    let (w, ops) = crate::nl80211::tests_support::radio();
    let params = crate::ops::NewIfaceParams {
        name: alloc::string::String::from("nan0"), iftype: IfType::Nan,
        addr: None, use_4addr: None, mntr_flags: 0,
    };
    let d = crate::ops::Cfg80211Ops::add_virtual_intf(ops.as_ref(), &w, &params).unwrap();
    w.add_wdev(d.clone());
    assert!(Req::wdev(&d).call(scan_cmd::trigger).is_err(Errno::Eopnotsupp));
}

#[test]
fn abort_marks_the_scan_and_reaches_the_driver() {
    let _g = lock();
    let (w, ops, d) = radio_with(IfType::Station);
    assert!(Req::wdev(&d).call(scan_cmd::trigger).is_ack());
    assert!(Req::wdev(&d).call(scan_cmd::abort).is_ack());
    assert!(ops.calls.lock().unwrap().contains(&Call::AbortScan));
    assert!(w.with_state(|s| s.scan.as_ref().is_some_and(|sc| sc.aborting)));
}

#[test]
fn abort_with_no_scan_running_succeeds_without_reaching_the_driver() {
    let _g = lock();
    let (_w, ops, d) = radio_with(IfType::Station);
    assert!(Req::wdev(&d).call(scan_cmd::abort).is_ack());
    assert!(!ops.calls.lock().unwrap().contains(&Call::AbortScan));
}

#[test]
fn a_results_dump_reports_one_message_per_network_and_terminates() {
    let _g = lock();
    let _now = test_now(1_000_000_000);
    let (w, _ops, d) = radio_with(IfType::Station);
    for (i, name) in [&b"one"[..], &b"two"[..], &b"three"[..]].iter().enumerate() {
        let bssid = MacAddr([0x02, 0, 0, 0, 0, i as u8]);
        inform_bss_frame(&w, &RxBeacon {
            freq: 2412, signal_mbm: -4000, now_ns: 1_000_000_000,
            frame: &beacon(bssid, name),
        }).expect("cached");
    }
    let reply = Req::wdev(&d).dump().call(scan_cmd::dump);
    assert_eq!(reply.parts().len(), 3);
    assert!(reply.is_done());
}

#[test]
fn a_reported_network_carries_the_attributes_a_supplicant_reads() {
    let _g = lock();
    let _now = test_now(7_000_000_000);
    let (w, _ops, d) = radio_with(IfType::Station);
    let bssid = MacAddr([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    let heard = 5_000_000_000;
    inform_bss_frame(&w, &RxBeacon {
        freq: 2412, signal_mbm: -4200, now_ns: heard,
        frame: &beacon(bssid, b"oxide"),
    }).expect("cached");
    let reply = Req::wdev(&d).dump().call(scan_cmd::dump);
    let parts = reply.parts();
    let part = parts[0];
    assert!(u32_of(part, a::GENERATION).is_some());
    let nest = find(part, a::BSS).expect("bss nest");
    assert_eq!(find(nest, bss::BSSID), Some(&bssid.0[..]));
    assert_eq!(u32_of(nest, bss::FREQUENCY), Some(2412));
    assert_eq!(u16_of(nest, bss::BEACON_INTERVAL), Some(100));
    assert_eq!(u16_of(nest, bss::CAPABILITY), Some(0x0011));
    assert!(find(nest, bss::TSF).is_some());
    assert!(find(nest, bss::INFORMATION_ELEMENTS).is_some());
    assert!(find(nest, bss::SIGNAL_MBM).is_some());
    let age = u32_of(nest, bss::SEEN_MS_AGO).expect("age");
    assert_eq!(age, 2_000, "age came from the dump's single clock snapshot");
    assert!(find(nest, bss::LAST_SEEN_BOOTTIME).is_some());
    assert!(u32_of(nest, bss::CHAN_WIDTH).is_some());
    // Nothing heard this network by probe response, so the flag is absent.
    assert!(!has(nest, bss::PRESP_DATA));
    assert!(!has(nest, bss::STATUS));
}

#[test]
fn an_empty_cache_dumps_only_the_terminator() {
    let _g = lock();
    let (_w, _ops, d) = radio_with(IfType::Station);
    let reply = Req::wdev(&d).dump().call(scan_cmd::dump);
    assert!(reply.parts().is_empty());
    assert!(reply.is_done());
}

#[test]
fn the_results_command_number_is_the_new_results_one() {
    let _g = lock();
    let (w, _ops, d) = radio_with(IfType::Station);
    inform_bss_frame(&w, &RxBeacon {
        freq: 2412, signal_mbm: -4000, now_ns: timekeeper::monotonic_ns(),
        frame: &beacon(MacAddr([0x02, 0, 0, 0, 0, 1]), b"x"),
    }).expect("cached");
    let reply = Req::wdev(&d).dump().call(scan_cmd::dump);
    assert_eq!(reply.part_cmds(), alloc::vec![cmd::NEW_SCAN_RESULTS]);
}

#[test]
fn a_dump_expires_a_result_older_than_the_live_monotonic_deadline() {
    let _g = lock();
    let _now = test_now(crate::scan::SCAN_RESULT_EXPIRE_NS + 2);
    let (w, _ops, d) = radio_with(IfType::Station);
    let heard = 1;
    inform_bss_frame(&w, &RxBeacon {
        freq: 2412, signal_mbm: -4000, now_ns: heard,
        frame: &beacon(MacAddr([0x02, 0, 0, 0, 0, 2]), b"old"),
    }).expect("cached");
    let reply = Req::wdev(&d).dump().call(scan_cmd::dump);
    assert!(reply.parts().is_empty());
    assert!(reply.is_done());
}
