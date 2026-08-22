// cfg80211 BSS changes reaching the softmac interface and its driver.

use wireless::ops::ApSettings;
use wireless::uapi::enums::IfType;
use wireless::wdev::BssParams;

use crate::flags::bss_changed;
use crate::tests_fixture::{chandef, drop_radio, iface, radio, AP};

#[test]
fn a_bss_change_reaches_the_live_softmac_configuration_and_driver() {
    let (local, rec) = radio(AP);
    let sdata = iface(&local, IfType::Ap, "ap0");
    let wiphy = local.wiphy().expect("fixture radio has a configuration device");
    wiphy.ops.start_ap(&wiphy, &sdata.wdev, &ApSettings {
        chandef: Some(chandef()), ssid: alloc::vec![b'a', b'p'], ..Default::default()
    }).expect("fixture access point starts");
    rec.bss.lock().clear();

    wiphy.ops.change_bss(&wiphy, &sdata.wdev, &BssParams {
        cts_protection: true, short_preamble: true, short_slot_time: true,
        basic_rates: alloc::vec![0x82, 0x84], ap_isolate: true, ..Default::default()
    }).expect("softmac accepts the BSS change");

    let conf = sdata.bss_conf();
    assert!(conf.use_cts_prot && conf.use_short_preamble && conf.use_short_slot);
    assert_eq!(conf.basic_rates, 0b11);
    assert!(sdata.with(|s| s.ap_isolate));
    let calls = rec.bss.lock();
    let (_, changed) = calls.last().expect("driver sees the changed configuration");
    assert_eq!(*changed & (bss_changed::ERP_CTS_PROT | bss_changed::ERP_PREAMBLE
        | bss_changed::ERP_SLOT | bss_changed::BASIC_RATES),
        bss_changed::ERP_CTS_PROT | bss_changed::ERP_PREAMBLE
            | bss_changed::ERP_SLOT | bss_changed::BASIC_RATES);
    drop(calls);
    drop_radio(&local);
}

#[test]
fn a_softmac_bss_change_before_beaconing_is_refused() {
    let (local, _rec) = radio(AP);
    let sdata = iface(&local, IfType::Ap, "ap0");
    let wiphy = local.wiphy().expect("fixture radio has a configuration device");
    let got = wiphy.ops.change_bss(&wiphy, &sdata.wdev, &BssParams {
        basic_rates: alloc::vec![0x82], ..Default::default()
    });
    assert_eq!(got, Err(syscall::errno::Errno::Enoent));
    drop_radio(&local);
}
