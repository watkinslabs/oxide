//! Command-encoding contract: field order, widths and the bandwidth both
//! directions ask for.

use crate::sco::cmd::{AcceptSyncConn, SetupSyncConn};
use crate::sco::param::ESCO_PARAM_CVSD;
use crate::uapi::bt::{BdAddr, BT_VOICE_CVSD_16BIT, BT_VOICE_TRANSPARENT};
use crate::uapi::hci::{EDR_ESCO_MASK, ESCO_2EV3};
use crate::uapi::sco as u;

#[test]
fn the_setup_command_round_trips_at_its_documented_width() {
    let cp = SetupSyncConn::new(0x0042, BT_VOICE_CVSD_16BIT, &ESCO_PARAM_CVSD[0]);
    let w = cp.to_wire();
    assert_eq!(w.len(), u::SETUP_SYNC_CONN_LEN);
    assert_eq!(w.len(), 17);
    assert_eq!(SetupSyncConn::from_wire(&w), Some(cp));
    assert!(SetupSyncConn::from_wire(&w[..16]).is_none());
}

#[test]
fn the_setup_command_carries_the_chosen_row_and_the_standard_bandwidth() {
    for row in ESCO_PARAM_CVSD.iter() {
        let cp = SetupSyncConn::new(7, BT_VOICE_CVSD_16BIT, row);
        assert_eq!(cp.max_latency, row.max_latency);
        assert_eq!(cp.retrans_effort, row.retrans_effort);
        assert_eq!(cp.pkt_type, row.pkt_type);
        assert_eq!(cp.tx_bandwidth, u::SCO_BANDWIDTH);
        assert_eq!(cp.rx_bandwidth, u::SCO_BANDWIDTH);
        assert_eq!(cp.voice_setting, BT_VOICE_CVSD_16BIT);
    }
}

#[test]
fn the_setup_command_fields_are_in_the_documented_order() {
    let cp = SetupSyncConn { handle: 0x0102, tx_bandwidth: 0x03040506, rx_bandwidth: 0x0708090a,
                             max_latency: 0x0b0c, voice_setting: 0x0d0e, retrans_effort: 0x0f,
                             pkt_type: 0x1011 };
    let w = cp.to_wire();
    assert_eq!(&w[0..2], &[0x02, 0x01]);
    assert_eq!(&w[2..6], &[0x06, 0x05, 0x04, 0x03]);
    assert_eq!(&w[6..10], &[0x0a, 0x09, 0x08, 0x07]);
    assert_eq!(&w[10..12], &[0x0c, 0x0b]);
    assert_eq!(&w[12..14], &[0x0e, 0x0d]);
    assert_eq!(w[14], 0x0f);
    assert_eq!(&w[15..17], &[0x11, 0x10]);
}

#[test]
fn the_accept_command_round_trips_at_its_documented_width() {
    let cp = AcceptSyncConn::new(BdAddr([1, 2, 3, 4, 5, 6]), BT_VOICE_CVSD_16BIT, EDR_ESCO_MASK);
    let w = cp.to_wire();
    assert_eq!(w.len(), u::ACCEPT_SYNC_CONN_LEN);
    assert_eq!(w.len(), 21);
    assert_eq!(AcceptSyncConn::from_wire(&w), Some(cp));
    assert_eq!(&w[0..6], &[1, 2, 3, 4, 5, 6]);
    assert!(AcceptSyncConn::from_wire(&w[..20]).is_none());
}

#[test]
fn the_accept_command_takes_the_air_codings_latency_and_effort() {
    let addr = BdAddr([9; 6]);
    let cp = AcceptSyncConn::new(addr, BT_VOICE_TRANSPARENT, EDR_ESCO_MASK);
    assert_eq!(cp.max_latency, u::SCO_MAX_LATENCY_T1);
    assert_eq!(cp.retrans_effort, u::SCO_RETRANS_QUALITY);
    assert_eq!(cp.content_format, BT_VOICE_TRANSPARENT);

    let cp = AcceptSyncConn::new(addr, BT_VOICE_TRANSPARENT, EDR_ESCO_MASK & !ESCO_2EV3);
    assert_eq!(cp.max_latency, u::SCO_MAX_LATENCY_T2);

    let cp = AcceptSyncConn::new(addr, BT_VOICE_CVSD_16BIT, EDR_ESCO_MASK);
    assert_eq!(cp.max_latency, u::SCO_MAX_LATENCY_DONT_CARE);
    assert_eq!(cp.retrans_effort, u::SCO_RETRANS_DONT_CARE);
    assert_eq!(cp.tx_bandwidth, u::SCO_BANDWIDTH);
}

#[test]
fn the_completion_event_round_trips_at_its_documented_width() {
    let ev = u::SyncConnComplete {
        status: 0, handle: 0x000c, bdaddr: BdAddr([6, 5, 4, 3, 2, 1]),
        link_type: crate::uapi::hci::ESCO_LINK, tx_interval: 12, retrans_window: 6,
        rx_pkt_len: 60, tx_pkt_len: 60, air_mode: 0x02,
    };
    let mut w = [0u8; u::SYNC_CONN_COMPLETE_LEN];
    assert!(ev.to_wire(&mut w));
    assert_eq!(w.len(), 17);
    assert_eq!(u::SyncConnComplete::from_wire(&w), Some(ev));
    assert!(u::SyncConnComplete::from_wire(&w[..16]).is_none());
    assert_eq!(&w[1..3], &0x000cu16.to_le_bytes());
    assert_eq!(&w[3..9], &[6, 5, 4, 3, 2, 1]);
    assert_eq!(w[16], 0x02);
}
