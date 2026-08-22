//! Link contract: the attempt walk under real refusals, and what a completion
//! event does to the link.

use crate::sco::cmd::SetupSyncConn;
use crate::sco::conn::{self, Outcome, SyncLink};
use crate::sco::link::CmdLog;
use crate::sco::param::{LinkCaps, ESCO_PARAM_CVSD, ESCO_PARAM_MSBC};
use crate::uapi::bt::{BdAddr, BT_CLOSED, BT_CONNECTED, BT_VOICE_CVSD_16BIT, BT_VOICE_TRANSPARENT};
use crate::uapi::hci::{ESCO_LINK, SCO_LINK};
use crate::uapi::hci_cmd::{HCI_OP_ACCEPT_SYNC_CONN_REQ, HCI_OP_SETUP_SYNC_CONN};
use crate::uapi::sco::{SyncConnComplete, BT_CODEC_CVSD, BT_CODEC_TRANSPARENT};

const FULL: LinkCaps = LinkCaps { esco: true, esco_2m: true, enhanced_setup: false };
const ENHANCED: LinkCaps = LinkCaps { esco: true, esco_2m: true, enhanced_setup: true };
const NO_2M: LinkCaps = LinkCaps { esco: true, esco_2m: false, enhanced_setup: false };

fn complete(status: u8) -> SyncConnComplete {
    SyncConnComplete { status, handle: 0x2a, bdaddr: BdAddr([1; 6]), link_type: ESCO_LINK,
                       tx_interval: 12, retrans_window: 6, rx_pkt_len: 60, tx_pkt_len: 60,
                       air_mode: 0x02 }
}

#[test]
fn the_first_attempt_sends_the_first_row() {
    let mut l = SyncLink::new(BdAddr([1; 6]), BT_VOICE_CVSD_16BIT, FULL);
    let mut tx = CmdLog::new();
    let cp = l.setup(0x0007, &mut tx).unwrap();
    assert_eq!(l.attempt, 1);
    assert_eq!(cp.max_latency, ESCO_PARAM_CVSD[0].max_latency);
    let (opcode, params) = tx.last_cmd().unwrap();
    assert_eq!(*opcode, HCI_OP_SETUP_SYNC_CONN);
    assert_eq!(SetupSyncConn::from_wire(params), Some(cp));
    assert_eq!(cp.handle, 0x0007, "the command names the baseband link");
}

#[test]
fn a_retryable_refusal_makes_the_next_attempt() {
    let mut l = SyncLink::new(BdAddr([1; 6]), BT_VOICE_CVSD_16BIT, FULL);
    let mut tx = CmdLog::new();
    l.setup(7, &mut tx).unwrap();
    for expected in 2..=ESCO_PARAM_CVSD.len() as u16 {
        assert_eq!(l.on_complete(&complete(0x1a), 7, &mut tx), Outcome::Retried);
        assert_eq!(l.attempt, expected);
        let cp = SetupSyncConn::from_wire(&tx.last_cmd().unwrap().1).unwrap();
        assert_eq!(cp.max_latency, ESCO_PARAM_CVSD[expected as usize - 1].max_latency);
    }
    // The table is exhausted; the link closes.
    assert_eq!(l.on_complete(&complete(0x1a), 7, &mut tx), Outcome::Failed(0x1a));
    assert_eq!(l.state, BT_CLOSED);
}

#[test]
fn a_permanent_refusal_closes_the_link_at_once() {
    let mut l = SyncLink::new(BdAddr([1; 6]), BT_VOICE_CVSD_16BIT, FULL);
    let mut tx = CmdLog::new();
    l.setup(7, &mut tx).unwrap();
    let before = tx.len();
    assert_eq!(l.on_complete(&complete(0x05), 7, &mut tx), Outcome::Failed(0x05));
    assert_eq!(tx.len(), before, "no further attempt is made");
    assert_eq!(l.state, BT_CLOSED);
    assert!(conn::retryable(0x1a) && !conn::retryable(0x05));
}

#[test]
fn an_inbound_link_does_not_retry() {
    let mut l = SyncLink::new(BdAddr([1; 6]), BT_VOICE_CVSD_16BIT, FULL);
    let mut tx = CmdLog::new();
    l.accept(&mut tx);
    assert_eq!(tx.last_cmd().unwrap().0, HCI_OP_ACCEPT_SYNC_CONN_REQ);
    assert_eq!(l.on_complete(&complete(0x1a), 7, &mut tx), Outcome::Failed(0x1a));
}

#[test]
fn success_adopts_what_the_controller_reports() {
    let mut l = SyncLink::new(BdAddr([1; 6]), BT_VOICE_CVSD_16BIT, FULL);
    let mut tx = CmdLog::new();
    l.setup(7, &mut tx).unwrap();
    let mut ev = complete(0);
    ev.link_type = SCO_LINK;
    ev.tx_pkt_len = 48;
    assert_eq!(l.on_complete(&ev, 7, &mut tx), Outcome::Connected);
    assert_eq!(l.state, BT_CONNECTED);
    assert_eq!(l.handle, 0x2a);
    assert_eq!(l.link_type, SCO_LINK);
    assert_eq!(l.mtu, 48);
}

#[test]
fn a_link_without_two_megabit_esco_starts_at_the_row_it_can_use() {
    let mut l = SyncLink::new(BdAddr([1; 6]), BT_VOICE_CVSD_16BIT, NO_2M);
    let mut tx = CmdLog::new();
    let cp = l.setup(7, &mut tx).unwrap();
    assert_eq!(l.attempt, 3);
    assert_eq!(cp.max_latency, ESCO_PARAM_CVSD[2].max_latency);
}

#[test]
fn a_wideband_link_walks_the_wideband_table() {
    let mut l = SyncLink::new(BdAddr([1; 6]), BT_VOICE_TRANSPARENT, FULL);
    let mut tx = CmdLog::new();
    let cp = l.setup(7, &mut tx).unwrap();
    assert_eq!(cp.max_latency, ESCO_PARAM_MSBC[0].max_latency);
    assert_eq!(l.codec.id, BT_CODEC_TRANSPARENT);
    assert_eq!(l.on_complete(&complete(0x11), 7, &mut tx), Outcome::Retried);
    assert_eq!(l.attempt, 2);
    assert_eq!(l.on_complete(&complete(0x11), 7, &mut tx), Outcome::Failed(0x11));
}

#[test]
fn a_fully_capable_wideband_link_uses_enhanced_setup() {
    let mut l = SyncLink::new(BdAddr([1; 6]), BT_VOICE_TRANSPARENT, ENHANCED);
    let mut tx = CmdLog::new();
    l.setup(7, &mut tx).unwrap();
    assert_eq!(tx.last_cmd().unwrap().0, crate::uapi::hci_cmd::HCI_OP_ENHANCED_SETUP_SYNC_CONN);
    assert_eq!(tx.last_cmd().unwrap().1.len(), crate::uapi::sco::ENHANCED_SETUP_SYNC_CONN_LEN);
}

#[test]
fn the_default_codec_follows_the_air_coding() {
    assert_eq!(conn::default_codec(BT_VOICE_CVSD_16BIT).id, BT_CODEC_CVSD);
    assert_eq!(conn::default_codec(BT_VOICE_TRANSPARENT).id, BT_CODEC_TRANSPARENT);
    assert_eq!(conn::default_setting(), BT_VOICE_CVSD_16BIT);
}

#[test]
fn every_status_the_reference_retries_is_retried() {
    for s in [0x10u8, 0x0d, 0x11, 0x1c, 0x1a, 0x1e, 0x1f, 0x20] { assert!(conn::retryable(s)); }
    for s in [0x00u8, 0x01, 0x04, 0x05, 0x06, 0x08, 0x0c, 0x13, 0x16, 0x3c] {
        assert!(!conn::retryable(s), "status 0x{s:02x} is permanent");
    }
}
