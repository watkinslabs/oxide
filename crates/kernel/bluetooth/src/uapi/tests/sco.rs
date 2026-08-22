//! SCO ABI constants and struct widths.

use crate::uapi::sco::*;

#[test]
fn the_struct_widths_are_the_ones_the_abi_defines() {
    assert_eq!(SOCKADDR_SCO_LEN, 8);
    assert_eq!(SCO_OPTIONS_LEN, 2);
    assert_eq!(SCO_CONNINFO_LEN, 6);
    assert_eq!(BT_VOICE_LEN, 2);
    assert_eq!(BT_CODEC_LEN, 7);
    assert_eq!(BT_CODECS_HDR_LEN, 1);
    assert_eq!(SETUP_SYNC_CONN_LEN, 17);
    assert_eq!(ACCEPT_SYNC_CONN_LEN, 21);
    assert_eq!(ENHANCED_SETUP_SYNC_CONN_LEN, 59);
    assert_eq!(SYNC_CONN_COMPLETE_LEN, 17);
}

#[test]
fn the_codec_identifiers_and_bandwidth_are_the_ones_the_abi_defines() {
    assert_eq!((BT_CODEC_CVSD, BT_CODEC_TRANSPARENT, BT_CODEC_MSBC), (0x02, 0x03, 0x05));
    assert_eq!(SCO_BANDWIDTH, 8000);
    assert_eq!(SCO_BANDWIDTH, 0x1f40);
    assert_eq!((SCO_RETRANS_POWER, SCO_RETRANS_QUALITY, SCO_RETRANS_DONT_CARE), (0x01, 0x02, 0xff));
    assert_eq!(SCO_MAX_LATENCY_DONT_CARE, 0xffff);
}

#[test]
fn a_completion_event_decodes_only_at_full_width() {
    let buf = [0u8; SYNC_CONN_COMPLETE_LEN];
    assert!(SyncConnComplete::from_wire(&buf).is_some());
    assert!(SyncConnComplete::from_wire(&buf[..SYNC_CONN_COMPLETE_LEN - 1]).is_none());
}
