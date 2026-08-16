//! The load commands and the out-of-band data command.

use super::*;
use crate::uapi::bt::{BdAddr, BDADDR_LE_PUBLIC};

fn addr() -> AddrInfo { AddrInfo::new(BdAddr([1, 2, 3, 4, 5, 6]), BDADDR_LE_PUBLIC) }

fn link_key(n: u8) -> LinkKeyInfo {
    LinkKeyInfo { addr: addr(), key_type: n, val: [n; 16], pin_len: 0 }
}

#[test]
fn link_keys_round_trip_and_the_count_leads() {
    let v = LoadLinkKeys { debug_keys: 1, keys: alloc::vec![link_key(0), link_key(4)] };
    let buf = v.encode();
    assert_eq!(buf.len(), 3 + 2 * MGMT_LINK_KEY_INFO_SIZE);
    assert_eq!(&buf[..3], &[1, 2, 0]);
    assert_eq!(LoadLinkKeys::decode(&buf), Some(v));
}

#[test]
fn an_empty_load_is_meaningful_and_decodes() {
    let v = LoadLinkKeys { debug_keys: 0, keys: alloc::vec![] };
    assert_eq!(v.encode(), alloc::vec![0, 0, 0]);
    assert_eq!(LoadLinkKeys::decode(&[0, 0, 0]), Some(v));
}

/// A count that does not account for exactly the bytes present is refused in
/// both directions — overstating would read past the buffer.
#[test]
fn a_key_count_that_disagrees_is_refused() {
    let mut buf = LoadLinkKeys { debug_keys: 0, keys: alloc::vec![link_key(0)] }.encode();
    buf[1] = 2;
    assert_eq!(LoadLinkKeys::decode(&buf), None, "count overstates");
    buf[1] = 0;
    assert_eq!(LoadLinkKeys::decode(&buf), None, "count understates");
    buf[1] = 1;
    assert!(LoadLinkKeys::decode(&buf).is_some());
    buf.push(0);
    assert_eq!(LoadLinkKeys::decode(&buf), None, "a trailing byte");
}

#[test]
fn long_term_keys_round_trip() {
    let k = LtkInfo {
        addr: addr(), key_type: 1, initiator: 0, enc_size: 16,
        ediv: 1, rand: 2, val: [5; 16],
    };
    let v = LoadLongTermKeys { keys: alloc::vec![k, k] };
    let buf = v.encode();
    assert_eq!(buf.len(), 2 + 2 * MGMT_LTK_INFO_SIZE);
    assert_eq!(LoadLongTermKeys::decode(&buf), Some(v));
    assert_eq!(LoadLongTermKeys::decode(&buf[..buf.len() - 1]), None);
}

#[test]
fn irks_round_trip() {
    let v = LoadIrks { irks: alloc::vec![IrkInfo { addr: addr(), val: [7; 16] }] };
    let buf = v.encode();
    assert_eq!(buf.len(), 2 + MGMT_IRK_INFO_SIZE);
    assert_eq!(LoadIrks::decode(&buf), Some(v));
}

#[test]
fn connection_parameters_round_trip() {
    let p = ConnParam {
        addr: addr(), min_interval: 24, max_interval: 40, latency: 0, timeout: 500,
    };
    let v = LoadConnParam { params: alloc::vec![p] };
    let buf = v.encode();
    assert_eq!(buf.len(), 2 + MGMT_CONN_PARAM_SIZE);
    assert_eq!(LoadConnParam::decode(&buf), Some(v));
}

#[test]
fn blocked_keys_round_trip() {
    let v = SetBlockedKeys {
        keys: alloc::vec![BlockedKeyInfo { key_type: 1, val: [0xbb; 16] }],
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 2 + MGMT_BLOCKED_KEY_INFO_SIZE);
    assert_eq!(SetBlockedKeys::decode(&buf), Some(v));
    assert_eq!(SetBlockedKeys::decode(&buf[..buf.len() - 1]), None);
}

/// The out-of-band command has two widths, and the width is what says which
/// form was sent. Anything between them is neither.
#[test]
fn oob_data_accepts_exactly_its_two_widths() {
    let short = AddRemoteOobData {
        addr: addr(), hash192: [1; 16], rand192: [2; 16], sc: None,
    };
    assert_eq!(short.encode().len(), MGMT_ADD_REMOTE_OOB_DATA_SIZE);
    assert_eq!(AddRemoteOobData::decode(&short.encode()), Some(short));

    let long = AddRemoteOobData {
        addr: addr(), hash192: [1; 16], rand192: [2; 16], sc: Some(([3; 16], [4; 16])),
    };
    assert_eq!(long.encode().len(), MGMT_ADD_REMOTE_OOB_EXT_DATA_SIZE);
    assert_eq!(AddRemoteOobData::decode(&long.encode()), Some(long));

    for n in [0usize, 38, 40, 55, 70, 72] {
        assert_eq!(AddRemoteOobData::decode(&alloc::vec![0u8; n]), None, "width {n}");
    }
}

#[test]
fn the_oob_type_selector_is_one_byte() {
    assert_eq!(ReadLocalOobExtData::decode(&[1]),
               Some(ReadLocalOobExtData { addr_type: 1 }));
    assert_eq!(ReadLocalOobExtData::decode(&[]), None);
    assert_eq!(ReadLocalOobExtData::decode(&[1, 0]), None);
    assert_eq!(ADDR_ONLY_SIZE, 7);
}
