//! Key delivery events.

use super::*;
use crate::mgmt::types::AddrInfo;
use crate::uapi::bt::{BDADDR_BREDR, BDADDR_LE_RANDOM};
use crate::uapi::mgmt::ev::{
    MGMT_CSRK_LOCAL_UNAUTHENTICATED, MGMT_CSRK_REMOTE_AUTHENTICATED, MGMT_LTK_P256_AUTH,
};

fn a(t: u8) -> AddrInfo { AddrInfo::new(BdAddr([1, 2, 3, 4, 5, 6]), t) }

#[test]
fn the_store_hint_leads_every_key_event() {
    let v = NewLinkKey {
        store_hint: 1,
        key: LinkKeyInfo { addr: a(BDADDR_BREDR), key_type: 4, val: [1; 16], pin_len: 0 },
    };
    let buf = v.encode();
    assert_eq!(buf[0], 1);
    assert_eq!(buf.len(), 1 + MGMT_LINK_KEY_INFO_SIZE);
    assert_eq!(NewLinkKey::decode(&buf), Some(v));
    assert_eq!(NewLinkKey::decode(&buf[..buf.len() - 1]), None);
    assert_eq!(NewLinkKey::decode(&alloc::vec![0u8; buf.len() + 1]), None);
}

#[test]
fn a_long_term_key_event_round_trips() {
    let v = NewLongTermKey {
        store_hint: 0,
        key: LtkInfo {
            addr: a(BDADDR_LE_RANDOM), key_type: MGMT_LTK_P256_AUTH, initiator: 1,
            enc_size: 16, ediv: 0, rand: 0, val: [9; 16],
        },
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 1 + MGMT_LTK_INFO_SIZE);
    assert_eq!(NewLongTermKey::decode(&buf), Some(v));
}

/// The identity key event carries both the resolvable address a client already
/// saw and the identity behind it.
#[test]
fn an_irk_event_carries_the_resolvable_address_as_well() {
    let v = NewIrk {
        store_hint: 1,
        rpa: BdAddr([0x40, 1, 2, 3, 4, 5]),
        irk: IrkInfo { addr: a(BDADDR_LE_RANDOM), val: [3; 16] },
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 1 + 6 + MGMT_IRK_INFO_SIZE);
    assert_eq!(&buf[1..7], &[0x40, 1, 2, 3, 4, 5]);
    assert_eq!(NewIrk::decode(&buf), Some(v));
    assert_eq!(NewIrk::decode(&buf[..buf.len() - 1]), None);
}

#[test]
fn a_csrk_event_round_trips_each_key_type() {
    for t in [MGMT_CSRK_LOCAL_UNAUTHENTICATED, MGMT_CSRK_REMOTE_AUTHENTICATED] {
        let v = NewCsrk {
            store_hint: 1,
            key: CsrkInfo { addr: a(BDADDR_LE_RANDOM), key_type: t, val: [4; 16] },
        };
        let buf = v.encode();
        assert_eq!(buf.len(), 1 + MGMT_CSRK_INFO_SIZE);
        assert_eq!(NewCsrk::decode(&buf), Some(v));
    }
}
