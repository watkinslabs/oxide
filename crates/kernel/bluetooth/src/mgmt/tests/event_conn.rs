//! Link lifecycle and pairing prompt events.

use super::*;
use crate::uapi::bt::{BdAddr, BDADDR_BREDR, BDADDR_LE_RANDOM};
use crate::uapi::mgmt::ev::{MGMT_DEV_DISCONN_REMOTE, MGMT_DEV_DISCONN_TIMEOUT};

fn a(t: u8) -> AddrInfo { AddrInfo::new(BdAddr([1, 2, 3, 4, 5, 6]), t) }

#[test]
fn a_connect_event_carries_its_eir() {
    let v = DeviceConnected {
        addr: a(BDADDR_LE_RANDOM), flags: 0x08, eir: alloc::vec![2, 0x01, 0x06],
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 7 + 4 + 2 + 3);
    assert_eq!(&buf[11..13], &3u16.to_le_bytes());
    assert_eq!(DeviceConnected::decode(&buf), Some(v));
}

#[test]
fn a_connect_event_with_a_lying_eir_length_is_refused() {
    let v = DeviceConnected { addr: a(BDADDR_BREDR), flags: 0, eir: alloc::vec![1, 2] };
    let mut buf = v.encode();
    buf[11] = 3;
    assert_eq!(DeviceConnected::decode(&buf), None);
    buf[11] = 1;
    assert_eq!(DeviceConnected::decode(&buf), None, "a byte the length does not claim");
}

#[test]
fn a_disconnect_event_names_a_reason() {
    for reason in [MGMT_DEV_DISCONN_TIMEOUT, MGMT_DEV_DISCONN_REMOTE] {
        let v = DeviceDisconnected { addr: a(BDADDR_BREDR), reason };
        let buf = v.encode();
        assert_eq!(buf.len(), 8);
        assert_eq!(buf[7], reason);
        assert_eq!(DeviceDisconnected::decode(&buf), Some(v));
    }
    assert_eq!(DeviceDisconnected::decode(&alloc::vec![0u8; 9]), None);
}

#[test]
fn the_two_status_events_share_one_record() {
    let v = AddrStatus { addr: a(BDADDR_BREDR), status: 5 };
    assert_eq!(v.encode().len(), 8);
    assert_eq!(AddrStatus::decode(&v.encode()), Some(v));
    assert_eq!(AddrStatus::decode(&alloc::vec![0u8; 7]), None);
}

#[test]
fn a_pin_request_says_whether_a_long_pin_is_wanted() {
    let v = PinCodeRequest { addr: a(BDADDR_BREDR), secure: 1 };
    assert_eq!(v.encode()[7], 1);
    assert_eq!(PinCodeRequest::decode(&v.encode()), Some(v));
}

#[test]
fn a_confirm_request_round_trips_its_value() {
    let v = UserConfirmRequest {
        addr: a(BDADDR_LE_RANDOM), confirm_hint: 1, value: 654_321,
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 12);
    assert_eq!(&buf[8..], &654_321u32.to_le_bytes());
    assert_eq!(UserConfirmRequest::decode(&buf), Some(v));
    assert_eq!(UserConfirmRequest::decode(&buf[..11]), None);
}

#[test]
fn a_passkey_notification_reports_progress() {
    let v = PasskeyNotify { addr: a(BDADDR_LE_RANDOM), passkey: 42, entered: 3 };
    let buf = v.encode();
    assert_eq!(buf.len(), 12);
    assert_eq!(buf[11], 3);
    assert_eq!(PasskeyNotify::decode(&buf), Some(v));
    assert_eq!(PasskeyNotify::decode(&alloc::vec![0u8; 13]), None);
}

#[test]
fn a_device_added_event_echoes_the_action() {
    let v = DeviceAdded { addr: a(BDADDR_LE_RANDOM), action: 2 };
    assert_eq!(DeviceAdded::decode(&v.encode()), Some(v));
    assert_eq!(DeviceAdded::decode(&alloc::vec![0u8; 7]), None);
}

#[test]
fn a_new_connection_parameter_event_round_trips() {
    let v = NewConnParam {
        addr: a(BDADDR_LE_RANDOM), store_hint: 1,
        min_interval: 6, max_interval: 12, latency: 0, timeout: 200,
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 16);
    assert_eq!(buf[7], 1, "the store hint precedes the values");
    assert_eq!(NewConnParam::decode(&buf), Some(v));
    assert_eq!(NewConnParam::decode(&buf[..15]), None);
}
