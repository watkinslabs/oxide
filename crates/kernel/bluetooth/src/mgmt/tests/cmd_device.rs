//! The device list and its flags.

use super::*;
use crate::uapi::bt::{BdAddr, BDADDR_LE_PUBLIC, BDADDR_LE_RANDOM};
use crate::uapi::mgmt::flags::{
    MGMT_DEVICE_FLAG_ADDRESS_RESOLUTION, MGMT_DEVICE_FLAG_DEVICE_PRIVACY,
    MGMT_DEVICE_FLAG_PAST, MGMT_DEVICE_FLAG_REMOTE_WAKEUP,
};

fn peer(t: u8) -> AddrInfo { AddrInfo::new(BdAddr([1, 2, 3, 4, 5, 6]), t) }

#[test]
fn add_device_round_trips() {
    let v = AddDevice { addr: peer(BDADDR_LE_PUBLIC), action: MGMT_DEV_ACTION_AUTO_CONNECT };
    let buf = v.encode();
    assert_eq!(buf.len(), 8);
    assert_eq!(AddDevice::decode(&buf), Some(v));
    assert_eq!(AddDevice::decode(&buf[..7]), None);
    assert_eq!(AddDevice::decode(&alloc::vec![0u8; 9]), None);
}

#[test]
fn an_action_outside_the_three_is_refused() {
    for a in 0..=2u8 {
        assert!(AddDevice { addr: peer(BDADDR_LE_PUBLIC), action: a }.action_is_valid());
    }
    for a in [3u8, 4, 0xff] {
        assert!(!AddDevice { addr: peer(BDADDR_LE_PUBLIC), action: a }.action_is_valid());
    }
}

/// A BR/EDR entry exists to accept an incoming connection. The two scan-driven
/// actions cannot fire on it, so storing one would be an entry that never runs.
#[test]
fn bredr_accepts_only_the_incoming_connection_action() {
    let mk = |t, action| AddDevice { addr: peer(t), action };
    assert!(mk(BDADDR_BREDR, MGMT_DEV_ACTION_ALLOW_CONNECT).is_acceptable());
    assert!(!mk(BDADDR_BREDR, MGMT_DEV_ACTION_BACKGROUND_SCAN).is_acceptable());
    assert!(!mk(BDADDR_BREDR, MGMT_DEV_ACTION_AUTO_CONNECT).is_acceptable());
    // LE takes all three.
    for a in 0..=2u8 {
        assert!(mk(BDADDR_LE_PUBLIC, a).is_acceptable(), "action {a}");
        assert!(mk(BDADDR_LE_RANDOM, a).is_acceptable(), "action {a}");
    }
}

#[test]
fn the_all_zero_address_and_a_bad_type_are_refused() {
    let any = AddDevice {
        addr: AddrInfo::new(BdAddr::default(), BDADDR_LE_PUBLIC),
        action: MGMT_DEV_ACTION_ALLOW_CONNECT,
    };
    assert!(!any.is_acceptable(), "the all-zero address names no peer");
    let bad = AddDevice { addr: peer(9), action: MGMT_DEV_ACTION_ALLOW_CONNECT };
    assert!(!bad.is_acceptable());
}

#[test]
fn set_device_flags_round_trips() {
    let v = SetDeviceFlags {
        addr: peer(BDADDR_LE_RANDOM), current_flags: MGMT_DEVICE_FLAG_REMOTE_WAKEUP,
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 11);
    assert_eq!(&buf[7..], &1u32.to_le_bytes());
    assert_eq!(SetDeviceFlags::decode(&buf), Some(v));
    assert_eq!(SetDeviceFlags::decode(&buf[..10]), None);
    assert_eq!(SetDeviceFlags::decode(&alloc::vec![0u8; 12]), None);
}

/// A flag the device does not support cannot be set: the request is refused
/// rather than masked, so a client is never told it got what it asked for.
#[test]
fn a_flag_outside_the_supported_set_is_refused() {
    let supported = MGMT_DEVICE_FLAG_REMOTE_WAKEUP | MGMT_DEVICE_FLAG_DEVICE_PRIVACY;
    let ok = SetDeviceFlags { addr: peer(BDADDR_LE_PUBLIC), current_flags: supported };
    assert!(ok.within(supported));
    let none = SetDeviceFlags { addr: peer(BDADDR_LE_PUBLIC), current_flags: 0 };
    assert!(none.within(supported));
    let over = SetDeviceFlags {
        addr: peer(BDADDR_LE_PUBLIC),
        current_flags: supported | MGMT_DEVICE_FLAG_ADDRESS_RESOLUTION,
    };
    assert!(!over.within(supported));
}

#[test]
fn the_device_flags_sit_where_the_interface_says() {
    assert_eq!(MGMT_DEVICE_FLAG_REMOTE_WAKEUP, 1);
    assert_eq!(MGMT_DEVICE_FLAG_DEVICE_PRIVACY, 2);
    assert_eq!(MGMT_DEVICE_FLAG_ADDRESS_RESOLUTION, 4);
    assert_eq!(MGMT_DEVICE_FLAG_PAST, 8);
}
