//! Bonding and the pairing replies.

use super::*;
use crate::uapi::bt::{BdAddr, BDADDR_BREDR};

fn addr() -> AddrInfo { AddrInfo::new(BdAddr([0xaa; 6]), BDADDR_BREDR) }

#[test]
fn pair_device_round_trips() {
    let v = PairDevice { addr: addr(), io_cap: 3 };
    let buf = v.encode();
    assert_eq!(buf.len(), 8);
    assert_eq!(buf[7], 3);
    assert_eq!(PairDevice::decode(&buf), Some(v));
    assert_eq!(PairDevice::decode(&buf[..7]), None);
    assert_eq!(PairDevice::decode(&alloc::vec![0u8; 9]), None);
}

#[test]
fn unpair_device_round_trips() {
    let v = UnpairDevice { addr: addr(), disconnect: 1 };
    assert_eq!(UnpairDevice::decode(&v.encode()), Some(v));
    assert_eq!(UnpairDevice::decode(&alloc::vec![0u8; 7]), None);
}

#[test]
fn a_pin_reply_round_trips_at_its_full_width() {
    let mut pin_code = [0u8; 16];
    pin_code[..4].copy_from_slice(b"1234");
    let v = PinCodeReply { addr: addr(), pin_len: 4, pin_code };
    let buf = v.encode();
    assert_eq!(buf.len(), 24, "the slot is padded to its full width");
    assert_eq!(PinCodeReply::decode(&buf), Some(v));
    assert_eq!(v.pin(), Some(&b"1234"[..]));
}

/// A declared length past the slot would hand padding to the controller as PIN
/// material, so it is refused rather than clamped.
#[test]
fn a_pin_length_outside_the_slot_is_refused() {
    let mk = |pin_len| PinCodeReply { addr: addr(), pin_len, pin_code: [1u8; 16] };
    assert!(mk(1).len_is_valid());
    assert!(mk(16).len_is_valid());
    assert!(!mk(17).len_is_valid());
    assert!(!mk(0).len_is_valid(), "an empty PIN is not a PIN");
    assert!(!mk(0xff).len_is_valid());
    assert_eq!(mk(17).pin(), None);
    assert_eq!(mk(0).pin(), None);
}

#[test]
fn a_passkey_reply_round_trips_its_word() {
    let v = UserPasskeyReply { addr: addr(), passkey: 123_456 };
    let buf = v.encode();
    assert_eq!(buf.len(), 11);
    assert_eq!(&buf[7..], &123_456u32.to_le_bytes());
    assert_eq!(UserPasskeyReply::decode(&buf), Some(v));
    assert_eq!(UserPasskeyReply::decode(&buf[..10]), None);
}

#[test]
fn confirm_name_round_trips() {
    let v = ConfirmName { addr: addr(), name_known: 1 };
    assert_eq!(ConfirmName::decode(&v.encode()), Some(v));
    assert_eq!(ConfirmName::decode(&alloc::vec![0u8; 9]), None);
}

/// The negative replies and the cancel are a bare address record.
#[test]
fn the_bare_address_replies_share_one_record() {
    let a = addr();
    let buf = a.encode();
    assert_eq!(buf.len(), 7);
    assert_eq!(AddrInfo::decode(&buf), Some(a));
    assert_eq!(AddrInfo::decode(&buf[..6]), None);
}
