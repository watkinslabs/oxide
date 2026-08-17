// What makes a key valid, and how that differs by kind.

extern crate alloc;
use alloc::vec;

use crate::crypto::key::{Key, KeyType, MAX_HW_WRAPPED_KEY_SIZE};
use crate::crypto::mode::Mode;
use crate::types::BlockError;

#[test]
fn raw_key_must_be_the_modes_exact_size() {
    for m in Mode::ALL {
        let n = m.params().key_size;
        assert!(Key::new(&vec![0u8; n], KeyType::Raw, m, 8, 4096).is_ok(), "{m:?}");
        assert_eq!(Key::new(&vec![0u8; n - 1], KeyType::Raw, m, 8, 4096).err(),
                   Some(BlockError::Einval), "{m:?} short");
        assert_eq!(Key::new(&vec![0u8; n + 1], KeyType::Raw, m, 8, 4096).err(),
                   Some(BlockError::Einval), "{m:?} long");
    }
}

#[test]
fn wrapped_key_size_is_a_range_not_a_width() {
    let m = Mode::Aes256Xts;
    let s = m.params().security_strength;
    // A wrapped blob's size is the controller's business, so anything from the
    // mode's security strength up to what this layer can hold is acceptable —
    // including sizes that would be refused outright for a raw key.
    assert!(Key::new(&vec![0u8; s], KeyType::HwWrapped, m, 8, 4096).is_ok());
    assert!(Key::new(&vec![0u8; 48], KeyType::HwWrapped, m, 8, 4096).is_ok());
    assert!(Key::new(&vec![0u8; MAX_HW_WRAPPED_KEY_SIZE], KeyType::HwWrapped, m, 8, 4096).is_ok());
    assert_eq!(Key::new(&vec![0u8; s - 1], KeyType::HwWrapped, m, 8, 4096).err(),
               Some(BlockError::Einval));
    assert_eq!(Key::new(&vec![0u8; MAX_HW_WRAPPED_KEY_SIZE + 1], KeyType::HwWrapped, m, 8, 4096)
                   .err(), Some(BlockError::Einval));
}

#[test]
fn dun_width_is_bounded_by_the_modes_iv() {
    let m = Mode::Aes256Xts;
    let iv = m.params().iv_size as u32;
    let k = vec![0u8; m.params().key_size];
    assert!(Key::new(&k, KeyType::Raw, m, iv, 4096).is_ok());
    assert_eq!(Key::new(&k, KeyType::Raw, m, iv + 1, 4096).err(), Some(BlockError::Einval));
    // A key naming no data unit at all would encrypt every unit at the same
    // keystream position.
    assert_eq!(Key::new(&k, KeyType::Raw, m, 0, 4096).err(), Some(BlockError::Einval));
    // The wide-block mode's tweak is twice as wide, so it accepts a number
    // the narrow modes refuse.
    let w = Mode::Adiantum;
    assert!(Key::new(&vec![0u8; w.params().key_size], KeyType::Raw, w, 32, 4096).is_ok());
}

#[test]
fn data_unit_size_must_be_a_power_of_two() {
    let m = Mode::Aes256Xts;
    let k = vec![0u8; m.params().key_size];
    assert!(Key::new(&k, KeyType::Raw, m, 8, 512).is_ok());
    assert_eq!(Key::new(&k, KeyType::Raw, m, 8, 4095).err(), Some(BlockError::Einval));
    assert_eq!(Key::new(&k, KeyType::Raw, m, 8, 0).err(), Some(BlockError::Einval));
}

#[test]
fn unit_arithmetic_follows_the_data_unit_size() {
    let m = Mode::Aes256Xts;
    let k = Key::new(&vec![0u8; m.params().key_size], KeyType::Raw, m, 8, 512).unwrap();
    assert_eq!(k.units(4096), 8);
    assert!(k.unit_aligned(1024));
    assert!(!k.unit_aligned(1025));
}
