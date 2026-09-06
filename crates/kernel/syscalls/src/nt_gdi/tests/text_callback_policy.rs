use super::*;
use core::cell::Cell;
use ipc::win32_gdi::{GdiManager, TextAttribute};

#[test]
fn move_optional_point_preserves_signed_bytes_and_copy_before_update() {
    let order = Cell::new(0);
    assert_eq!(move_to_result(0x1000, Ok((i32::MIN, -7)), |pointer, bytes| {
        assert_eq!(pointer, 0x1000);
        assert_eq!(&bytes[..4], &i32::MIN.to_le_bytes());
        assert_eq!(&bytes[4..], &(-7i32).to_le_bytes());
        assert_eq!(order.replace(1), 0); true
    }, || { assert_eq!(order.replace(2), 1); true }), 1);
    assert_eq!(order.get(), 2);
    assert_eq!(move_to_result(0, Ok((0, 0)), |_, _| unreachable!(), || true), 1);
}

#[test]
fn move_failed_snapshot_or_copy_never_changes_position() {
    assert_eq!(move_to_result(1, Err(1), |_, _| unreachable!(), || unreachable!()), 0);
    let mut owner = GdiManager::new();
    let dc = owner.create_dc(1, 1).unwrap();
    let old = owner.text_state(dc).unwrap().attributes.current_position;
    assert_eq!(move_to_result(1, Ok(old), |_, _| false,
        || owner.set_text_position(dc, (4, 5)).is_ok()), 0);
    assert_eq!(owner.text_state(dc).unwrap().attributes.current_position, old);
    assert_eq!(move_to_result(1, Ok(old), |_, _| true, || false), 0);
}

#[test]
fn dword_color_is_reversed_once_and_noncolor_retains_all_bits() {
    for (encoding, input, expected) in [(OldValueEncoding::Xrgb, 0x123456, 0x563412),
        (OldValueEncoding::RawDword, 0x563412, 0x563412),
        (OldValueEncoding::RawDword, 0xffffffff, 0xffffffff)] {
        assert_eq!(set_dword_result(0x1234, Ok(input), encoding, |pointer, old| {
            assert_eq!(pointer, 0x1234); assert_eq!(old, expected); true
        }), 1);
    }
}

#[test]
fn dword_missing_or_faulting_copyout_keeps_canonical_mutation() {
    let mut owner = GdiManager::new();
    let dc = owner.create_dc(1, 1).unwrap();
    for pointer in [0, 0x1000] {
        let result = owner.set_text_attribute(dc, TextAttribute::Foreground, 0x123456).map_err(|_| 1);
        assert_eq!(set_dword_result(pointer, result, OldValueEncoding::Xrgb, |_, _| {
            assert_ne!(pointer, 0); false
        }), 0);
        assert_eq!(owner.text_state(dc).unwrap().attributes.foreground, 0x123456);
    }
    assert_eq!(set_dword_result(1, Err(1), OldValueEncoding::RawDword, |_, _| unreachable!()), 0);
}
