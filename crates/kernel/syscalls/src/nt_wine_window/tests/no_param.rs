//! `NtUserCallNoParam` code coverage, decoding and answer shapes.
use super::*;

#[test]
fn every_code_the_multiplexer_defines_decodes_to_its_own_arm() {
    for (wire, expected) in CODES.iter().enumerate() {
        assert_eq!(code(wire as u64), Some(*expected), "wire code {wire}");
        assert_eq!(*expected as u32, wire as u32, "discriminant is the wire code");
    }
    assert_eq!(CODES.len(), 9);
}

#[test]
fn the_code_argument_is_a_ulong_and_the_high_half_carries_nothing() {
    assert_eq!(code(0xdead_beef_0000_0004), Some(Code::GetShellWindow));
    assert_eq!(code(0x1234_5678_0000_0000), Some(Code::GetDesktopWindow));
}

#[test]
fn an_unknown_code_answers_zero_never_a_status() {
    for wire in [CODES.len() as u64, 64, 0xffff, u64::from(u32::MAX)] { assert_eq!(code(wire), None); }
    // The multiplexer's result is used as a handle or a tick count, so the
    // refusal answer is zero and never STATUS_NOT_IMPLEMENTED.
    assert_eq!(UNHANDLED, 0);
    assert_ne!(UNHANDLED, 0xc000_0002);
}

#[test]
fn dialog_base_units_pack_width_low_height_high_and_never_answer_zero() {
    assert_eq!(dialog_base_units(8, 16, 96), 8 | (16 << 16));
    // Doubling the density doubles both cells.
    assert_eq!(dialog_base_units(8, 16, 192), 16 | (32 << 16));
    // A cell that scales below one pixel is still one pixel: a zero base unit
    // divides every dialog-unit conversion by zero.
    assert_eq!(dialog_base_units(1, 1, 1), 1 | (1 << 16));
    // The word is one DWORD: each half is truncated to its half-word rather
    // than spilling into the other half or past the word.
    assert_eq!(dialog_base_units(i32::MAX, i32::MAX, i32::MAX) & !0xffff_ffffu64, 0);
    assert_eq!(dialog_base_units(0x1_0008, 0x1_0010, 96), 8 | (16 << 16));
}

#[test]
fn the_display_change_lparam_packs_the_resolution() {
    assert_eq!(display_change_lparam(1024, 768), 1024 | (768 << 16));
    assert_eq!(display_change_lparam(0x1_0000, 0x1_0000), 0);
}
