use super::*;

const VK_SHIFT: usize = 0x10;
const VK_CONTROL: usize = 0x11;
const VK_CAPITAL: usize = 0x14;

fn state() -> [u8; 256] { [0; 256] }

#[test]
fn the_scan_table_covers_every_documented_code_and_both_prefix_pages() {
    assert_eq!(VSC_TO_VK.len(), 0x7f);
    let table = scan_to_vkey_table();
    assert_eq!(table[0x1e] & 0xff, b'A' as u16);
    assert_eq!(table[0x2a] & 0xff, 0xa0);
    assert_eq!(table[0x36] & 0xff, 0xa1);
    assert_eq!(table[0x11d] & 0xff, 0xa3);
    assert_eq!(table[0x21d] & 0xff, 0x13);
    assert_eq!(table[0x00], 0);
}

#[test]
fn a_virtual_key_maps_to_its_scan_code_and_back() {
    assert_eq!(map_virtual_key(b'A' as u32, MAPVK_VK_TO_VSC), 0x1e);
    assert_eq!(map_virtual_key(0x1e, MAPVK_VSC_TO_VK), b'A' as u32);
    assert_eq!(map_virtual_key(0x1e, MAPVK_VSC_TO_VK_EX), b'A' as u32);
}

#[test]
fn a_side_agnostic_modifier_maps_to_its_left_hand_scan_code_and_back_to_the_generic_key() {
    assert_eq!(map_virtual_key(0x10, MAPVK_VK_TO_VSC), 0x2a);
    assert_eq!(map_virtual_key(0x11, MAPVK_VK_TO_VSC), 0x1d);
    assert_eq!(map_virtual_key(0x36, MAPVK_VSC_TO_VK), 0x10);
    assert_eq!(map_virtual_key(0x36, MAPVK_VSC_TO_VK_EX), 0xa1);
}

#[test]
fn an_extended_key_drops_its_prefix_page_in_the_plain_direction_and_is_biased_in_the_extended_one() {
    assert_eq!(map_virtual_key(0xa3, MAPVK_VK_TO_VSC), 0x1d);
    assert_eq!(map_virtual_key(0x13, MAPVK_VK_TO_VSC), 0);
    assert_eq!(map_virtual_key(0xa3, MAPVK_VK_TO_VSC_EX), 0xe01d);
    assert_eq!(map_virtual_key(0xe01d, MAPVK_VSC_TO_VK_EX), 0xa3);
}

#[test]
fn a_numeric_pad_key_resolves_through_its_navigation_twin() {
    assert_eq!(map_virtual_key(0x60, MAPVK_VK_TO_VSC), 0x52);
    assert_eq!(map_virtual_key(0x6e, MAPVK_VK_TO_VSC), 0x53);
}

#[test]
fn the_character_direction_answers_the_unmodified_character() {
    assert_eq!(map_virtual_key(b'A' as u32, MAPVK_VK_TO_CHAR), b'A' as u32);
    assert_eq!(map_virtual_key(0xbb, MAPVK_VK_TO_CHAR), b'=' as u32);
    assert_eq!(map_virtual_key(0x300, MAPVK_VK_TO_CHAR), 0);
    assert_eq!(map_virtual_key(0x1e, 99), 0);
}

#[test]
fn a_letter_answers_its_case_from_shift_and_caps_lock() {
    let mut keys = state();
    assert_eq!(vkey_to_wchar(b'A' as u32, &keys), Some(b'a' as u16));
    keys[VK_SHIFT] = 0x80;
    assert_eq!(vkey_to_wchar(b'A' as u32, &keys), Some(b'A' as u16));
    keys[VK_SHIFT] = 0;
    keys[VK_CAPITAL] = 1;
    assert_eq!(vkey_to_wchar(b'A' as u32, &keys), Some(b'A' as u16));
    // Caps lock folds into the shift bit, so holding shift with caps lock on
    // selects the same column as shift alone.
    keys[VK_SHIFT] = 0x80;
    assert_eq!(vkey_to_wchar(b'A' as u32, &keys), Some(b'A' as u16));
}

#[test]
fn a_digit_key_answers_its_shifted_symbol_but_caps_lock_leaves_it_alone() {
    let mut keys = state();
    assert_eq!(vkey_to_wchar(b'1' as u32, &keys), Some(b'1' as u16));
    keys[VK_CAPITAL] = 1;
    assert_eq!(vkey_to_wchar(b'1' as u32, &keys), Some(b'1' as u16));
    keys[VK_CAPITAL] = 0;
    keys[VK_SHIFT] = 0x80;
    assert_eq!(vkey_to_wchar(b'1' as u32, &keys), Some(b'!' as u16));
}

#[test]
fn control_letters_answer_their_control_character_and_control_alt_answers_none() {
    let mut keys = state();
    keys[VK_CONTROL] = 0x80;
    assert_eq!(vkey_to_wchar(b'C' as u32, &keys), Some(3));
    assert_eq!(vkey_to_wchar(0x0d, &keys), Some(0x000a));
    keys[0x12] = 0x80;
    assert_eq!(vkey_to_wchar(b'C' as u32, &keys), None);
}

#[test]
fn a_column_with_no_character_answers_none() {
    let mut keys = state();
    keys[VK_CONTROL] = 0x80;
    assert_eq!(vkey_to_wchar(b'2' as u32, &keys), None);
}

#[test]
fn a_character_names_its_key_and_the_modifier_bits_that_produce_it() {
    assert_eq!(wchar_to_vkey(b'a' as u16), Some(b'A' as u16));
    assert_eq!(wchar_to_vkey(b'A' as u16), Some(0x0100 | b'A' as u16));
    assert_eq!(wchar_to_vkey(b'!' as u16), Some(0x0100 | b'1' as u16));
    assert_eq!(wchar_to_vkey(0x001b), Some(0x1b));
    assert_eq!(wchar_to_vkey(3), Some(0x03));
    assert_eq!(wchar_to_vkey(5), Some(0x0200 | b'E' as u16));
    assert_eq!(wchar_to_vkey(0x0100), None);
}

#[test]
fn a_named_key_answers_its_name_and_an_unnamed_one_its_character() {
    let name = key_name(0x1e << 16).unwrap();
    assert_eq!(name, alloc::vec![b'A' as u16]);
    let escape = key_name(0x01 << 16).unwrap();
    assert_eq!(escape, alloc::vec![b'E' as u16, b's' as u16, b'c' as u16]);
    let right_ctrl = key_name((0x11d << 16) as u32).unwrap();
    assert_eq!(right_ctrl.len(), "Right Ctrl".len());
}

#[test]
fn a_side_agnostic_name_request_resolves_a_right_modifier_to_its_left_twin() {
    let sided = key_name(0x36 << 16).unwrap();
    assert_eq!(sided.len(), "Right Shift".len());
    let generic = key_name((0x36 << 16) | 0x0200_0000).unwrap();
    assert_eq!(generic.len(), "Shift".len());
}
