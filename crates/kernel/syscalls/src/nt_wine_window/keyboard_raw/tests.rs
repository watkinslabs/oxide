use super::*;

#[test]
fn the_ordinals_match_the_generated_win32u_table() {
    assert_eq!([ACTIVATE_KEYBOARD_LAYOUT, GET_KEYBOARD_LAYOUT, GET_KEYBOARD_LAYOUT_LIST,
        GET_KEYBOARD_LAYOUT_NAME, GET_KEY_NAME_TEXT, MAP_VIRTUAL_KEY_EX, TO_UNICODE_EX, VK_KEY_SCAN_EX],
        [0x1319, 0x1411, 0x1412, 0x1413, 0x140f, 0x14b1, 0x15d1, 0x15f4]);
}

#[test]
fn a_name_copy_always_leaves_room_for_the_terminator() {
    assert_eq!(name_copy_length(5, 9), 5);
    assert_eq!(name_copy_length(5, 3), 2);
    assert_eq!(name_copy_length(5, 1), 0);
    assert_eq!(name_copy_length(5, 0), 0);
    assert_eq!(name_copy_length(5, -1), 0);
}

#[test]
fn a_translation_reports_one_character_only_when_one_was_produced() {
    assert_eq!(translated_length(true), 1);
    assert_eq!(translated_length(false), 0);
}
