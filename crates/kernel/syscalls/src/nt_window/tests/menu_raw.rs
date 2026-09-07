//! System-menu composition and the whole-menu property record codec.
use super::*;

fn record(mask: u32, style: u32, max_height: u32, background: u64, help: u32, data: u64) -> [u8; MENUINFO_BYTES as usize] {
    let mut bytes = [0u8; MENUINFO_BYTES as usize];
    bytes[0..4].copy_from_slice(&MENUINFO_BYTES.to_le_bytes());
    bytes[4..8].copy_from_slice(&mask.to_le_bytes());
    bytes[8..12].copy_from_slice(&style.to_le_bytes());
    bytes[12..16].copy_from_slice(&max_height.to_le_bytes());
    bytes[16..24].copy_from_slice(&background.to_le_bytes());
    bytes[24..28].copy_from_slice(&help.to_le_bytes());
    bytes[32..40].copy_from_slice(&data.to_le_bytes());
    bytes
}

#[test]
fn a_record_of_the_wrong_size_names_nothing() {
    let mut bytes = record(1, 2, 3, 4, 5, 6);
    bytes[0..4].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(decode_menu_info(bytes), None);
    bytes[0..4].copy_from_slice(&(MENUINFO_BYTES + 8).to_le_bytes());
    assert_eq!(decode_menu_info(bytes), None);
}

#[test]
fn every_property_survives_the_round_trip() {
    let bytes = record(0x1f, 0xdead, 0x1234, 0x1122_3344_5566_7788, 0x99, 0xaabb_ccdd_eeff_0011);
    let (mask, info) = decode_menu_info(bytes).unwrap();
    assert_eq!(mask, 0x1f);
    assert_eq!(info, ipc::win32_menu::MenuInfo { style: 0xdead, max_height: 0x1234,
        background: 0x1122_3344_5566_7788, context_help_id: 0x99, data: 0xaabb_ccdd_eeff_0011 });
    let encoded = encode_menu_info(record(0x1f, 0, 0, 0, 0, 0), info);
    assert_eq!(decode_menu_info(encoded).unwrap(), (0x1f, info));
}

#[test]
fn encoding_leaves_the_callers_size_and_mask_in_place() {
    let bytes = encode_menu_info(record(0x0c, 0, 0, 0, 0, 0), ipc::win32_menu::MenuInfo::default());
    assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), MENUINFO_BYTES);
    assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 0x0c);
}

#[test]
fn only_a_window_style_carrying_a_system_menu_gets_one() {
    assert!(has_system_menu(WS_SYSMENU));
    assert!(has_system_menu(WS_SYSMENU | 0x1000));
    assert!(!has_system_menu(0));
    assert!(!has_system_menu(!WS_SYSMENU));
}

#[test]
fn a_revert_request_reports_no_menu() {
    assert_eq!(system_menu_result(false, 0x40), 0x40);
    assert_eq!(system_menu_result(true, 0x40), 0);
}

#[test]
fn the_standard_window_menu_carries_its_commands_in_order() {
    let ids: alloc::vec::Vec<u32> = SYSTEM_MENU_COMMANDS.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, alloc::vec![SC_RESTORE, SC_MOVE, SC_SIZE, SC_MINIMIZE, SC_MAXIMIZE, SC_SEPARATOR, SC_CLOSE]);
    assert!(SYSTEM_MENU_COMMANDS.iter().all(|(id, text)| (*id == SC_SEPARATOR) == text.is_empty()));
}
