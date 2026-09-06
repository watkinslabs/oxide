use super::*;
use ipc::win32_accel::{FCONTROL, FALT, FSHIFT, FVIRTKEY};

#[test]
fn the_msg_prefix_decodes_hwnd_message_and_params() {
    let mut bytes = [0u8; 48];
    bytes[0] = 1; bytes[8] = 0x11; bytes[9] = 0x01; bytes[16] = 0x4e; bytes[24] = 0x20;
    assert_eq!(Msg::decode(&bytes), Some(Msg { hwnd: 1, message: 0x0111, wparam: 0x4e, lparam: 0x20 }));
    assert_eq!(Msg::decode(&bytes[..31]), None);
}

#[test]
fn a_table_needs_a_positive_count_that_the_bytes_cover() {
    let one = Accel { virt: FVIRTKEY | FCONTROL, key: 0x4e, cmd: 3 }.encode();
    let mut two = one.to_vec(); two.extend_from_slice(&one);
    assert_eq!(decode_table(&two, 2).unwrap().len(), 2);
    assert_eq!(decode_table(&two, 0), None);
    assert_eq!(decode_table(&two, -1), None);
    assert_eq!(decode_table(&two, 3), None);
    assert_eq!(decode_table(&two, MAX_TABLE_ENTRIES as i64 + 1), None);
}

#[test]
fn modifier_mask_reads_the_high_bit_of_each_key_state() {
    assert_eq!(modifiers(|key| if key == VK_CONTROL || key == VK_SHIFT { 0x8000 } else { 0 }), FCONTROL | FSHIFT);
    assert_eq!(modifiers(|key| if key == VK_MENU { 0x8001 } else { 1 }), FALT);
    assert_eq!(modifiers(|_| 0), 0);
}

const BAR: Target = Target { style: 0, captured: false, menu: 5, placement: MenuPlacement::InBar, item_state: 0 };

#[test]
fn a_command_outside_any_menu_is_sent_directly() {
    assert_eq!(plan(7, Target { placement: MenuPlacement::NotInMenu, ..BAR }), alloc::vec![(WM_COMMAND, 0x10007, 0)]);
}

#[test]
fn a_menu_command_initialises_the_menu_first_and_respects_disabled_state() {
    assert_eq!(plan(7, BAR), alloc::vec![(WM_INITMENU, 5, 0), (WM_COMMAND, 0x10007, 0)]);
    let popup = Target { placement: MenuPlacement::InPopup { submenu: 9, position: 2 }, ..BAR };
    assert_eq!(plan(7, popup), alloc::vec![(WM_INITMENU, 5, 0), (WM_INITMENUPOPUP, 9, 2), (WM_COMMAND, 0x10007, 0)]);
    assert_eq!(plan(7, Target { item_state: MF_GRAYED, ..BAR }), alloc::vec![(WM_INITMENU, 5, 0)]);
    assert_eq!(plan(7, Target { style: WS_MINIMIZE, ..BAR }), alloc::vec![(WM_INITMENU, 5, 0)]);
    assert!(plan(7, Target { captured: true, ..BAR }).is_empty());
    assert!(plan(7, Target { style: WS_DISABLED, ..BAR }).is_empty());
    assert_eq!(plan(7, Target { style: WS_CHILD, ..BAR })[0], (WM_INITMENU, 0, 0));
}
