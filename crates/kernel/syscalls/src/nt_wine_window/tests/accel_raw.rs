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

const BAR: Target = Target { style: 0, captured: false, menu: 5, sys_menu: 6, placement: MenuPlacement::InBar(MenuOwner::Client), item_state: 0 };

#[test]
fn a_command_outside_any_menu_is_sent_directly() {
    assert_eq!(plan(7, Target { placement: MenuPlacement::NotInMenu, ..BAR }), alloc::vec![(WM_COMMAND, 0x10007, 0)]);
}

#[test]
fn a_menu_command_initialises_the_menu_first_and_respects_disabled_state() {
    assert_eq!(plan(7, BAR), alloc::vec![(WM_INITMENU, 5, 0), (WM_COMMAND, 0x10007, 0)]);
    let popup = Target { placement: MenuPlacement::InPopup { owner: MenuOwner::Client, submenu: 9, position: 2 }, ..BAR };
    assert_eq!(plan(7, popup), alloc::vec![(WM_INITMENU, 5, 0), (WM_INITMENUPOPUP, 9, 2), (WM_COMMAND, 0x10007, 0)]);
    assert_eq!(plan(7, Target { item_state: MF_GRAYED, ..BAR }), alloc::vec![(WM_INITMENU, 5, 0)]);
    assert_eq!(plan(7, Target { style: WS_MINIMIZE, ..BAR }), alloc::vec![(WM_INITMENU, 5, 0)]);
    // A captured mouse withholds the command but the menu is still told to
    // initialise itself; a disabled window is told nothing at all.
    assert_eq!(plan(7, Target { captured: true, ..BAR }), alloc::vec![(WM_INITMENU, 5, 0)]);
    assert!(plan(7, Target { style: WS_DISABLED, ..BAR }).is_empty());
    assert_eq!(plan(7, Target { style: WS_CHILD, ..BAR })[0], (WM_INITMENU, 0, 0));
}

#[test]
fn a_system_menu_command_is_sent_as_a_system_command_against_the_system_menu() {
    let bar = Target { placement: MenuPlacement::InBar(MenuOwner::System), ..BAR };
    assert_eq!(plan(0xf060, bar), alloc::vec![(WM_INITMENU, 6, 0), (WM_SYSCOMMAND, 0xf060, 0x10000)]);
    let popup = Target { placement: MenuPlacement::InPopup { owner: MenuOwner::System, submenu: 9, position: 0 }, ..BAR };
    assert_eq!(plan(0xf060, popup),
        alloc::vec![(WM_INITMENU, 6, 0), (WM_INITMENUPOPUP, 9, 0x10000), (WM_SYSCOMMAND, 0xf060, 0x10000)]);
}

#[test]
fn a_disabled_system_item_sends_no_command_and_an_iconic_window_keeps_its_system_commands() {
    let system = Target { placement: MenuPlacement::InBar(MenuOwner::System), ..BAR };
    assert_eq!(plan(0xf060, Target { item_state: MF_DISABLED, ..system }), alloc::vec![(WM_INITMENU, 6, 0)]);
    // Restoring an iconic window is exactly what its system menu is for, so
    // the iconic rule guards the window's own commands only.
    assert_eq!(plan(0xf120, Target { style: WS_MINIMIZE, ..system }), alloc::vec![(WM_INITMENU, 6, 0), (WM_SYSCOMMAND, 0xf120, 0x10000)]);
}

fn menu_of(items: &[(u32, u32, &[(u32, u32)])]) -> (ipc::win32_menu::MenuManager, u32) {
    use ipc::win32_menu::{MenuItem, MenuManager};
    let mut menus = MenuManager::new();
    let root = menus.create().unwrap();
    for (position, (id, state, children)) in items.iter().enumerate() {
        let submenu = if children.is_empty() { None } else {
            let sub = menus.create_popup().unwrap();
            for (index, (child, child_state)) in children.iter().enumerate() {
                menus.insert(sub, index, MenuItem { id: *child, state: *child_state, text: alloc::vec::Vec::new(), submenu: None }).unwrap();
            }
            Some(sub.raw())
        };
        menus.insert(root, position, MenuItem { id: *id, state: *state, text: alloc::vec::Vec::new(), submenu }).unwrap();
    }
    (menus, root.raw())
}

#[test]
fn a_command_is_found_in_a_submenu_with_the_position_of_the_top_level_item_that_holds_it() {
    let (menus, root) = menu_of(&[(1, 0, &[]), (2, 0, &[(7, MF_GRAYED)])]);
    let submenu = menus.item(ipc::win32_menu::MenuId::from_raw(root).unwrap(), 1, ipc::win32_menu::MF_BYPOSITION).unwrap().submenu.unwrap();
    assert_eq!(locate(&menus, Some(root), 7, MenuOwner::Client),
        Some((MenuPlacement::InPopup { owner: MenuOwner::Client, submenu, position: 1 }, MF_GRAYED)));
    assert_eq!(locate(&menus, Some(root), 1, MenuOwner::System), Some((MenuPlacement::InBar(MenuOwner::System), 0)));
    assert_eq!(locate(&menus, Some(root), 99, MenuOwner::Client), None);
    assert_eq!(locate(&menus, None, 7, MenuOwner::Client), None);
}
