use super::*;

const TID: u64 = 3;
const OTHER: u64 = 4;
const VK_F1: u32 = 0x70;

fn key(id: i32, flags: u32, vkey: u32) -> Hotkey { Hotkey { tid: TID, window: None, id, flags, vkey } }

#[test]
fn one_combination_is_claimed_once() {
    let mut keys = Hotkeys::new();
    assert_eq!(keys.register(key(1, MOD_ALT, VK_F1)), Ok(None));
    let rival = Hotkey { tid: OTHER, ..key(2, MOD_ALT, VK_F1) };
    assert_eq!(keys.register(rival), Err(HotkeyError::AlreadyRegistered));
    assert_eq!(keys.len(), 1);
}

#[test]
fn only_the_matching_modifier_bits_take_part_in_the_duplicate_test() {
    let mut keys = Hotkeys::new();
    keys.register(key(1, MOD_ALT, VK_F1)).unwrap();
    assert_eq!(keys.register(Hotkey { tid: OTHER, ..key(2, MOD_CONTROL, VK_F1) }), Ok(None));
    assert_eq!(keys.register(Hotkey { tid: OTHER, ..key(3, MOD_ALT | 0x4000, VK_F1) }), Err(HotkeyError::AlreadyRegistered));
}

#[test]
fn the_same_owner_id_replaces_its_own_registration() {
    let mut keys = Hotkeys::new();
    keys.register(key(1, MOD_SHIFT, VK_F1)).unwrap();
    let replaced = keys.register(key(1, MOD_WIN, 0x71)).unwrap().unwrap();
    assert_eq!((replaced.flags, replaced.vkey), (MOD_SHIFT, VK_F1));
    assert_eq!(keys.len(), 1);
    assert_eq!(keys.unregister(TID, None, 1).unwrap().vkey, 0x71);
}

#[test]
fn releasing_an_unclaimed_id_is_refused() {
    let mut keys = Hotkeys::new();
    assert_eq!(keys.unregister(TID, None, 5), Err(HotkeyError::NotRegistered));
    keys.register(key(5, MOD_ALT, VK_F1)).unwrap();
    assert_eq!(keys.unregister(OTHER, None, 5), Err(HotkeyError::NotRegistered));
    assert!(keys.unregister(TID, None, 5).is_ok());
    assert!(keys.is_empty());
}

#[test]
fn a_named_window_must_belong_to_the_registering_thread() {
    let mut manager = crate::win32_window::WindowManager::new();
    let window = manager.create(TID, None, 0).unwrap();
    assert_eq!(manager.register_hotkey(OTHER, Some(window), 1, MOD_ALT, VK_F1), Err(HotkeyError::OtherThread));
    assert_eq!(manager.register_hotkey(TID, Some(window), 1, MOD_ALT, VK_F1), Ok(None));
    let stray = crate::win32_window::WindowId::from_raw(0x999).unwrap();
    assert_eq!(manager.register_hotkey(TID, Some(stray), 2, MOD_SHIFT, VK_F1), Err(HotkeyError::NoSuchWindow));
    assert!(manager.unregister_hotkey(TID, Some(window), 1).is_ok());
}
