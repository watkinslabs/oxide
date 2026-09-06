use super::*;

fn child(manager: &mut WindowManager) -> WindowId {
    let parent = manager.create(7, None, 0x1000).unwrap();
    let window = manager.create(7, Some(parent), 0x2000).unwrap();
    manager.set_window_styles(window, WS_CHILD, 0).unwrap();
    window
}

#[test]
fn control_pointer_width_zero_and_previous_value() {
    let mut manager = WindowManager::new();
    let window = child(&mut manager);
    assert_eq!(manager.control_id(window), Some(0));
    let mut previous = 0;
    for value in [1001, 0x1234_5678_9abc_def0, u64::MAX, 0] {
        assert_eq!(manager.set_control_id(window, value), Ok(previous));
        assert_eq!(manager.control_id(window), Some(value));
        assert_eq!(manager.get(window).unwrap().id_menu, value);
        assert_eq!(manager.menu(window), None);
        previous = value;
    }
}

#[test]
fn control_effective_child_mask_not_parent_presence() {
    let mut manager = WindowManager::new();
    let parent = manager.create(7, None, 0x1000).unwrap();
    for style in [0, WS_POPUP, WS_CHILD | WS_POPUP, WS_CHILD, WS_CHILD | 0x1000_0000] {
        let window = manager.create(7, Some(parent), 0x2000).unwrap();
        manager.set_window_styles(window, style, 0).unwrap();
        manager.set_menu(window, Some(8)).unwrap();
        let before = manager.get(window).unwrap();
        if style & (WS_CHILD | WS_POPUP) == WS_CHILD {
            assert_eq!(manager.set_control_id(window, 0xffff_ffff_8000_0042), Ok(0));
            assert_eq!(manager.control_id(window), Some(0xffff_ffff_8000_0042));
        } else {
            assert_eq!(manager.set_control_id(window, 42), Err(WindowError::InvalidParent));
            assert_eq!(manager.control_id(window), None);
            assert_eq!(manager.get(window), Some(before));
        }
        assert_eq!(manager.menu(window), Some(8));
    }
}

#[test]
fn control_menu_destruction_does_not_clear_numeric_alias() {
    let mut manager = WindowManager::new();
    let window = child(&mut manager);
    let top = manager.create(7, None, 0x1000).unwrap();
    manager.set_menu(top, Some(42)).unwrap();
    manager.set_control_id(window, 42).unwrap();
    manager.clear_menu(42);
    assert_eq!(manager.menu(top), None);
    assert_eq!(manager.control_id(window), Some(42));
}

#[test]
fn control_destroyed_handle_cannot_mutate_survivor_or_reuse_id() {
    let mut manager = WindowManager::new();
    let old = child(&mut manager);
    manager.set_control_id(old, u64::MAX).unwrap();
    manager.destroy(old).unwrap();
    let new = child(&mut manager);
    assert_ne!(old, new);
    assert_eq!(manager.set_control_id(old, 12), Err(WindowError::NoSuchWindow));
    assert_eq!(manager.control_id(old), None);
    assert_eq!(manager.control_id(new), Some(0));
}

#[test]
fn control_class_creation_uses_same_record_and_process_namespace() {
    let mut manager = WindowManager::new();
    let parent = manager.create(7, None, 0x1000).unwrap();
    let atom = manager.register_class(&[69, 68, 73, 84], 0x2000).unwrap();
    let window = manager.create_class_atom(7, Some(parent), atom).unwrap();
    manager.set_window_styles(window, WS_CHILD, 0).unwrap();
    manager.set_control_id(window, 0x8000_0000_0000_0001).unwrap();
    assert_eq!(manager.get(window).unwrap().id_menu, 0x8000_0000_0000_0001);
    assert_eq!(manager.get(window).unwrap().class_atom, Some(atom));
    let mut other = WindowManager::new();
    let alias = child(&mut other);
    assert_eq!(alias, window);
    assert_eq!(other.control_id(alias), Some(0));
}
