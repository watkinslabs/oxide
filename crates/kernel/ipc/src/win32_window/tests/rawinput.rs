use super::*;

fn device(page: u16, usage: u16, flags: u32, target: Option<WindowId>) -> RawRegistration {
    RawRegistration { usage_page: page, usage, flags, target }
}

#[test]
fn the_inventory_presents_one_mouse_and_one_keyboard_with_paths_and_info() {
    let list = devices();
    assert_eq!(list[0], RawDevice { handle: MOUSE_HANDLE, kind: RIM_TYPEMOUSE });
    assert_eq!(list[1], RawDevice { handle: KEYBOARD_HANDLE, kind: RIM_TYPEKEYBOARD });
    assert!(device_path(MOUSE_HANDLE).is_some());
    assert_eq!(device_path(3), None);
    let info = device_info(KEYBOARD_HANDLE).unwrap();
    assert_eq!(u32::from_le_bytes(info[0..4].try_into().unwrap()), RID_DEVICE_INFO_BYTES as u32);
    assert_eq!(u32::from_le_bytes(info[4..8].try_into().unwrap()), RIM_TYPEKEYBOARD);
    assert_eq!(u32::from_le_bytes(info[20..24].try_into().unwrap()), 12);
    assert_eq!(u32::from_le_bytes(info[28..32].try_into().unwrap()), 101);
    let mouse = device_info(MOUSE_HANDLE).unwrap();
    assert_eq!(u32::from_le_bytes(mouse[12..16].try_into().unwrap()), 5);
    assert_eq!(device_info(9), None);
}

#[test]
fn an_input_sink_without_a_target_and_a_removal_with_one_are_both_refused() {
    let mut registrations = RawRegistrations::new();
    let target = WindowId::from_raw(2);
    assert_eq!(registrations.register(&[device(1, 2, RIDEV_INPUTSINK, None)]), Err(RawInputError::InvalidParameter));
    assert_eq!(registrations.register(&[device(1, 2, RIDEV_REMOVE, target)]), Err(RawInputError::InvalidParameter));
    assert!(registrations.is_empty());
}

#[test]
fn a_batch_is_admitted_whole_before_any_of_it_applies() {
    let mut registrations = RawRegistrations::new();
    let batch = [device(1, 2, 0, None), device(1, 6, RIDEV_INPUTSINK, None)];
    assert_eq!(registrations.register(&batch), Err(RawInputError::InvalidParameter));
    assert!(registrations.is_empty());
}

#[test]
fn registrations_stay_sorted_and_a_repeat_usage_replaces_its_entry() {
    let mut registrations = RawRegistrations::new();
    registrations.register(&[device(1, 6, 0, None), device(1, 2, 0, None), device(0xd, 4, 0, None)]).unwrap();
    let keys: Vec<(u16, u16)> = registrations.entries().iter().map(|entry| (entry.usage_page, entry.usage)).collect();
    assert_eq!(keys, alloc::vec![(1, 2), (1, 6), (0xd, 4)]);
    registrations.register(&[device(1, 6, RIDEV_NOLEGACY, None)]).unwrap();
    assert_eq!(registrations.len(), 3);
    assert_eq!(registrations.entries()[1].flags, RIDEV_NOLEGACY);
}

#[test]
fn a_removal_drops_only_the_named_usage() {
    let mut registrations = RawRegistrations::new();
    registrations.register(&[device(1, 2, 0, None), device(1, 6, 0, None)]).unwrap();
    registrations.register(&[device(1, 2, RIDEV_REMOVE, None)]).unwrap();
    assert_eq!(registrations.len(), 1);
    assert_eq!(registrations.entries()[0].usage, 6);
    registrations.register(&[device(9, 9, RIDEV_REMOVE, None)]).unwrap();
    assert_eq!(registrations.len(), 1);
}
