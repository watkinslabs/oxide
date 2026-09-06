use super::*;

const CTRL_N: Accel = Accel { virt: FVIRTKEY | FCONTROL, key: 0x4e, cmd: 0x1f4 };
const ALT_X: Accel = Accel { virt: FALT | 0x80, key: b'x' as u16, cmd: 7 };

#[test]
fn a_table_needs_at_least_one_entry_and_hands_out_distinct_handles() {
    let mut tables = AcceleratorTables::new();
    assert_eq!(tables.create(&[]), Err(AccelError::EmptyTable));
    let first = tables.create(&[CTRL_N]).unwrap();
    let second = tables.create(&[CTRL_N, ALT_X]).unwrap();
    assert_ne!(first, second);
    assert_eq!(tables.entries(second).unwrap().len(), 2);
    assert!(tables.destroy(first).is_ok());
    assert_eq!(tables.entries(first), Err(AccelError::NoSuchTable));
    assert_eq!(tables.destroy(first), Err(AccelError::NoSuchTable));
}

#[test]
fn copying_strips_the_resource_end_marker_and_honours_the_limit() {
    let mut tables = AcceleratorTables::new();
    let handle = tables.create(&[CTRL_N, ALT_X]).unwrap();
    let copied = tables.copy(handle, 8).unwrap();
    assert_eq!(copied[1].virt, FALT);
    assert_eq!(tables.copy(handle, 1).unwrap(), alloc::vec![CTRL_N]);
}

#[test]
fn the_packed_record_round_trips_through_six_bytes() {
    assert_eq!(Accel::decode(&CTRL_N.encode()), Some(CTRL_N));
    assert_eq!(Accel::decode(&[1, 2, 3]), None);
    assert_eq!(ACCEL_BYTES, 6);
}

#[test]
fn only_keyboard_messages_can_carry_an_accelerator() {
    assert!(is_accelerator_message(WM_KEYDOWN));
    assert!(is_accelerator_message(WM_SYSCHAR));
    assert!(!is_accelerator_message(WM_KEYUP));
    assert!(!is_accelerator_message(0x0005));
}

#[test]
fn a_virtual_key_accelerator_demands_the_exact_modifier_set() {
    assert!(matches(WM_KEYDOWN, 0x4e, 0, FCONTROL, CTRL_N));
    assert!(!matches(WM_KEYDOWN, 0x4e, 0, FCONTROL | FSHIFT, CTRL_N));
    assert!(!matches(WM_KEYDOWN, 0x4e, 0, 0, CTRL_N));
    assert!(!matches(WM_KEYDOWN, 0x4f, 0, FCONTROL, CTRL_N));
    assert!(!matches(WM_CHAR, 0x4e, 0, FCONTROL, CTRL_N));
}

#[test]
fn a_character_accelerator_matches_by_alt_state_only() {
    assert!(matches(WM_SYSCHAR, b'x' as u64, 0, FALT, ALT_X));
    assert!(matches(WM_SYSCHAR, b'x' as u64, 0, FALT | FCONTROL, ALT_X));
    assert!(!matches(WM_CHAR, b'x' as u64, 0, 0, ALT_X));
    assert!(matches(WM_SYSKEYDOWN, b'x' as u64, 0x2000_0000, 0, ALT_X));
    assert!(!matches(WM_SYSKEYDOWN, b'x' as u64, 0x2100_0000, 0, ALT_X));
    assert_eq!(find(WM_KEYDOWN, 0x4e, 0, FCONTROL, &[ALT_X, CTRL_N]), Some(CTRL_N));
    assert_eq!(find(WM_KEYDOWN, 0x41, 0, FCONTROL, &[ALT_X, CTRL_N]), None);
}
