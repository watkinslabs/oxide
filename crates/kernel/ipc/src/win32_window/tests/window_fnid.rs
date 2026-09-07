//! Window function identity: what an identity names and what a window keeps.
use super::*;
use crate::win32_window::WindowManager;

#[test]
fn only_an_identity_with_the_valid_bit_and_an_index_inside_the_arrays_names_a_procedure() {
    assert_eq!(fnid_proc_index(make_fnid(0)), Some(0));
    assert_eq!(fnid_proc_index(make_fnid(CLIENT_PROC_COUNT - 1)), Some(CLIENT_PROC_COUNT as usize - 1));
    assert_eq!(fnid_proc_index(make_fnid(CLIENT_PROC_COUNT)), None);
    assert_eq!(fnid_proc_index(0), None);
    // The index alone, without the valid bit, names nothing.
    assert_eq!(fnid_proc_index(2), None);
    assert_eq!(fnid_proc_index(0xffff), None);
}

#[test]
fn a_window_keeps_the_first_identity_it_is_given() {
    let mut state = WindowManager::new();
    let window = state.create(1, None, 0).unwrap();
    assert_eq!(state.window_fnid(window), Some(0));
    assert!(state.set_window_fnid(window, make_fnid(2)).is_ok());
    assert_eq!(state.window_fnid(window), Some(make_fnid(2)));
    // Naming the same identity again changes nothing and is accepted.
    assert!(state.set_window_fnid(window, make_fnid(2)).is_ok());
    // A different identity is refused, and the window keeps the one it has.
    assert!(state.set_window_fnid(window, make_fnid(7)).is_err());
    assert_eq!(state.window_fnid(window), Some(make_fnid(2)));
}

#[test]
fn a_window_that_does_not_exist_names_no_identity_and_takes_none() {
    let mut state = WindowManager::new();
    let window = state.create(1, None, 0).unwrap();
    state.destroy(window).unwrap();
    assert_eq!(state.window_fnid(window), None);
    assert!(state.set_window_fnid(window, make_fnid(2)).is_err());
}

#[test]
fn a_builtin_control_identity_reserves_its_whole_extra_area_and_a_dialog_reserves_none() {
    assert_eq!(private_size(make_fnid(7), 24), 24);
    assert_eq!(private_size(make_fnid(PROC_DIALOG), 30), 0);
    assert_eq!(private_size(make_fnid(PROC_MDICLIENT), 16), 0);
    // An identity with no valid bit, and one past the arrays, name no control.
    assert_eq!(private_size(0, 24), 0);
    assert_eq!(private_size(make_fnid(CLIENT_PROC_COUNT), 24), 0);
}

#[test]
fn taking_a_control_identity_closes_the_extra_area_to_the_application() {
    use crate::win32_window::LongPtrError;
    let mut state = WindowManager::new();
    let atom = state.register_class_with_extra(&[b'E' as u16], 0, 16).unwrap();
    let window = state.create_class_atom(1, None, atom).unwrap();
    // Before the identity the whole area is the application's.
    assert_eq!(state.set_window_long(window, 0, 8, 0x1122_3344_5566_7788), Ok(0));
    assert_eq!(state.get_window_long(window, 0, 8), Ok(0x1122_3344_5566_7788));
    state.set_window_fnid(window, make_fnid(11)).unwrap();
    assert_eq!(state.get_window_long(window, 0, 8), Err(LongPtrError::InvalidIndex));
    assert_eq!(state.set_window_long(window, 8, 8, 1), Err(LongPtrError::InvalidIndex));
    // The control's own accesses still reach it, and read what was written.
    assert_eq!(state.get_window_long_internal(window, 0, 8), Ok(0x1122_3344_5566_7788));
    assert_eq!(state.set_window_long_internal(window, 8, 8, 0x99), Ok(0));
    assert_eq!(state.get_window_long_internal(window, 8, 8), Ok(0x99));
    // An internal access past the buffer is still out of range.
    assert_eq!(state.get_window_long_internal(window, 16, 8), Err(LongPtrError::InvalidIndex));
}

#[test]
fn a_dialog_identity_leaves_the_extra_area_open_to_the_application() {
    let mut state = WindowManager::new();
    let atom = state.register_class_with_extra(&[b'D' as u16], 0, 30).unwrap();
    let window = state.create_class_atom(1, None, atom).unwrap();
    state.set_window_fnid(window, make_fnid(PROC_DIALOG)).unwrap();
    assert_eq!(state.set_window_long(window, 0, 8, 0x77), Ok(0));
    assert_eq!(state.get_window_long(window, 0, 8), Ok(0x77));
}
