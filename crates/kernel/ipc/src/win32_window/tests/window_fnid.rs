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
