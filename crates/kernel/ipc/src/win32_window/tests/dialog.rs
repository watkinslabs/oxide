//! The dialog state pointer and the MDI-client mark.
use crate::win32_window::WindowManager;

#[test]
fn a_window_carries_no_dialog_state_until_it_is_given_one() {
    let mut state = WindowManager::new();
    let window = state.create(1, None, 0).unwrap();
    assert_eq!(state.dialog_info(window), Some(0));
    assert_eq!(state.set_dialog_info(window, 0x7fff_0000_1000), Ok(0));
    assert_eq!(state.dialog_info(window), Some(0x7fff_0000_1000));
    // The replacement answers the pointer the window held.
    assert_eq!(state.set_dialog_info(window, 0), Ok(0x7fff_0000_1000));
}

#[test]
fn the_mdi_client_mark_is_taken_once_and_never_taken_back() {
    let mut state = WindowManager::new();
    let window = state.create(1, None, 0).unwrap();
    assert_eq!(state.is_mdi_client(window), Some(false));
    state.mark_mdi_client(window).unwrap();
    assert_eq!(state.is_mdi_client(window), Some(true));
    state.mark_mdi_client(window).unwrap();
    assert_eq!(state.is_mdi_client(window), Some(true));
}

#[test]
fn a_window_that_does_not_exist_carries_neither_mark() {
    let mut state = WindowManager::new();
    let window = state.create(1, None, 0).unwrap();
    state.destroy(window).unwrap();
    assert_eq!(state.dialog_info(window), None);
    assert_eq!(state.is_mdi_client(window), None);
    assert!(state.set_dialog_info(window, 1).is_err());
    assert!(state.mark_mdi_client(window).is_err());
}
