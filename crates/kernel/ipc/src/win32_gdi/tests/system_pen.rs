//! Protected system-pen identity, colour tracking and deletion protection.
use super::*;

#[test]
fn system_pen_identity_is_cached_and_typed() {
    let mut state = GdiManager::new();
    let window = state.system_pen(SystemColor::Window).unwrap();
    assert_eq!(state.system_pen(SystemColor::Window), Ok(window));
    let face = state.system_pen(SystemColor::Face).unwrap();
    assert_ne!(face, window);
    assert_eq!(state.pen_description(window, 0).unwrap().color, SystemColor::Window.color());
    assert_eq!(state.pen_description(window, 0).unwrap().width, 1);
}

#[test]
fn a_changed_role_colour_retires_the_cached_pen() {
    let mut state = GdiManager::new();
    let first = state.system_pen_value(SystemColor::Face, 0x00112233).unwrap();
    assert_eq!(state.system_pen_value(SystemColor::Face, 0x00112233), Ok(first));
    let second = state.system_pen_value(SystemColor::Face, 0x00445566).unwrap();
    assert_ne!(second, first);
    assert_eq!(state.pen_description(second, 0).unwrap().color, 0x00445566);
}

#[test]
fn application_deletion_cannot_free_a_system_pen() {
    let mut state = GdiManager::new();
    let pen = state.system_pen(SystemColor::WindowFrame).unwrap();
    assert!(state.is_system_pen(pen));
    assert_eq!(state.delete_object(pen), Ok(()));
    assert_eq!(state.system_pen(SystemColor::WindowFrame), Ok(pen));
    assert_eq!(state.pen_description(pen, 0).unwrap().color, SystemColor::WindowFrame.color());
}

#[test]
fn a_pen_of_another_role_is_not_protected_by_this_role() {
    let mut state = GdiManager::new();
    let system = state.system_pen(SystemColor::Highlight).unwrap();
    let plain = state.create_pen(0, 1, 0x00ff0000).unwrap();
    assert!(!state.is_system_pen(plain));
    assert!(state.is_system_pen(system));
}
