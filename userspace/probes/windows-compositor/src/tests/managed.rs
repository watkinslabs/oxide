use crate::managed::{at_creation, Managed};
use crate::styles::{WS_CAPTION, WS_CHILD, WS_EX_APPWINDOW, WS_POPUP, WS_SYSMENU, WS_THICKFRAME, WS_VISIBLE};

fn probe(style: u32, ex_style: u32) -> Managed {
    Managed { style, ex_style, activating: false, active: false, fullscreen: false, owns_popups: false }
}

/// The dropdown: a bare popup with no caption, no thick frame, no system menu
/// and no application-window extended style, shown without activation. It is
/// unmanaged, so its X window is override-redirect and the desktop puts no
/// frame around it.
#[test]
fn a_menu_popup_is_not_managed() {
    assert!(!at_creation(WS_POPUP, 0));
    assert!(!at_creation(WS_POPUP | WS_VISIBLE, 0));
}

/// The application's own window carries a caption and is framed.
#[test]
fn a_captioned_window_is_managed() {
    assert!(at_creation(WS_CAPTION, 0));
    // Half a caption is not a caption: both frame bits are required.
    assert!(!at_creation(WS_CAPTION & !crate::styles::WS_BORDER, 0));
}

#[test]
fn a_child_window_is_never_managed() {
    assert!(!at_creation(WS_CHILD, 0));
    assert!(!at_creation(WS_CHILD | WS_CAPTION, 0));
    assert!(!at_creation(WS_CHILD, WS_EX_APPWINDOW));
    // WS_POPUP alongside WS_CHILD is a popup, and the ordinary popup rules run.
    assert!(at_creation(WS_CHILD | WS_POPUP | WS_CAPTION, 0));
}

#[test]
fn a_thick_frame_or_application_style_is_managed() {
    assert!(at_creation(WS_THICKFRAME, 0));
    assert!(at_creation(WS_POPUP, WS_EX_APPWINDOW));
}

/// A popup with a system menu is a caption in all but name.
#[test]
fn a_popup_with_a_system_menu_is_managed() {
    assert!(at_creation(WS_POPUP | WS_SYSMENU, 0));
    // The system menu earns nothing for a window that is not a popup and has
    // neither caption nor thick frame.
    assert!(!at_creation(WS_SYSMENU, 0));
}

#[test]
fn activation_ownership_and_fullscreen_each_make_a_bare_popup_managed() {
    let bare = probe(WS_POPUP, 0);
    assert!(!bare.is_managed());
    assert!(Managed { activating: true, ..bare }.is_managed());
    assert!(Managed { active: true, ..bare }.is_managed());
    assert!(Managed { fullscreen: true, ..bare }.is_managed());
    assert!(Managed { owns_popups: true, ..bare }.is_managed());
    // None of them reaches a child window.
    let child = probe(WS_CHILD, 0);
    for probe in [Managed { activating: true, ..child }, Managed { active: true, ..child }, Managed { fullscreen: true, ..child }, Managed { owns_popups: true, ..child }] {
        assert!(!probe.is_managed());
    }
}

/// Ownership is the last word, after every style test has declined.
#[test]
fn owning_a_popup_is_weaker_than_every_style_test() {
    assert!(Managed { owns_popups: true, ..probe(WS_POPUP, 0) }.is_managed());
    assert!(!probe(WS_POPUP, 0).is_managed());
}
