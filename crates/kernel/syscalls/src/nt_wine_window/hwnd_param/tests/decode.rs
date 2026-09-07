//! The one method-to-request mapping.
//!
//! The exhaustiveness test is the point of this file: the ordinal is refused
//! as a whole when no route claims it, and a refusal here is answered with the
//! invalid-service status, which a client dereferences the result of. A method
//! this decoder does not name must therefore be a red test, not a dead guest.
use super::*;

#[test]
fn every_method_index_the_enumeration_holds_decodes_to_a_request() {
    for method in 0..COUNT {
        assert!(decode(method, 0).is_some(), "method {method} decodes to nothing");
    }
    // One past the enumeration names nothing, and neither does a wild code.
    assert_eq!(decode(COUNT, 0), None);
    assert_eq!(decode(0xffff_ffff, 0), None);
}

#[test]
fn the_three_rectangle_methods_are_three_different_rectangles() {
    // The window, client and present rectangles are separate methods. Reading
    // one flag out of the parameter record instead once made all three the
    // same query and answered the window rectangle for a client request.
    let kind = |method| match decode(method, 0x40) {
        Some(Request::GetRect { kind, params }) => { assert_eq!(params, 0x40); kind }
        other => panic!("method {method} is not a rectangle request: {other:?}"),
    };
    assert_eq!(kind(GET_WINDOW_RECT), RectKind::Window);
    assert_eq!(kind(GET_CLIENT_RECT), RectKind::Client);
    assert_eq!(kind(GET_PRESENT_RECT), RectKind::Present);
    // The child rectangle is the window rectangle in the parent's space.
    assert_eq!(kind(GET_CHILD_RECT), RectKind::Parent);
}

#[test]
fn the_window_long_methods_carry_their_width_and_encoding() {
    let long = |method| match decode(method, 0x3f0) {
        Some(Request::GetWindowLong { offset, width, ansi }) => { assert_eq!(offset, 0x3f0); (width, ansi) }
        other => panic!("method {method} is not a window long: {other:?}"),
    };
    assert_eq!(long(GET_WINDOW_LONG_A), (4, true));
    assert_eq!(long(GET_WINDOW_LONG_W), (4, false));
    assert_eq!(long(GET_WINDOW_LONG_PTR_A), (8, true));
    assert_eq!(long(GET_WINDOW_LONG_PTR_W), (8, false));
    // A negative index arrives as a sign-extended offset, not a huge one.
    assert_eq!(decode(GET_WINDOW_LONG_W, -16i64 as u64),
        Some(Request::GetWindowLong { offset: -16, width: 4, ansi: false }));
    assert_eq!(decode(GET_WINDOW_WORD, -21i64 as u64), Some(Request::GetWindowWord { offset: -21 }));
}

#[test]
fn the_class_long_methods_carry_their_width_and_their_encoding() {
    let class = |method| match decode(method, -12i64 as u64) {
        Some(Request::ClassLong { offset, width, ansi }) => { assert_eq!(offset, -12); (width, ansi) }
        other => panic!("method {method} is not a class long: {other:?}"),
    };
    assert_eq!(class(GET_CLASS_LONG_A), (4, true));
    assert_eq!(class(GET_CLASS_LONG_W), (4, false));
    assert_eq!(class(GET_CLASS_LONG_PTR_A), (8, true));
    assert_eq!(class(GET_CLASS_LONG_PTR_W), (8, false));
    assert_eq!(class(GET_CLASS_WORD), (2, true));
}

#[test]
fn the_parameter_word_reaches_each_request_unaltered() {
    assert_eq!(decode(CLIENT_TO_SCREEN, 0x7fff_0000), Some(Request::ClientToScreen { point: 0x7fff_0000 }));
    assert_eq!(decode(SCREEN_TO_CLIENT, 0x7fff_0000), Some(Request::ScreenToClient { point: 0x7fff_0000 }));
    assert_eq!(decode(GET_SCROLL_INFO, 0x30), Some(Request::GetScrollInfo { params: 0x30 }));
    assert_eq!(decode(GET_WINDOW_INFO, 0x30), Some(Request::GetWindowInfo { info: 0x30 }));
    assert_eq!(decode(GET_WINDOW_RELATIVE, 5), Some(Request::GetWindowRelative { relationship: 5 }));
    assert_eq!(decode(GET_WINDOW_THREAD, 0x30), Some(Request::GetWindowThread { process: 0x30 }));
    assert_eq!(decode(IS_CHILD, 0x22), Some(Request::IsChild { child: 0x22 }));
    assert_eq!(decode(MAP_WINDOW_POINTS, 0x30), Some(Request::MapWindowPoints { params: 0x30 }));
    assert_eq!(decode(MIRROR_RGN, 0x44), Some(Request::MirrorRgn { region: 0x44 }));
    assert_eq!(decode(MONITOR_FROM_WINDOW, 2), Some(Request::MonitorFromWindow { flags: 2 }));
    assert_eq!(decode(SET_DIALOG_INFO, 0x9000), Some(Request::SetDialogInfo { info: 0x9000 }));
    assert_eq!(decode(SET_MDI_CLIENT_INFO, 0x9000), Some(Request::SetMdiClientInfo { info: 0x9000 }));
    assert_eq!(decode(SEND_HARDWARE_INPUT, 0x30), Some(Request::SendHardwareInput { params: 0x30 }));
    assert_eq!(decode(EXPOSE_WINDOW_SURFACE, 0x30), Some(Request::ExposeWindowSurface { params: 0x30 }));
    assert_eq!(decode(GET_WIN_MONITOR_DPI, 0), Some(Request::GetWinMonitorDpi { kind: 0 }));
    assert_eq!(decode(SET_RAW_WINDOW_POS, 0x30), Some(Request::SetRawWindowPos { params: 0x30 }));
    assert_eq!(decode(GET_PRIVATE_DATA, 0x30), Some(Request::GetPrivateData { params: 0x30 }));
    assert_eq!(decode(SET_PRIVATE_DATA, 0x30), Some(Request::SetPrivateData { params: 0x30 }));
}

#[test]
fn each_method_index_names_exactly_one_position_in_the_enumeration() {
    // The indices are the client's, so their values are the contract; a
    // renumbering here silently reroutes every call the client makes.
    let named = [CLIENT_TO_SCREEN, GET_CHILD_RECT, GET_CLASS_LONG_A, GET_CLASS_LONG_W, GET_CLASS_LONG_PTR_A,
        GET_CLASS_LONG_PTR_W, GET_CLASS_WORD, GET_SCROLL_INFO, GET_WINDOW_INFO, GET_WINDOW_LONG_A,
        GET_WINDOW_LONG_W, GET_WINDOW_LONG_PTR_A, GET_WINDOW_LONG_PTR_W, GET_WINDOW_RECT, GET_CLIENT_RECT,
        GET_PRESENT_RECT, GET_WINDOW_RELATIVE, GET_WINDOW_THREAD, GET_WINDOW_WORD, IS_CHILD, MAP_WINDOW_POINTS,
        MIRROR_RGN, MONITOR_FROM_WINDOW, SCREEN_TO_CLIENT, SET_DIALOG_INFO, SET_MDI_CLIENT_INFO,
        SEND_HARDWARE_INPUT, EXPOSE_WINDOW_SURFACE, GET_WIN_MONITOR_DPI, SET_RAW_WINDOW_POS,
        GET_PRIVATE_DATA, SET_PRIVATE_DATA];
    assert_eq!(named.len() as u32, COUNT);
    for (position, method) in named.iter().enumerate() { assert_eq!(*method, position as u32); }
}
