use super::*;

#[test]
fn method_params_have_the_wine_16_byte_layout() {
    let params = GetWindowRectsParams { rect: 0x1122_3344_5566_7788, client: 1, dpi: 144 };
    assert_eq!(GetWindowRectsParams::decode(params.encode()), params);
    assert_eq!(PARAM_BYTES, 16);
}

#[test]
fn methods_nine_through_twelve_preserve_offset_and_width() {
    assert_eq!(decode_request(GET_WINDOW_LONG_A, 0), Some(Request::GetWindowLong { offset: 0, width: 4 }));
    assert_eq!(decode_request(GET_WINDOW_LONG_W, 0x3f0), Some(Request::GetWindowLong { offset: 0x3f0, width: 4 }));
    assert_eq!(decode_request(GET_WINDOW_LONG_PTR_A, 0x3f0), Some(Request::GetWindowLong { offset: 0x3f0, width: 8 }));
    assert_eq!(decode_request(GET_WINDOW_LONG_PTR_W, 0x3f0), Some(Request::GetWindowLong { offset: 0x3f0, width: 8 }));
}

#[test]
fn popup_wins_and_child_ids_are_pointer_width() {
    assert!(is_effective_child(WS_CHILD));
    assert!(!is_effective_child(WS_CHILD | WS_POPUP));
    assert_eq!(classify_create_menu(WS_CHILD, u64::MAX), CreateMenuValue::ChildControlId(u64::MAX));
    assert_eq!(classify_create_menu(0, u64::MAX), CreateMenuValue::MenuHandle(u64::MAX));
}
