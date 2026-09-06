use super::*;

#[test]
fn get_params_and_scroll_info_preserve_wire_layout() {
    let params = GetScrollInfoParams { bar: ipc::win32_window::SB_VERT, info: 0x1122_3344_5566_7788 };
    assert_eq!(GetScrollInfoParams::decode(params.encode()), params);
    let info = ipc::win32_window::ScrollInfo { cb_size: 28, mask: 0x17, min: -2, max: 100, page: 8, pos: 9, track_pos: 10 };
    assert_eq!(decode_scroll_info(encode_scroll_info(info)), info);
}
