use super::*;
use alloc::vec;
#[test]
fn getdc_uses_style_and_null_uses_desktop_window_cache() {
    for (hwnd, flags) in [(7, DCX_USESTYLE), (0, DCX_CACHE | DCX_WINDOW)] {
        assert_eq!(route(GET_DC, &[hwnd], |r| { assert_eq!(r, Request::Acquire { hwnd: hwnd as u32, region: 0, flags }); 0x1234 }), Some(0x1234));
    }
}
#[test]
fn getdcex_preserves_consumed_region_and_windows_flag_width() {
    let flags = DCX_WINDOW | DCX_INTERSECTRGN;
    assert_eq!(route(GET_DC_EX, &[7, 0x401234, u64::from(flags) | (1 << 40)], |r| {
        assert_eq!(r, Request::Acquire { hwnd: 7, region: 0x401234, flags }); 77
    }), Some(77));
    assert_eq!(route(GET_DC_EX, &[7, u64::MAX, 0], |r| {
        assert_eq!(r, Request::Acquire { hwnd: 7, region: 0, flags: 0 }); 88
    }), Some(88));
}
#[test]
fn malformed_consumed_handles_fail_without_calling_owner() {
    for (ordinal, args) in [(GET_DC, vec![1 << 40]), (GET_DC_EX, vec![7, 1 << 40, DCX_EXCLUDERGN as u64]),
        (GET_DC_EX, vec![7, 2]), (RELEASE_DC, vec![0, 1 << 40])] {
        assert_eq!(route(ordinal, &args, |_| panic!("invalid identity reached owner")), Some(0));
    }
}
#[test]
fn release_ignores_hwnd_and_preserves_full_owner_result() {
    assert_eq!(route(RELEASE_DC, &[u64::MAX, 0x1234], |r| {
        assert_eq!(r, Request::Release { dc: 0x1234 }); 1
    }), Some(1));
    assert_eq!(route(0, &[], |_| panic!("unrelated ordinal reached owner")), None);
}
