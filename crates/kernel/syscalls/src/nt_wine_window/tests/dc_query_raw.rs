use super::*;
use ipc::win32_gdi::{GdiManager,TextAttribute,DEFAULT_DC_FONT_HANDLE};
use syscall::nt_gdi_client as client;
#[path="../../nt_gdi/dc_query.rs"]
mod policy;

#[test]
fn caption_query_copies_actual_colorref_once_without_changing_private_dc() {
    let mut g=GdiManager::new();let dc=g.create_dc(4,4).unwrap();
    g.set_text_attribute(dc,TextAttribute::Foreground,0x123456).unwrap();
    g.set_text_attribute(dc,TextAttribute::Background,0xabcdee).unwrap();
    g.set_text_attribute(dc,TextAttribute::BackgroundMode,1).unwrap();
    let before=g.text_state(dc).unwrap().attributes;let handles=g.live_handles();
    for (method,expected) in [(9,0x563412),(1,0xeecdab),(2,1)] {
        assert_eq!(route(GET_DC_DWORD,&[dc as u64,method|(0x1234<<32),0x123400001000],
            |h|g.text_state(u32::try_from(h).ok()?).ok().map(|s|s.attributes),policy::dc_query_value,
            |p,value|{assert_eq!(p,0x123400001000);assert_eq!(value,expected);true}),Some(1));
    }
    assert_eq!(g.text_state(dc).unwrap().attributes,before);assert_eq!(g.live_handles(),handles);
    assert!(g.pixels(dc).unwrap().iter().all(|p|*p==0));
}

#[test]
fn direct_client_color_changes_survive_decode_and_getter_reencoding() {
    let dc=0x10040;
    let mut bytes=client::encode_dc_attr(dc,4,4,client::DcText::default()).unwrap();
    for colorref in [0x000a246au32,0x006a240a,0x00123456] {
        bytes[client::dc::TEXT_COLOR..client::dc::TEXT_COLOR+4].copy_from_slice(&colorref.to_le_bytes());
        let shared=client::decode_text(&bytes,dc).unwrap();
        let attributes=TextAttributes {foreground:shared.foreground,background:shared.background,
            background_mode:shared.background_mode,alignment:shared.alignment,current_position:shared.current_position};
        assert_eq!(route(GET_DC_DWORD,&[dc as u64,9,0x1000], |_|Some(attributes),policy::dc_query_value,
            |_,value|{assert_eq!(value,colorref);true}),Some(1));
    }
}

#[test]
fn wine_10_20_selector_matrix_exposes_only_notepad_backed_attributes() {
    // Pinned include/ntgdi.h defines these as one zero-based selector enum.
    // Keep the complete matrix here so adding a fabricated default cannot make
    // an unowned DC attribute look implemented.
    const REFERENCE_SELECTORS: [u32; 11] = [
        0, // NtGdiGetArcDirection
        1, // NtGdiGetBkColor
        2, // NtGdiGetBkMode
        3, // NtGdiGetDCBrushColor
        4, // NtGdiGetDCPenColor
        5, // NtGdiGetGraphicsMode
        6, // NtGdiGetLayout
        7, // NtGdiGetPolyFillMode
        8, // NtGdiGetROP2
        9, // NtGdiGetTextColor
        10, // NtGdiIsMemDC
    ];
    let attributes = TextAttributes::default();
    for selector in REFERENCE_SELECTORS {
        let supported = policy::dc_query_value(selector, attributes);
        if matches!(selector, 1 | 2 | 9) {
            assert!(supported.is_some(), "Notepad selector {selector} lost its canonical owner");
        } else {
            assert!(supported.is_none(), "selector {selector} must not invent unowned DC state");
        }
    }
}

#[test]
fn empty_dc_metrics_resolve_the_canonical_stock_font() {
    let mut g = GdiManager::new();
    let dc = g.create_dc(1, 1).unwrap();
    let state = g.text_state(dc).unwrap();
    assert_eq!(state.font, g.stock_font(DEFAULT_DC_FONT_HANDLE));
    let metrics = g.text_metrics(dc).unwrap();
    assert!(metrics.height > 0 && metrics.ascent > 0 && metrics.descent > 0);
    assert_eq!(metrics.average_width, metrics.max_width);
    assert_eq!(metrics.average_width, metrics.character_width);
}

#[test]
fn unknown_methods_invalid_dc_bad_pointer_and_failed_copy_are_false_without_write() {
    let attributes=TextAttributes::default();
    assert_eq!(route(0x11ee,&[], |_|panic!("unclaimed lookup"),policy::dc_query_value,|_,_|false),None);
    assert_eq!(route(GET_DC_DWORD,&[1,9], |_|panic!("short lookup"),policy::dc_query_value,|_,_|false),Some(0));
    assert_eq!(route(GET_DC_DWORD,&[u64::MAX,9,0x1000], |h|{assert_eq!(h,u64::MAX);None},policy::dc_query_value,
        |_,_|panic!("invalid DC wrote output")),Some(0));
    assert_eq!(route(GET_DC_DWORD,&[1,u64::MAX,0x1000], |_|Some(attributes),policy::dc_query_value,
        |_,_|panic!("unknown method wrote")),Some(0));
    for pointer in [0,u64::MAX-3] {
        assert_eq!(route(GET_DC_DWORD,&[1,9,pointer], |_|Some(attributes),policy::dc_query_value,
            |_,_|panic!("invalid pointer wrote")),Some(0));
    }
    assert_eq!(route(GET_DC_DWORD,&[1,9,0x1000], |_|Some(attributes),policy::dc_query_value,|_,_|false),Some(0));
}
