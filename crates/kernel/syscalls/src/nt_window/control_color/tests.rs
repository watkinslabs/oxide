use super::*;
use alloc::vec::Vec;
use ipc::win32_gdi::{GdiManager, GdiError, Rect};
use std::cell::RefCell;

#[test]
fn control_color_edit_returns_actual_brush_and_fills_clipped_pixels() {
    let state = RefCell::new(GdiManager::new());
    let dc = state.borrow_mut().create_dc(4, 3).unwrap();
    state.borrow_mut().set_text_attribute(dc, TextAttribute::Foreground, 0x123456).unwrap();
    state.borrow_mut().set_text_attribute(dc, TextAttribute::Background, 0xabcdef).unwrap();
    state.borrow_mut().set_text_attribute(dc, TextAttribute::BackgroundMode, 1).unwrap();
    let before = state.borrow().text_state(dc).unwrap();
    let brush = apply(WM_CTLCOLOREDIT, |field, color| state.borrow_mut().set_text_attribute(dc, field, color),
        |role| state.borrow_mut().system_brush(role)).unwrap() as u32;
    let after = state.borrow().text_state(dc).unwrap();
    assert_eq!((after.attributes.foreground, after.attributes.background), (0, 0xffffff));
    assert_eq!(after.attributes.background_mode, before.attributes.background_mode);
    assert_eq!(after.font, before.font);
    assert_eq!(state.borrow().selected_object(dc, ipc::win32_gdi::TYPE_BRUSH), Some(ipc::win32_gdi::stock_object(0).unwrap().handle));
    let mut owner = state.borrow_mut();
    owner.select_brush(dc, brush).unwrap();
    owner.intersect_clip_rect(dc, Rect { left: 1, top: 1, right: 3, bottom: 3 }).unwrap();
    owner.pat_blt(dc, 0, 0, 4, 3, 0x00f00021).unwrap();
    assert_eq!(owner.pixels(dc).unwrap(), &[0,0,0,0, 0,0xffffff,0xffffff,0, 0,0xffffff,0xffffff,0]);
}

#[test]
fn control_color_roles_and_failed_dc_still_return_system_brush() {
    for message in [WM_CTLCOLOREDIT, WM_CTLCOLORLISTBOX] { assert_eq!(role(message), Some(SystemColor::Window)); }
    for message in [WM_CTLCOLORMSGBOX, WM_CTLCOLORBTN, WM_CTLCOLORDLG, WM_CTLCOLORSTATIC] { assert_eq!(role(message), Some(SystemColor::Face)); }
    let calls = RefCell::new(Vec::new());
    assert_eq!(apply(WM_CTLCOLOREDIT, |field, color| {
        calls.borrow_mut().push((field, color)); Err::<u32, _>(GdiError::NoSuchObject)
    }, |_| Ok(0x100040)), Some(0x100040));
    assert_eq!(*calls.borrow(), [(TextAttribute::Foreground, 0), (TextAttribute::Background, 0xffffff)]);
    assert_eq!(apply(WM_CTLCOLOREDIT, |_, _| Ok::<u32, ()>(0), |_| Err(())), Some(0));
    assert_eq!(apply(0x1337, |_, _| -> Result<u32, ()> { panic!("unclaimed changed DC") }, |_| panic!("unclaimed allocated brush")), None);
    assert_eq!(role(0x137), None);
}
