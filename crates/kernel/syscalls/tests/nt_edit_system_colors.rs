//! EDIT/edge color queries must reach canonical protected brushes and pixels.
#[path = "../src/nt_wine_window/system_color_raw.rs"]
mod raw;
#[path = "../../ipc/src/win32_gdi/system_text_colors.rs"]
mod colors;
use ipc::win32_gdi::{GdiManager, SystemColor};

#[test]
fn edit_selection_and_frame_color_queries_do_not_allocate_or_mutate_dc() {
    let mut owner = GdiManager::new(); let dc = owner.create_dc(2,2).unwrap();
    let handles = owner.live_handles(); let attributes = owner.text_state(dc).unwrap().attributes;
    let missing: Vec<_> = [6,13,14].into_iter().filter(|index| SystemColor::from_index(*index).is_none()).collect();
    assert!(missing.is_empty(),"mandatory system roles missing: {missing:?}");
    for (index,xrgb,colorref) in [(6,colors::WINDOW_FRAME,0), (13,colors::HIGHLIGHT,0x006a240a),
        (14,colors::HIGHLIGHT_TEXT,0x00ffffff)] {
        let role = SystemColor::from_index(index).expect("mandatory EDIT/frame color missing");
        assert_eq!(role.color(),xrgb);
        assert_eq!(raw::route::<()>(0x133d,&[index as u64 | (7u64<<32),6], |_|panic!("color query allocated brush")),Some(colorref));
    }
    assert_eq!(owner.live_handles(),handles);
    assert_eq!(owner.text_state(dc).unwrap().attributes,attributes);
}

#[test]
fn selected_text_background_and_monochrome_frame_use_protected_distinct_brushes() {
    let mut owner = GdiManager::new(); let dc = owner.create_dc(6,1).unwrap();
    let attributes = owner.text_state(dc).unwrap().attributes;
    let selected = owner.selected_object(dc,ipc::win32_gdi::TYPE_BRUSH);
    let mut handles = Vec::new();
    for (column,index,xrgb) in [(0,6,colors::WINDOW_FRAME),(1,13,colors::HIGHLIGHT),(2,14,colors::HIGHLIGHT_TEXT),
        (3,8,0),(4,5,0xffffff),(5,20,0xffffff)] {
        let previous = owner.selected_object(dc,ipc::win32_gdi::TYPE_BRUSH);
        let brush = raw::route(0x133d,&[index,7], |role|owner.system_brush(role)).unwrap() as u32;
        assert_eq!(owner.selected_object(dc,ipc::win32_gdi::TYPE_BRUSH),previous);
        assert_ne!(brush,0,"missing canonical system role {index}");
        assert!(owner.contains_object(brush));
        assert!(!handles.contains(&brush),"distinct system roles aliased"); handles.push(brush);
        assert_eq!(owner.text_state(dc).unwrap().attributes,attributes);
        owner.select_brush(dc,brush).unwrap();
        owner.pat_blt(dc,column,0,1,1,0x00f00021).unwrap();
        assert_eq!(owner.pixels(dc).unwrap()[column as usize],xrgb);
        owner.delete_object(brush).unwrap();
        assert!(owner.contains_object(brush));
        assert_eq!(raw::route(0x133d,&[index,7], |role|owner.system_brush(role)),Some(brush as u64));
    }
    // A fresh DC carries the stock white brush; the colour queries never replace it.
    assert_eq!(selected,owner.stock_object(0).map(|stock|stock.handle));
    owner.delete_object(dc).unwrap();
    for handle in handles { assert!(owner.contains_object(handle)); }
}

#[test]
fn normal_status_edges_have_all_required_canonical_roles() {
    for index in [15,16,20,21,22] {
        let role = SystemColor::from_index(index).expect("normal edge palette missing");
        let mut owner = GdiManager::new();
        let handle = raw::route(0x133d,&[index as u64,7], |role|owner.system_brush(role)).unwrap() as u32;
        assert!(owner.is_system_brush(handle));
        let dc = owner.create_dc(1,1).unwrap(); owner.select_brush(dc,handle).unwrap();
        owner.pat_blt(dc,0,0,1,1,0x00f00021).unwrap();
        assert_eq!(owner.pixels(dc).unwrap(),&[role.color()]);
    }
}
