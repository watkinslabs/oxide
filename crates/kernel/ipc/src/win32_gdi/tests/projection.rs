use crate::win32_gdi::*;

#[test]
fn selected_object_query_uses_internal_type_and_retained_identity() {
    let mut state = GdiManager::new();
    let dc = state.create_dc(2, 2).unwrap();
    assert_eq!(state.selected_object(dc, TYPE_FONT), Some(DEFAULT_DC_FONT_HANDLE));
    assert_eq!(state.selected_object(dc, TYPE_BRUSH), Some(state.stock_object(0).unwrap().handle));
    let font = state.create_font(Font { height: -16, width: 0, weight: 400, italic: false }).unwrap();
    state.select_font(dc, font).unwrap(); state.delete_object(font).unwrap();
    assert_eq!(state.selected_object(dc, TYPE_FONT), Some(font));
    assert_eq!(state.selected_object(dc, 6), None);
    assert_eq!(state.selected_object(0, TYPE_FONT), None);
    state.select_font(dc, DEFAULT_DC_FONT_HANDLE).unwrap();
    assert_eq!(state.selected_object(dc, TYPE_FONT), Some(DEFAULT_DC_FONT_HANDLE));
    assert!(!state.contains_object(font));
}

fn font() -> Font { Font { height: -16, width: 0, weight: 400, italic: false } }

#[test]
fn live_projection_contains_exact_stock_and_typed_dynamic_identities_once() {
    let mut owner = GdiManager::new();
    let dc = owner.create_dc(2, 2).unwrap();
    let font = owner.create_font(font()).unwrap();
    let brush = owner.create_solid_brush(0x123456).unwrap();
    assert_eq!(dc, TYPE_DC | FIRST_DYNAMIC_SLOT);
    assert_eq!(font, TYPE_FONT | (FIRST_DYNAMIC_SLOT + 1));
    assert_eq!(brush, TYPE_BRUSH | (FIRST_DYNAMIC_SLOT + 2));
    let mut expected = alloc::vec![dc, font, brush];
    for index in [0, 1, 2, 3, 4, 5, 18] { expected.push(0x00900000 | (32 + index)); }
    for index in [6, 7, 8, 19] { expected.push(0x00b00000 | (32 + index)); }
    for index in [10, 11, 12, 13, 14, 16, 17] { expected.push(0x008a0000 | (32 + index)); }
    expected.sort_unstable();
    let mut actual = owner.live_handles(); actual.sort_unstable();
    assert_eq!(actual, expected);
    assert_eq!(actual.len(), 21);
    for handle in actual { assert!(owner.contains_object(handle)); }
    owner.delete_object(font).unwrap();
    assert!(!owner.contains_object(font));
    assert!(!owner.live_handles().contains(&font));
    assert!(owner.contains_object(dc) && owner.contains_object(brush));
}

#[test]
fn deleted_selected_brush_projects_until_final_deselection() {
    let mut owner = GdiManager::new();
    let first = owner.create_dc(2, 2).unwrap();
    let second = owner.create_dc(2, 2).unwrap();
    let brush = owner.create_solid_brush(0x123456).unwrap();
    let white = owner.stock_object(0).unwrap().handle;
    owner.select_brush(first, brush).unwrap(); owner.select_brush(second, brush).unwrap();
    let old_snapshot = owner.live_handles();
    owner.delete_object(brush).unwrap();
    assert!(owner.contains_object(brush));
    assert_eq!(owner.live_handles().iter().filter(|id| **id == brush).count(), 1);
    assert_eq!(owner.select_brush(first, white), Ok(brush));
    assert!(owner.contains_object(brush) && owner.live_handles().contains(&brush));
    assert_eq!(owner.select_brush(second, white), Ok(brush));
    assert!(!owner.contains_object(brush));
    assert!(!owner.live_handles().contains(&brush));
    assert!(old_snapshot.contains(&brush));
    assert!(owner.contains_object(white));
}

#[test]
fn destroying_final_selecting_window_dc_collects_only_its_deleted_brush() {
    let mut owner = GdiManager::new();
    let window = owner.acquire_window_dc(10, 2, 2).unwrap();
    let memory = owner.create_dc(2, 2).unwrap();
    let brush = owner.create_solid_brush(0x123456).unwrap();
    let survivor = owner.create_solid_brush(0x654321).unwrap();
    owner.select_brush(window, brush).unwrap(); owner.select_brush(memory, brush).unwrap();
    owner.delete_object(brush).unwrap(); owner.delete_object(memory).unwrap();
    assert!(owner.contains_object(brush));
    assert!(!owner.contains_object(memory));
    owner.destroy_window_dc(10).unwrap();
    assert_eq!(owner.window_dc(10), None);
    let live = owner.live_handles();
    for handle in [brush, window, memory] {
        assert!(!owner.contains_object(handle)); assert!(!live.contains(&handle));
    }
    assert!(owner.contains_object(survivor) && live.contains(&survivor));
}

#[test]
fn window_lookup_does_not_allocate_resize_or_mutate_surface_and_selection() {
    let mut owner = GdiManager::new();
    let initial = owner.live_handles();
    for _ in 0..20 { assert_eq!(owner.window_dc(99), None); }
    assert_eq!(owner.live_handles(), initial);
    let dc = owner.acquire_window_dc(10, 3, 2).unwrap();
    assert_eq!(dc & SLOT_MASK, FIRST_DYNAMIC_SLOT);
    let font = owner.create_font(font()).unwrap(); owner.select_font(dc, font).unwrap();
    owner.fill_rect(dc, Rect { left: 0, top: 0, right: 3, bottom: 2 }, 0x123456).unwrap();
    let before = owner.text_state(dc).unwrap();
    let pixels = owner.pixels(dc).unwrap().to_vec();
    let live = owner.live_handles();
    for _ in 0..20 {
        assert_eq!(owner.window_dc(10), Some(dc)); assert_eq!(owner.window_dc(99), None);
    }
    assert_eq!(owner.text_state(dc).unwrap(), before);
    assert_eq!(owner.pixels(dc).unwrap(), pixels.as_slice());
    assert_eq!(owner.live_handles(), live);
    assert_eq!(owner.create_dc(1, 1).unwrap() & SLOT_MASK, FIRST_DYNAMIC_SLOT + 2);
    assert_eq!(owner.acquire_window_dc(10, 4, 3), Ok(dc));
    assert_eq!(owner.window_dc(10), Some(dc));
    assert_eq!((owner.text_state(dc).unwrap().width, owner.text_state(dc).unwrap().height), (4, 3));
}

#[test]
fn forged_stock_and_dynamic_types_never_enter_projection() {
    let mut owner = GdiManager::new();
    let dc = owner.create_dc(1, 1).unwrap();
    let before = owner.live_handles();
    for handle in [0, 45, TYPE_FONT | 45, 0x0081002d, DEFAULT_DC_FONT_HANDLE | 0x01000000,
        0x008a0034, (dc & SLOT_MASK) | TYPE_FONT, dc | 0x00800000] {
        assert!(!owner.contains_object(handle));
        assert!(!owner.live_handles().contains(&handle));
        assert_eq!(owner.delete_object(handle), Err(GdiError::NoSuchObject));
    }
    assert_eq!(owner.live_handles(), before);
    owner.delete_object(DEFAULT_DC_FONT_HANDLE).unwrap();
    assert!(owner.contains_object(DEFAULT_DC_FONT_HANDLE));
    assert_eq!(owner.live_handles(), before);
}
