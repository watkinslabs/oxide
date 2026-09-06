use super::*;
use crate::win32_gdi::Font;

#[test]
fn object_types_are_encoded_in_the_canonical_handle() {
    let mut state = GdiManager::new();
    let dc = state.create_dc(2, 2).unwrap();
    let font = state.create_font(Font { height: 16, width: 0, weight: 400, italic: false }).unwrap();
    assert_eq!(dc, TYPE_DC | FIRST_DYNAMIC_SLOT);
    assert_eq!(font, TYPE_FONT | (FIRST_DYNAMIC_SLOT + 1));
    assert_eq!(dc & 0x1f0000, TYPE_DC);
    assert_eq!(state.select_font(dc, font), Ok(crate::win32_gdi::DEFAULT_DC_FONT_HANDLE));
    state.delete_object(dc).unwrap();
    let next = state.create_dc(2, 2).unwrap();
    assert_ne!(next, dc);
    assert_ne!(next & SLOT_MASK, font & SLOT_MASK);
}

#[test]
fn handle_exhaustion_never_wraps_into_stock_or_existing_slots() {
    let mut state = GdiManager::new();
    state.next = SLOT_LIMIT - 1;
    let dc = state.create_dc(1, 1).unwrap();
    assert_eq!(dc & SLOT_MASK, SLOT_LIMIT - 1);
    assert_eq!(state.create_dc(1, 1), Err(GdiError::HandleLimit));
    assert_eq!(state.create_font(Font { height: 16, width: 0, weight: 400, italic: false }), Err(GdiError::HandleLimit));
    assert_eq!(state.pixels(dc).unwrap(), &[0]);
}
