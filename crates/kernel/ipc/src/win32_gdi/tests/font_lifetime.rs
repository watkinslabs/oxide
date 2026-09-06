use crate::win32_gdi::*;

fn logical() -> Font { Font { height: -20, width: 0, weight: 700, italic: true } }
fn assert_live(owner: &GdiManager, handle: u32) {
    assert!(owner.contains_object(handle));
    assert_eq!(owner.live_handles().iter().filter(|id| **id == handle).count(), 1);
}
fn assert_gone(owner: &GdiManager, handle: u32) {
    assert!(!owner.contains_object(handle)); assert!(!owner.live_handles().contains(&handle));
}

#[test]
fn two_selected_dcs_preserve_deleted_font_until_final_deselection() {
    let mut owner = GdiManager::new();
    let first = owner.create_dc(2, 2).unwrap();
    let second = owner.create_dc(2, 2).unwrap();
    let font = owner.create_font(logical()).unwrap();
    owner.select_font(first, font).unwrap(); owner.select_font(second, font).unwrap();
    owner.delete_object(font).unwrap();
    assert_live(&owner, font);
    for dc in [first, second] { assert_eq!(owner.text_state(dc).unwrap().font, Some(logical())); }
    assert_eq!(owner.select_font(first, DEFAULT_DC_FONT_HANDLE), Ok(font));
    assert_live(&owner, font);
    assert_eq!(owner.text_state(second).unwrap().font, Some(logical()));
    assert_eq!(owner.select_font(second, DEFAULT_DC_FONT_HANDLE), Ok(font));
    assert_gone(&owner, font);
    assert_eq!(owner.select_font(first, font), Err(GdiError::NoSuchObject));
}

#[test]
fn pending_font_reselection_never_transiently_drops_its_final_reference() {
    let mut owner = GdiManager::new();
    let first = owner.create_dc(2, 2).unwrap();
    let second = owner.create_dc(2, 2).unwrap();
    let font = owner.create_font(logical()).unwrap();
    owner.select_font(first, font).unwrap(); owner.delete_object(font).unwrap();
    assert_eq!(owner.select_font(first, font), Ok(font));
    assert_live(&owner, font);
    assert_eq!(owner.select_font(second, font), Ok(DEFAULT_DC_FONT_HANDLE));
    owner.select_font(first, DEFAULT_DC_FONT_HANDLE).unwrap();
    assert_live(&owner, font);
    owner.delete_object(font).unwrap();
    assert_eq!(owner.text_state(second).unwrap().font, Some(logical()));
    owner.select_font(second, DEFAULT_DC_FONT_HANDLE).unwrap();
    assert_gone(&owner, font);
}

#[test]
fn final_dc_destruction_collects_pending_font_but_keeps_unselected_live_fonts() {
    let mut owner = GdiManager::new();
    let window = owner.acquire_window_dc(42, 2, 2).unwrap();
    let memory = owner.create_dc(2, 2).unwrap();
    let font = owner.create_font(logical()).unwrap();
    let survivor = owner.create_font(logical()).unwrap();
    owner.select_font(window, font).unwrap(); owner.select_font(memory, font).unwrap();
    owner.delete_object(font).unwrap(); owner.delete_object(memory).unwrap();
    assert_live(&owner, font); assert_gone(&owner, memory);
    owner.destroy_window_dc(42).unwrap();
    assert_gone(&owner, font); assert_gone(&owner, window);
    assert_eq!(owner.window_dc(42), None);
    assert_live(&owner, survivor); assert_live(&owner, DEFAULT_DC_FONT_HANDLE);
}

#[test]
fn unselected_font_deletes_immediately_while_stock_deletion_is_immutable() {
    let mut owner = GdiManager::new();
    let dc = owner.create_dc(2, 2).unwrap();
    let font = owner.create_font(logical()).unwrap();
    owner.delete_object(font).unwrap(); assert_gone(&owner, font);
    assert_eq!(owner.delete_object(font), Err(GdiError::NoSuchObject));
    let before = owner.text_state(dc).unwrap();
    owner.delete_object(DEFAULT_DC_FONT_HANDLE).unwrap();
    assert_live(&owner, DEFAULT_DC_FONT_HANDLE);
    assert_eq!(owner.text_state(dc).unwrap(), before);
    let replacement = owner.create_font(logical()).unwrap();
    assert_ne!(replacement, font);
}

#[test]
fn failed_selection_preserves_pending_font_and_live_projection() {
    let mut owner = GdiManager::new();
    let dc = owner.create_dc(2, 2).unwrap();
    let font = owner.create_font(logical()).unwrap();
    let brush = owner.create_solid_brush(0x123456).unwrap();
    owner.select_font(dc, font).unwrap(); owner.delete_object(font).unwrap();
    let before = owner.live_handles();
    assert_eq!(owner.select_font(dc, brush), Err(GdiError::NoSuchObject));
    assert_eq!(owner.select_font(0, DEFAULT_DC_FONT_HANDLE), Err(GdiError::NoSuchObject));
    assert_eq!(owner.live_handles(), before);
    assert_eq!(owner.text_state(dc).unwrap().font, Some(logical()));
    assert_live(&owner, font);
}

#[test]
fn all_logfont_bytes_and_derived_metrics_survive_pending_deletion() {
    let mut owner = GdiManager::new();
    let dc = owner.create_dc(2, 2).unwrap();
    let mut bytes = [0u8; 92];
    for (index, byte) in bytes.iter_mut().enumerate() { *byte = index as u8; }
    bytes[..4].copy_from_slice(&(-20i32).to_le_bytes());
    bytes[4..8].copy_from_slice(&0i32.to_le_bytes());
    bytes[16..20].copy_from_slice(&700i32.to_le_bytes()); bytes[20] = 1;
    let font = owner.create_font_record(FontRecord::from_bytes(bytes).unwrap()).unwrap();
    assert_eq!(owner.font_record(font).unwrap().bytes(), bytes);
    owner.select_font(dc, font).unwrap(); owner.delete_object(font).unwrap();
    assert_live(&owner, font);
    let retained = owner.font_record(font).unwrap();
    assert_eq!(retained.bytes(), bytes);
    assert_eq!(retained.metrics(), logical());
    assert_eq!(owner.text_state(dc).unwrap().font, Some(retained.metrics()));
    owner.delete_object(dc).unwrap();
    assert_gone(&owner, font);
    assert_eq!(owner.font_record(font), Err(GdiError::NoSuchObject));
}

#[test]
fn stock_font_query_is_immutable_and_wrong_object_types_fail() {
    let mut owner = GdiManager::new();
    let dc = owner.create_dc(2, 2).unwrap();
    let brush = owner.create_solid_brush(0).unwrap();
    let record = owner.font_record(DEFAULT_DC_FONT_HANDLE).unwrap();
    assert_eq!(record.metrics(), Font { height: 16, width: 7, weight: 700, italic: false });
    assert_eq!(record.bytes().len(), 92);
    owner.delete_object(DEFAULT_DC_FONT_HANDLE).unwrap();
    assert_eq!(owner.font_record(DEFAULT_DC_FONT_HANDLE).unwrap(), record);
    for handle in [dc, brush, 0x0081002d, DEFAULT_DC_FONT_HANDLE | 0x01000000] {
        assert_eq!(owner.font_record(handle), Err(GdiError::NoSuchObject));
    }
}
