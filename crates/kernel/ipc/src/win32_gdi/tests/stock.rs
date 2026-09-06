use super::*;

#[test]
fn stock_font_logical_values_match_ansi_default_objects() {
    let owner = GdiManager::new();
    for (index, height, width, weight, face, charset, pitch) in [
        (10, 12, 0, 400, "", 255, 0x31), (11, 12, 0, 400, "Courier", 0, 0x31),
        (12, 12, 0, 400, "MS Sans Serif", 0, 0x22), (13, 16, 7, 700, "System", 0, 0x22),
        (14, 16, 0, 700, "System", 0, 0x22), (16, 16, 0, 400, "Courier", 0, 0x31),
        (17, -11, 0, 400, "MS Shell Dlg", 0, 0x22),
    ] {
        let object = owner.stock_object(index).unwrap();
        assert_eq!(object.handle, 0x008a_0000 | (32 + index));
        let StockDescription::Font(font) = object.description else { unreachable!() };
        assert_eq!(font.logical, Font { height, width, weight, italic: false });
        assert_eq!((font.face, font.charset, font.pitch_and_family), (face, charset, pitch));
        assert_eq!(owner.stock_font(object.handle), Some(font.logical));
    }
    assert_eq!(DEFAULT_DC_FONT_HANDLE, 0x008a_002d);
}

#[test]
fn brush_and_pen_stock_descriptions_preserve_null_and_dc_color_semantics() {
    for (index, color) in [(0, 0xffffff), (1, 0xc0c0c0), (2, 0x808080), (3, 0x404040), (4, 0), (5, 0), (18, 0xffffff)] {
        let object = stock_object(index).unwrap();
        assert_eq!(object.handle, 0x0090_0000 | (32 + index));
        assert_eq!(object.description, StockDescription::Brush(StockBrush {
            style: if index == 5 { StockStyle::Null } else { StockStyle::Solid }, color, dc_color: index == 18,
        }));
    }
    for index in [6, 7, 8, 19] {
        let object = stock_object(index).unwrap();
        assert_eq!(object.handle, 0x00b0_0000 | (32 + index));
        assert_eq!(object.description, StockDescription::Pen(StockPen {
            style: if index == 8 { StockStyle::Null } else { StockStyle::Solid },
            width: 0, color: if index == 6 { 0xffffff } else { 0 }, dc_color: index == 19,
        }));
    }
}

#[test]
fn unsupported_types_and_forged_stock_identities_are_not_objects() {
    let owner = GdiManager::new();
    for index in [9, 15, 20, 21, 22, 23, 24, u32::MAX] { assert!(stock_object(index).is_none()); }
    for handle in [0, 45, TYPE_FONT | 45, STOCK_BIT | super::super::TYPE_DC | 45,
        DEFAULT_DC_FONT_HANDLE | 0x0100_0000, STOCK_BIT | TYPE_FONT | 64] {
        assert!(stock_by_handle(handle).is_none());
        assert!(owner.stock_font(handle).is_none());
    }
    for index in 0..20 {
        if let Some(object) = stock_object(index) { assert_eq!(stock_by_handle(object.handle), Some(object)); }
    }
}

#[test]
fn stock_queries_do_not_consume_dynamic_slots_or_create_mutable_fonts() {
    let mut owner = GdiManager::new();
    let before = (owner.next, owner.fonts.len(), owner.brushes.len(), owner.dcs.len(), owner.window_dcs.len());
    for _ in 0..100 { for index in 0..24 { let _ = owner.stock_object(index); } }
    assert_eq!((owner.next, owner.fonts.len(), owner.brushes.len(), owner.dcs.len(), owner.window_dcs.len()), before);
    assert_eq!(owner.create_dc(1, 1).unwrap() & super::super::SLOT_MASK, super::super::FIRST_DYNAMIC_SLOT);
}

#[test]
fn default_dc_selects_system_font_and_stock_deletion_preserves_selection() {
    let mut owner = GdiManager::new();
    let dc = owner.create_dc(8, 8).unwrap();
    assert_eq!(owner.text_state(dc).unwrap().font, Some(Font { height: 16, width: 7, weight: 700, italic: false }));
    let ansi = stock_object(11).unwrap();
    assert_eq!(owner.select_font(dc, ansi.handle), Ok(DEFAULT_DC_FONT_HANDLE));
    assert_eq!(owner.delete_object(ansi.handle), Ok(()));
    assert_eq!(owner.text_state(dc).unwrap().font, owner.stock_font(ansi.handle));
    assert_eq!(owner.select_font(dc, DEFAULT_DC_FONT_HANDLE), Ok(ansi.handle));
    assert_eq!(owner.delete_object(DEFAULT_DC_FONT_HANDLE), Ok(()));
    assert_eq!(owner.text_state(dc).unwrap().font, owner.stock_font(DEFAULT_DC_FONT_HANDLE));
}

#[test]
fn delete_stock_is_successful_and_immutable_but_forged_stock_is_not() {
    let mut owner = GdiManager::new();
    let before = (owner.next, owner.fonts.len(), owner.brushes.len(), owner.dcs.len(), owner.window_dcs.len());
    for index in 0..20 {
        if let Some(stock) = stock_object(index) {
            assert_eq!(owner.delete_object(stock.handle), Ok(()));
            assert_eq!(owner.stock_object(index), Some(stock));
        }
    }
    assert_eq!(owner.delete_object(DEFAULT_DC_FONT_HANDLE ^ TYPE_FONT), Err(super::super::GdiError::NoSuchObject));
    assert_eq!((owner.next, owner.fonts.len(), owner.brushes.len(), owner.dcs.len(), owner.window_dcs.len()), before);
}

#[test]
fn selecting_nonfont_stock_never_changes_the_default_font() {
    let mut owner = GdiManager::new();
    let dc = owner.create_dc(8, 8).unwrap();
    let before = owner.text_state(dc).unwrap();
    for index in [0, 1, 2, 3, 4, 5, 6, 7, 8, 18, 19] {
        let object = stock_object(index).unwrap();
        assert_eq!(owner.stock_font(object.handle), None);
        assert_eq!(owner.select_font(dc, object.handle), Err(super::super::GdiError::NoSuchObject));
        assert_eq!(owner.text_state(dc).unwrap(), before);
    }
}
