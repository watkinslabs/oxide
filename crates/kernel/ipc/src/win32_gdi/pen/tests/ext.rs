use super::*;
use crate::win32_gdi::GdiManager;

const GEOMETRIC_SOLID: u32 = PS_GEOMETRIC;
const COSMETIC_SOLID: u32 = 0;

#[test]
fn the_null_line_style_resolves_to_the_stock_pen_whatever_else_is_asked() {
    assert_eq!(admit_ext_pen(PS_GEOMETRIC | PS_NULL, 7, 9, 0x123456, &[]), Ok(ExtPenRequest::Null));
    assert_eq!(admit_ext_pen(PS_NULL, 0, BS_SOLID, 0, &[]), Ok(ExtPenRequest::Null));
}

#[test]
fn a_geometric_pen_with_a_null_brush_is_the_stock_null_pen() {
    assert_eq!(admit_ext_pen(GEOMETRIC_SOLID, 5, BS_NULL, 0x00ff00, &[]), Ok(ExtPenRequest::Null));
    // A cosmetic pen has no such shortcut: it must be solid-brushed.
    assert_eq!(admit_ext_pen(COSMETIC_SOLID, 1, BS_NULL, 0, &[]), Err(GdiError::InvalidDimensions));
}

#[test]
fn a_cosmetic_pen_must_be_one_unit_wide_and_solid_brushed() {
    assert_eq!(admit_ext_pen(COSMETIC_SOLID, 1, BS_SOLID, 0x0000ff, &[]),
        Ok(ExtPenRequest::Create { style: 0, width: 1, color: 0x0000ff }));
    assert_eq!(admit_ext_pen(COSMETIC_SOLID, 2, BS_SOLID, 0, &[]), Err(GdiError::InvalidDimensions));
    assert_eq!(admit_ext_pen(COSMETIC_SOLID, 1, 2, 0, &[]), Err(GdiError::InvalidDimensions));
}

#[test]
fn style_entries_belong_only_to_the_user_line_style() {
    assert_eq!(admit_ext_pen(COSMETIC_SOLID, 1, BS_SOLID, 0, &[4, 4]), Err(GdiError::InvalidDimensions));
    assert_eq!(admit_ext_pen(PS_USERSTYLE, 1, BS_SOLID, 0, &[4, 4]),
        Ok(ExtPenRequest::Create { style: PS_USERSTYLE, width: 1, color: 0 }));
    assert_eq!(admit_ext_pen(PS_USERSTYLE, 1, BS_SOLID, 0, &[]), Err(GdiError::InvalidDimensions));
}

#[test]
fn a_user_style_carries_at_most_sixteen_entries() {
    let sixteen = [1u32; MAX_STYLE_ENTRIES];
    assert!(admit_ext_pen(PS_USERSTYLE, 1, BS_SOLID, 0, &sixteen).is_ok());
    let seventeen = [1u32; MAX_STYLE_ENTRIES + 1];
    assert_eq!(admit_ext_pen(PS_USERSTYLE, 1, BS_SOLID, 0, &seventeen), Err(GdiError::InvalidDimensions));
}

#[test]
fn a_geometric_user_style_refuses_a_negative_or_wholly_zero_pattern() {
    let style = PS_GEOMETRIC | PS_USERSTYLE;
    assert_eq!(admit_ext_pen(style, 3, BS_SOLID, 0, &[0, 0]), Err(GdiError::InvalidDimensions));
    assert_eq!(admit_ext_pen(style, 3, BS_SOLID, 0, &[4, (-1i32) as u32]), Err(GdiError::InvalidDimensions));
    assert!(admit_ext_pen(style, 3, BS_SOLID, 0, &[4, 0]).is_ok());
    // A cosmetic user style accepts what a geometric one refuses.
    assert!(admit_ext_pen(PS_USERSTYLE, 1, BS_SOLID, 0, &[0, 0]).is_ok());
}

#[test]
fn the_two_restricted_line_styles_match_only_their_own_pen_type() {
    assert!(admit_ext_pen(PS_GEOMETRIC | PS_INSIDEFRAME, 3, BS_SOLID, 0, &[]).is_ok());
    assert_eq!(admit_ext_pen(PS_INSIDEFRAME, 1, BS_SOLID, 0, &[]), Err(GdiError::InvalidDimensions));
    assert!(admit_ext_pen(PS_ALTERNATE, 1, BS_SOLID, 0, &[]).is_ok());
    assert_eq!(admit_ext_pen(PS_GEOMETRIC | PS_ALTERNATE, 3, BS_SOLID, 0, &[]), Err(GdiError::InvalidDimensions));
}

#[test]
fn an_unknown_line_style_is_refused() {
    assert_eq!(admit_ext_pen(9, 1, BS_SOLID, 0, &[]), Err(GdiError::InvalidDimensions));
    assert_eq!(admit_ext_pen(0x0f, 1, BS_SOLID, 0, &[]), Err(GdiError::InvalidDimensions));
}

#[test]
fn the_created_pen_carries_the_dashes_its_style_implies() {
    let mut gdi = GdiManager::new();
    let alternate = gdi.create_ext_pen(PS_ALTERNATE, 1, BS_SOLID, 0x00ff00, &[]).unwrap();
    let pen = gdi.pen_description(alternate, 0).unwrap();
    assert_eq!(pen.pattern.count, 2);
    assert!(pen.pattern.covers(0));
    assert!(!pen.pattern.covers(1));
    // A cosmetic user style is measured in three-unit steps.
    let user = gdi.create_ext_pen(PS_USERSTYLE, 1, BS_SOLID, 0x00ff00, &[2, 1]).unwrap();
    let pen = gdi.pen_description(user, 0).unwrap();
    assert_eq!(&pen.pattern.entries[..2], &[6, 3]);
    assert!(pen.pattern.covers(5));
    assert!(!pen.pattern.covers(6));
}

#[test]
fn an_odd_entry_count_runs_the_pattern_twice_with_the_roles_swapped() {
    let pattern = crate::win32_gdi::DashPattern::new(&[2, 3, 4], 1);
    assert_eq!(pattern.cycle(), 18);
    assert!(pattern.covers(0) && pattern.covers(1));
    assert!(!pattern.covers(2));
    assert!(pattern.covers(5));
    // The second pass inverts: what was drawn is now skipped.
    assert!(!pattern.covers(9));
    assert!(pattern.covers(11));
}

#[test]
fn a_null_request_and_a_created_pen_reach_the_object_owner() {
    let mut gdi = GdiManager::new();
    let stock = gdi.create_ext_pen(PS_GEOMETRIC | PS_NULL, 4, BS_SOLID, 0, &[]).unwrap();
    assert_eq!(gdi.pen_description(stock, 0).unwrap().style, PS_NULL);
    assert_eq!(gdi.create_ext_pen(COSMETIC_SOLID, 4, BS_SOLID, 0, &[]), Err(GdiError::InvalidDimensions));
}
