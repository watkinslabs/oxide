use super::*;
#[test]
fn classic_pen_metadata_null_stock_and_typed_identity_are_canonical() {
    let mut g=GdiManager::new();let dc=g.create_dc(3,3).unwrap();
    assert_eq!(g.select_pen(dc,DEFAULT_DC_PEN_HANDLE),Ok(DEFAULT_DC_PEN_HANDLE));
    for style in [0,1,2,3,4,6] {
        let h=g.create_pen(style,-3,0x123456).unwrap();
        assert_eq!(h&!0xffff,TYPE_PEN);assert!(g.contains_object(h));
        let p=g.pen_description(h,0).unwrap();assert_eq!((p.style,p.width,p.color),(style as u32,3,0x123456));
    }
    let null=g.create_pen(5,i32::MIN,u32::MAX).unwrap();assert_eq!(null,stock_object(8).unwrap().handle);
    assert_eq!(g.pen_description(null,0).unwrap().style,PS_NULL);
    for style in [-1,7,8,0x10000] {assert!(g.create_pen(style,1,0).is_err());}
    assert!(g.create_pen(0,i32::MIN,0).is_err());
    assert!(g.create_pen(0,1,0xff000000).is_err());
}
#[test]
fn selected_deleted_pen_lives_until_both_dc_references_are_released() {
    let mut g=GdiManager::new();let a=g.create_dc(2,2).unwrap();let b=g.create_dc(2,2).unwrap();
    let p=g.create_pen(0,1,0xabcdef).unwrap();
    g.select_pen(a,p).unwrap();g.select_pen(b,p).unwrap();g.delete_object(p).unwrap();
    assert!(g.live_handles().contains(&p));assert_eq!(g.selected_pen(a).unwrap().color,0xabcdef);
    assert_eq!(g.select_pen(a,DEFAULT_DC_PEN_HANDLE),Ok(p));assert!(g.contains_object(p));
    g.delete_object(b).unwrap();assert!(!g.contains_object(p));assert!(!g.live_handles().contains(&p));
    assert!(g.select_pen(a,p).is_err());assert_eq!(g.selected_pen(a).unwrap().color,0);
}
#[test]
fn forged_nonpen_selection_preserves_selection_and_dc_pen_color_is_not_stock_mutation() {
    let mut g=GdiManager::new();let dc=g.create_dc(2,2).unwrap();let brush=g.create_solid_brush(1).unwrap();
    assert!(g.select_pen(dc,brush).is_err());assert!(g.select_pen(dc,dc).is_err());
    assert_eq!(g.select_pen(dc,stock_object(19).unwrap().handle),Ok(DEFAULT_DC_PEN_HANDLE));
    g.dcs.iter_mut().find(|(id,_)|*id==dc).unwrap().1.dc_pen_color=0x123456;
    assert_eq!(g.selected_pen(dc).unwrap().color,0x123456);
    assert_eq!(g.pen_description(stock_object(19).unwrap().handle,0).unwrap().color,0);
    g.delete_object(stock_object(19).unwrap().handle).unwrap();
    assert_eq!(g.selected_pen(dc).unwrap().color,0x123456);
}
