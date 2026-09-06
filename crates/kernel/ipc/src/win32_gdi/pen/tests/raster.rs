use super::*;
use crate::win32_gdi::{DcLeaseRequest,LeaseOwner,DCX_CACHE,TYPE_PEN};
use crate::win32_window::{PaintRegion,WindowRect};

#[test]
fn line_commits_position_only_on_success_and_rop_truth_tables_are_exact(){
    let mut g=GdiManager::new();let dc=g.create_dc(5,4).unwrap();
    let pen=g.create_pen(0,1,0x123456).unwrap();g.select_pen(dc,pen).unwrap();
    assert_eq!(g.selected_object(dc,TYPE_PEN),Some(pen));
    g.pen_line_to(dc,(4,0),None).unwrap();assert_eq!(&g.pixels(dc).unwrap()[..5],&[0x123456,0x123456,0x123456,0x123456,0]);
    assert_eq!(g.text_state(dc).unwrap().attributes.current_position,(4,0));
    let wide=g.create_pen(0,3,0).unwrap();g.select_pen(dc,wide).unwrap();
    let before=g.pixels(dc).unwrap().to_vec();assert!(g.pen_line_to(dc,(0,3),None).is_err());
    assert_eq!(g.pixels(dc).unwrap(),before);assert_eq!(g.text_state(dc).unwrap().attributes.current_position,(4,0));
    let p=0x123456;let d=0x654321;
    let expected=[0,!(p|d),!p&d,!p,p&!d,!d,p^d,!(p&d),p&d,!(p^d),d,!p|d,p,p|!d,p|d,RGB];
    for (index,value) in expected.into_iter().enumerate(){assert_eq!(rop2(index as u16+1,p,d),value&RGB);}
}
#[test]
fn rectangle_fills_interior_outlines_once_and_preserves_position(){
    let mut g=GdiManager::new();let dc=g.create_dc(6,6).unwrap();
    let pen=g.create_pen(0,1,0x123456).unwrap();g.select_pen(dc,pen).unwrap();
    g.set_text_position(dc,(5,5)).unwrap();let mut state=g.pen_raster_state(dc).unwrap();state.rop=7;
    g.pen_rectangle(dc,Rect{left:5,top:5,right:1,bottom:1},Some(state)).unwrap();
    for y in 0..6 {for x in 0..6 {let expected=if (1..5).contains(&x)&&(1..5).contains(&y){
        if x==1||x==4||y==1||y==4{0x123456}else{RGB}
    }else{0};assert_eq!(g.pixels(dc).unwrap()[y*6+x],expected,"{x},{y}");}}
    assert_eq!(g.text_state(dc).unwrap().attributes.current_position,(5,5));
}
#[test]
fn leased_lines_keep_negative_origin_exact_holes_and_inactive_rejection(){
    let mut g=GdiManager::new();let backing=g.acquire_window_dc(7,8,5).unwrap();
    let mut visible=PaintRegion::from_rect(WindowRect{left:-2,top:0,right:5,bottom:3}).unwrap();
    visible.subtract(&PaintRegion::from_rect(WindowRect{left:0,top:0,right:2,bottom:3}).unwrap()).unwrap();
    let dc=g.acquire_dc_lease(DcLeaseRequest{hwnd:7,backing_hwnd:7,backing,origin:(2,1),screen_origin:(0,0),
        width:5,height:3,visible,flags:DCX_CACHE,owner:LeaseOwner::Cached,clip_handle:0}).unwrap();
    let p=g.create_pen(0,1,0xabcdef).unwrap();g.select_pen(dc,p).unwrap();
    g.set_text_position(dc,(i32::MIN,1)).unwrap();g.pen_line_to(dc,(i32::MAX,1),None).unwrap();
    assert_eq!(&g.pixels(backing).unwrap()[16..24],&[0xabcdef,0xabcdef,0,0,0xabcdef,0xabcdef,0xabcdef,0]);
    g.release_dc_lease(dc).unwrap();assert!(g.select_pen(dc,p).is_err());assert_eq!(g.selected_object(dc,TYPE_PEN),None);
    assert!(g.pen_line_to(dc,(0,0),None).is_err());
}
#[test]
fn dashed_clipping_preserves_phase_and_transparent_gaps(){
    let mut g=GdiManager::new();let dc=g.create_dc(8,2).unwrap();
    let p=g.create_pen(2,1,0x112233).unwrap();g.select_pen(dc,p).unwrap();
    let mut state=g.pen_raster_state(dc).unwrap();state.position=(-4,0);state.opaque=false;
    g.pen_line_to(dc,(8,0),Some(state)).unwrap();
    assert_eq!(&g.pixels(dc).unwrap()[..8],&[0,0,0x112233,0x112233,0x112233,0,0,0]);
    assert_eq!(g.text_state(dc).unwrap().attributes.current_position,(0,0));
}
#[test]
fn compatible_null_pen_fill_and_degenerate_outline_use_integer_device_bounds(){
    let mut g=GdiManager::new();let dc=g.create_dc(5,5).unwrap();
    let null=g.create_pen(5,0,0).unwrap();g.select_pen(dc,null).unwrap();
    g.pen_rectangle(dc,Rect{left:0,top:0,right:4,bottom:4},None).unwrap();
    for y in 0..5{for x in 0..5{assert_eq!(g.pixels(dc).unwrap()[y*5+x],if x<4&&y<4{RGB}else{0});}}
    let small=g.create_dc(2,2).unwrap();
    let p=g.create_pen(0,1,RGB).unwrap();g.select_pen(small,p).unwrap();
    g.pen_rectangle(small,Rect{left:0,top:0,right:1,bottom:1},None).unwrap();
    assert!(g.pixels(small).unwrap().iter().all(|p|*p==0));
}
