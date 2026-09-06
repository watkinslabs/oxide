use super::*;
#[test]
fn noredraw_clean_resize_stays_clean_but_advances_generation(){
    let mut pending=PendingOutput::default();pending.resized_with_redraw(8,8,false);
    assert_eq!(pending.damage,None);assert_eq!(pending.generation,1);
    pending.resized_with_redraw(4,4,true);assert_eq!(pending.damage,Some(Rect{left:0,top:0,right:4,bottom:4}));
}
#[test]
fn noredraw_keeps_prior_dirty_intersection_without_expanding_on_growth(){
    let mut pending=PendingOutput::default();pending.record(Some(Rect{left:2,top:2,right:6,bottom:6}));
    pending.resized_with_redraw(10,10,false);assert_eq!(pending.damage,Some(Rect{left:2,top:2,right:6,bottom:6}));
    pending.resized_with_redraw(4,5,false);assert_eq!(pending.damage,Some(Rect{left:2,top:2,right:4,bottom:5}));
    pending.resized_with_redraw(1,1,false);assert_eq!(pending.damage,None);
    pending.resized_with_redraw(10,10,false);assert_eq!(pending.damage,None);
}
#[test]
fn noredraw_keeps_inflight_reservation_and_invalidates_old_ack(){
    let mut g=GdiManager::new();let dc=g.acquire_window_dc(7,4,4).unwrap();
    g.write_dc_pixel(dc,0,0,1).unwrap();let token=g.pending_output(7,dc).unwrap();assert!(g.reserve_output(token));
    let state=&mut g.dcs.iter_mut().find(|(id,_)|*id==dc).unwrap().1;
    state.pending_output.resized_with_redraw(4,4,false);
    assert_eq!(state.pending_output.in_flight,Some(token));
    assert!(!g.finish_output(token,true));let next=g.pending_output(7,dc).unwrap();
    assert_eq!(next.damage,token.damage);assert_eq!(next.generation,token.generation+1);
    assert!(g.reserve_output(next));assert!(g.finish_output(next,true));
}
#[test]
fn noredraw_zero_extent_discards_undrawable_coverage_only(){
    let mut pending=PendingOutput::default();pending.record(Some(Rect{left:0,top:0,right:4,bottom:4}));
    pending.resized_with_redraw(0,4,false);assert_eq!(pending.damage,None);assert_eq!(pending.generation,2);
}
