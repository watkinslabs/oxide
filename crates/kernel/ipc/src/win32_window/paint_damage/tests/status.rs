//! Paint wake state and acknowledged arrivals have independent lifetimes.
use super::*;
use super::super::{WindowManager,WindowId,MessageFilter,WindowPosition};
use super::super::queue_status::{QS_PAINT,QS_KEY};
fn rect(l:i32,t:i32,r:i32,b:i32)->WindowRect{WindowRect{left:l,top:t,right:r,bottom:b}}
fn window(state:&mut WindowManager,tid:u64)->WindowId{
    let id=state.create(tid,None,0).unwrap();state.set_visible(id,true).unwrap();state.set_rect(id,rect(0,0,10,10)).unwrap();id
}
fn status(state:&mut WindowManager,tid:u64)->u32{state.queue_status(tid,QS_PAINT).unwrap()}
fn all()->MessageFilter{MessageFilter{hwnd:None,first:0,last:0}}
#[test]
fn query_acknowledges_paint_without_consuming_or_rearming_existing_damage(){
    let mut state=WindowManager::new();let id=window(&mut state,7);state.invalidate(id,Some(rect(0,0,3,3))).unwrap();
    assert_eq!(state.queue_status(7,QS_KEY),Some(0));assert_eq!(status(&mut state,7),0x00200020);
    assert_eq!(status(&mut state,7),0x00200000);state.invalidate(id,Some(rect(4,4,6,6))).unwrap();
    assert_eq!(status(&mut state,7),0x00200000);assert!(state.pending_paint_message(7).is_some());
}
#[test]
fn new_obligations_and_removal_with_remaining_work_rearm_changes_per_thread(){
    let mut state=WindowManager::new();let a=window(&mut state,7);let b=window(&mut state,7);let c=window(&mut state,8);
    state.invalidate(a,None).unwrap();assert_eq!(status(&mut state,7),0x00200020);
    state.invalidate(b,None).unwrap();state.invalidate(c,None).unwrap();assert_eq!(status(&mut state,7),0x00200020);
    state.begin_paint(a).unwrap();assert_eq!(status(&mut state,7),0x00200020);assert_eq!(status(&mut state,7),0x00200000);
    state.begin_paint(b).unwrap();assert_eq!(status(&mut state,7),0);assert_eq!(status(&mut state,8),0x00200020);
}
#[test]
fn beginning_last_paint_clears_unreported_changes(){
    let mut state=WindowManager::new();let id=window(&mut state,7);state.invalidate(id,None).unwrap();
    state.begin_paint(id).unwrap();assert_eq!(status(&mut state,7),0);
}
#[test]
fn internal_and_region_obligations_are_independent_and_internal_removal_rearms_remaining_region(){
    let mut state=WindowManager::new();let id=window(&mut state,7);state.invalidate(id,None).unwrap();status(&mut state,7);
    state.redraw_damage(id,None,RDW_INTERNALPAINT,false).unwrap();assert_eq!(status(&mut state,7),0x00200020);
    state.redraw_damage(id,None,RDW_INTERNALPAINT,false).unwrap();assert_eq!(status(&mut state,7),0x00200000);
    state.take_pending_paint(7,all(),true).unwrap();assert_eq!(status(&mut state,7),0x00200020);
    state.redraw_damage(id,None,RDW_VALIDATE|RDW_NOFRAME,false).unwrap();assert_eq!(status(&mut state,7),0);
    state.redraw_damage(id,None,RDW_INTERNALPAINT,false).unwrap();state.take_pending_paint(7,all(),true).unwrap();assert_eq!(status(&mut state,7),0);
}
#[test]
fn nonclient_only_erase_updates_paint_status_on_region_removal(){
    for other in [false,true]{
        let mut state=WindowManager::new();let id=window(&mut state,7);state.set_client_rect(id,rect(2,2,8,8)).unwrap();
        if other{let b=window(&mut state,7);state.invalidate(b,None).unwrap();}
        let border=PaintRegion::from_rect(rect(-2,-2,8,0)).unwrap();
        state.redraw_damage(id,Some(&border),RDW_INVALIDATE|RDW_FRAME|RDW_ERASE,false).unwrap();
        if other{status(&mut state,7);}state.take_erase_damage(id).unwrap();
        assert_eq!(status(&mut state,7),if other{0x00200020}else{0});
    }
}
#[test]
fn child_begin_paint_clears_parent_obligation_when_parent_region_is_fully_validated(){
    let mut state=WindowManager::new();let parent=window(&mut state,7);let child=state.create(7,Some(parent),0).unwrap();
    state.set_visible(child,true).unwrap();state.set_rect(child,rect(0,0,10,10)).unwrap();
    state.invalidate(parent,None).unwrap();state.invalidate(child,None).unwrap();state.begin_paint(child).unwrap();
    assert_eq!(status(&mut state,7),0);
}
#[test]
fn destruction_rearms_remaining_paint_and_clears_last_unreported_paint(){
    let mut state=WindowManager::new();let a=window(&mut state,7);let b=window(&mut state,7);
    state.invalidate(a,None).unwrap();state.invalidate(b,None).unwrap();status(&mut state,7);
    state.destroy(a).unwrap();assert_eq!(status(&mut state,7),0x00200020);
    state.invalidate(a,None).unwrap_err();state.destroy(b).unwrap();assert_eq!(status(&mut state,7),0);
}
#[test]
fn position_damage_arrival_is_changed_but_expansion_of_existing_region_is_not(){
    let mut state=WindowManager::new();let id=window(&mut state,7);
    for size in [20,30]{
        state.apply_position(7,WindowPosition{window:id,rect:rect(0,0,size,size),client:None,order:None,visible:None,flags:0x10,notify_geometry:false}).unwrap();
        assert_eq!(status(&mut state,7),if size==20{0x00200020}else{0x00200000});
    }
}
#[test]
fn validation_rearms_other_pending_paint_then_clears_a_drained_class(){
    let mut state=WindowManager::new();let a=window(&mut state,7);let b=window(&mut state,7);
    state.invalidate(a,None).unwrap();state.invalidate(b,None).unwrap();status(&mut state,7);
    state.redraw_damage(a,None,RDW_VALIDATE|RDW_NOFRAME,false).unwrap();assert_eq!(status(&mut state,7),0x00200020);
    state.redraw_damage(b,None,RDW_VALIDATE|RDW_NOFRAME,false).unwrap();assert_eq!(status(&mut state,7),0);
}
