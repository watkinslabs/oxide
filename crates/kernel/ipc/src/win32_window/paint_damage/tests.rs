use super::*;
use super::super::{WindowManager, WindowId};
fn rect(l: i32, t: i32, r: i32, b: i32) -> WindowRect { WindowRect { left:l, top:t, right:r, bottom:b } }
fn covered(region: &PaintRegion, x: i32, y: i32) -> usize {
    region.rects().iter().filter(|r| r.left <= x && x < r.right && r.top <= y && y < r.bottom).count()
}

// Wine 10.20 server/window.c redraw_window: INVALIDATE/VALIDATE and internal flags are ordered branches.
#[test]
fn exact_region_hole_subtraction_and_union_do_not_fill_gaps() {
    let mut region = PaintRegion::from_rect(rect(0,0,10,10)).unwrap();
    region.subtract(&PaintRegion::from_rect(rect(2,2,8,8)).unwrap()).unwrap();
    assert_eq!(region.bounds(),Some(rect(0,0,10,10)));
    for y in 0..10 { for x in 0..10 { assert_eq!(covered(&region,x,y),usize::from(!(2..8).contains(&x)||!(2..8).contains(&y))); } }
    region.union(&PaintRegion::from_rect(rect(4,4,6,6)).unwrap()).unwrap();
    assert_eq!(covered(&region,3,3),0); assert_eq!(covered(&region,4,4),1);
    let original = region.clone();
    assert!(region.translated(i32::MAX,0).is_err()); assert_eq!(region,original);
    region.subtract(&PaintRegion::from_rect(rect(-1,-1,11,11)).unwrap()).unwrap();
    assert!(region.is_empty());
}

#[test]
fn exact_region_operations_match_pixel_set_oracle() {
    let mut region = PaintRegion::default(); let mut pixels = [[false;16];16];
    let mut seed = 0x4839u32;
    for step in 0..100 {
        let mut next = || { seed = seed.wrapping_mul(1664525).wrapping_add(1013904223); (seed >> 16) as i32 % 16 };
        let (a,b,c,d)=(next(),next(),next(),next());
        let r=rect(a.min(b),c.min(d),a.max(b),c.max(d));
        let rhs=PaintRegion::from_rect(r).unwrap();
        if step%3==0 { region.subtract(&rhs).unwrap(); } else { region.union(&rhs).unwrap(); }
        for y in 0..16 { for x in 0..16 {
            if x>=r.left && x<r.right && y>=r.top && y<r.bottom { pixels[y as usize][x as usize]=step%3!=0; }
            assert_eq!(covered(&region,x,y),usize::from(pixels[y as usize][x as usize]));
        } }
    }
}

#[test]
fn paint_flags_preserve_internal_only_and_exact_validate_hole() {
    let client=rect(0,0,10,10); let frame=rect(-2,-2,12,12);
    let mut damage=PaintDamage::default();
    damage.apply(None,client,frame,RDW_INVALIDATE|RDW_VALIDATE|RDW_ERASE|RDW_FRAME,false).unwrap();
    assert!(damage.erase&&damage.nonclient); assert_eq!(damage.region.bounds(),Some(frame));
    damage.apply(Some(&PaintRegion::from_rect(rect(2,2,8,8)).unwrap()),client,frame,RDW_VALIDATE|RDW_NOERASE,false).unwrap();
    assert!(!damage.erase); assert_eq!(covered(&damage.region,5,5),0); assert_eq!(covered(&damage.region,-1,-1),1);
    damage.apply(None,client,frame,RDW_VALIDATE|RDW_NOFRAME|RDW_INTERNALPAINT|RDW_NOINTERNALPAINT,false).unwrap();
    assert!(damage.pending()); assert!(damage.region.is_empty()); assert!(damage.internal);
    damage.apply(None,client,frame,RDW_NOINTERNALPAINT,false).unwrap(); assert!(!damage.pending());
}

fn window() -> (WindowManager, WindowId) {
    let mut state=WindowManager::new(); let id=state.create(7,None,0x1234).unwrap();
    state.set_visible(id,true).unwrap(); state.set_rect(id,rect(0,0,10,10)).unwrap(); (state,id)
}

#[test]
fn actual_owner_transfers_exact_session_and_preserves_callback_damage() {
    let (mut state,id)=window();
    state.invalidate(id,Some(rect(0,0,3,3))).unwrap();
    state.invalidate(id,Some(rect(7,7,10,10))).unwrap();
    assert_eq!(state.pending_paint_message(7).unwrap().hwnd,Some(id));
    assert_eq!(state.begin_paint(id),Ok(Some(rect(0,0,10,10))));
    assert_eq!(covered(&state.paint_region(id).unwrap(),5,5),0);
    assert!(state.pending_paint_message(7).is_none());
    state.invalidate(id,Some(rect(4,4,6,6))).unwrap(); state.end_paint(id).unwrap();
    assert_eq!(state.begin_paint(id),Ok(Some(rect(4,4,6,6)))); state.end_paint(id).unwrap();
    state.redraw_damage(id,None,RDW_INTERNALPAINT,false).unwrap();
    assert!(state.pending_paint_message(7).is_some()); assert_eq!(state.begin_paint(id),Ok(None));
    assert!(state.pending_paint_message(7).is_none());
}

#[test]
fn actual_validate_does_not_leave_stale_paint_queue_message() {
    let (mut state,id)=window(); state.invalidate(id,None).unwrap();
    state.redraw_damage(id,None,RDW_VALIDATE|RDW_NOFRAME,false).unwrap();
    assert!(state.pending_paint_message(7).is_none());
    let filter=super::super::MessageFilter{hwnd:None,first:0,last:0};
    assert!(state.peek_for_thread(7,filter,false).is_none());
}

#[test]
fn tree_invalidation_maps_child_origin_and_uses_opposite_clipchildren_rule() {
    let (mut state,root)=window(); let child=state.create(7,Some(root),0x2345).unwrap();
    state.set_visible(child,true).unwrap(); state.set_rect(child,rect(2,2,8,8)).unwrap();
    let request=PaintRegion::from_rect(rect(4,4,6,6)).unwrap();
    state.redraw_tree(root,Some(&request),RDW_INVALIDATE,|_,_,r|r.try_copy()).unwrap();
    assert_eq!(state.begin_paint(child),Ok(Some(rect(2,2,4,4))));
    assert!(state.painting.iter().find(|(id,_)|*id==child).unwrap().1.erase);
    state.end_paint(child).unwrap();
    state.set_window_styles(root,0x0200_0000,0).unwrap();
    state.redraw_tree(root,None,RDW_INVALIDATE,|_,_,r|r.try_copy()).unwrap();
    assert_eq!(state.begin_paint(child),Ok(None)); state.end_paint(child).unwrap();
    state.redraw_tree(root,None,RDW_INVALIDATE|RDW_ALLCHILDREN,|_,_,r|r.try_copy()).unwrap();
    assert_eq!(state.begin_paint(child),Ok(Some(rect(0,0,6,6)))); state.end_paint(child).unwrap();
    state.redraw_tree(root,None,RDW_INVALIDATE|RDW_ALLCHILDREN|RDW_NOCHILDREN,|_,_,r|r.try_copy()).unwrap();
    assert_eq!(state.begin_paint(child),Ok(None));
}

#[test]
fn paint_selection_orders_parent_and_transparent_siblings_and_consumes_internal() {
    let (mut state,root)=window(); let low=state.create(7,Some(root),1).unwrap(); let high=state.create(7,Some(root),1).unwrap();
    for id in [low,high] { state.set_visible(id,true).unwrap();state.set_rect(id,rect(0,0,4,4)).unwrap();state.invalidate(id,None).unwrap(); }
    state.set_window_styles(high,0,0x20).unwrap();
    assert_eq!(state.pending_paint_message(7).unwrap().hwnd,Some(low));
    state.invalidate(root,None).unwrap();
    let child_filter=super::super::MessageFilter{hwnd:Some(high),first:0,last:0};
    assert!(state.take_pending_paint(7,child_filter).is_none());
    assert_eq!(state.pending_paint_message(7).unwrap().hwnd,Some(root));
    state.redraw_tree(root,None,RDW_VALIDATE|RDW_NOFRAME|RDW_ALLCHILDREN,|_,_,r|r.try_copy()).unwrap();
    state.redraw_damage(root,None,RDW_INTERNALPAINT,false).unwrap();
    let filter=super::super::MessageFilter{hwnd:None,first:0,last:0};
    assert!(state.take_pending_paint(7,filter).is_some());assert!(state.take_pending_paint(7,filter).is_none());
}

#[test]
fn erase_snapshot_does_not_overwrite_callback_time_invalidation() {
    let (mut state,id)=window();
    state.redraw_damage(id,None,RDW_INVALIDATE|RDW_ERASE|RDW_FRAME,false).unwrap();
    let saved=state.take_erase_damage(id).unwrap();assert!(saved.erase&&saved.nonclient);
    state.redraw_damage(id,Some(&PaintRegion::from_rect(rect(3,3,4,4)).unwrap()),RDW_INVALIDATE|RDW_ERASE,false).unwrap();
    state.finish_erase_damage(id,false);
    let new=state.take_erase_damage(id).unwrap();assert!(new.erase);
    state.finish_erase_damage(id,true);
    let delayed=state.take_erase_damage(id).unwrap();assert!(delayed.delayed_erase);
    assert!(state.pending_paint_message(7).is_some());
}

#[test]
fn begin_child_paint_subtracts_exact_hole_from_unclipped_parent() {
    let (mut state,root)=window();let child=state.create(7,Some(root),1).unwrap();
    state.set_visible(child,true).unwrap();state.set_rect(child,rect(2,2,8,8)).unwrap();
    state.invalidate(root,None).unwrap();state.invalidate(child,None).unwrap();state.begin_paint(child).unwrap();
    state.begin_paint(root).unwrap();let region=state.paint_region(root).unwrap();
    assert_eq!(covered(&region,0,0),1);assert_eq!(covered(&region,3,3),0);assert_eq!(region.bounds(),Some(rect(0,0,10,10)));
}

#[test]
fn fragmentation_exhaustion_does_not_replace_original_region() {
    let mut region=PaintRegion::from_rect(rect(0,0,9000,2)).unwrap();
    let cuts:Vec<_>=(0..4096).map(|x|rect(x*2+1,0,x*2+2,2)).collect();
    let cuts=PaintRegion::from_rects(&cuts).unwrap();let original=region.clone();
    assert_eq!(region.subtract(&cuts),Err(WindowError::NoMemory));assert_eq!(region,original);
}

#[test]
fn erase_now_validates_nonclient_only_damage_without_creating_client_paint() {
    let (mut state,id)=window();
    state.windows.iter_mut().find(|(window,_)|*window==id).unwrap().1.client_rect=Some(rect(2,2,8,8));
    let border=PaintRegion::from_rect(rect(-2,-2,8,0)).unwrap();
    state.redraw_damage(id,Some(&border),RDW_INVALIDATE|RDW_FRAME|RDW_ERASE,false).unwrap();
    let snapshot=state.take_erase_damage(id).unwrap();assert!(snapshot.nonclient&&snapshot.erase);
    assert!(state.pending_paint_message(7).is_none());assert!(snapshot.region.clipped(rect(0,0,6,6)).unwrap().is_empty());
}

#[test]
fn wait_predicate_never_consumes_internal_paint_posted_or_quit() {
    let (mut state,id)=window();
    let all=super::super::MessageFilter{hwnd:None,first:0,last:0};
    let paint=super::super::MessageFilter{hwnd:Some(id),first:super::super::WM_PAINT,last:super::super::WM_PAINT};
    state.redraw_damage(id,None,RDW_INTERNALPAINT,false).unwrap();
    for _ in 0..3 { assert!(state.has_message_for_thread(7,paint)); }
    assert!(state.take_pending_paint(7,paint).is_some());assert!(!state.has_message_for_thread(7,paint));
    let posted=super::super::WinMessage{hwnd:Some(id),message:super::super::WM_CLOSE,wparam:0,lparam:0};
    state.post_to_window(id,posted).unwrap();state.post_quit(7,19);
    assert!(state.has_message_for_thread(7,all));assert!(!state.has_message_for_thread(7,paint));
    assert_eq!(state.peek_for_thread(7,all,true),Some(posted));
    for _ in 0..3 { assert!(state.has_message_for_thread(7,all)); }
    assert_eq!(state.peek_for_thread(7,all,true).unwrap().message,super::super::WM_QUIT);
    assert!(!state.has_message_for_thread(7,all));assert!(!state.has_message_for_thread(8,all));
}
