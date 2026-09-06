use super::*;
const TID:u64=37;
fn setup()->(WindowManager,WindowId,WindowId,WindowId) {
    let mut state=WindowManager::new();let root=state.create(TID,None,0).unwrap();
    let a=state.create(TID,Some(root),0).unwrap();let b=state.create(TID,Some(root),0).unwrap();
    state.set_window_styles(a,WS_CHILD,0).unwrap();state.set_window_styles(b,WS_CHILD,0).unwrap();
    (state,root,a,b)
}
fn request(id:WindowId)->WindowPosition {
    WindowPosition {window:id,rect:WindowRect {left:0,top:0,right:100,bottom:50},client:None,
        order:None,visible:None,flags:NOACTIVATE,notify_geometry:true}
}
#[test]
fn geometry_visibility_and_messages_are_canonical() {
    let(mut s,_,a,_)=setup();let mut p=request(a);p.visible=Some(true);
    s.apply_position(TID,p).unwrap();assert_eq!(s.rect(a),Some(p.rect));assert!(s.get(a).unwrap().visible);
    let filter=MessageFilter {hwnd:Some(a),first:WM_SIZE,last:WM_SIZE};
    assert_eq!(s.peek_for_thread(TID,filter,true).unwrap().lparam,mouse_lparam(100,50));
}
#[test]
fn sibling_order_and_topmost_are_in_the_canonical_vector() {
    let(mut s,root,a,b)=setup();let mut p=request(a);p.order=Some(PositionOrder::Top);
    s.apply_position(TID,p).unwrap();assert_eq!(s.position_siblings(Some(root)),[b,a]);
    p.order=Some(PositionOrder::Bottom);s.apply_position(TID,p).unwrap();assert_eq!(s.position_siblings(Some(root)),[a,b]);
    p.order=Some(PositionOrder::Topmost);s.apply_position(TID,p).unwrap();assert_ne!(s.get(a).unwrap().ex_style&WS_EX_TOPMOST,0);
    let mut q=request(b);q.order=Some(PositionOrder::Top);s.apply_position(TID,q).unwrap();assert_eq!(s.position_siblings(Some(root)),[b,a]);
    p.order=Some(PositionOrder::NotTopmost);s.apply_position(TID,p).unwrap();assert_eq!(s.get(a).unwrap().ex_style&WS_EX_TOPMOST,0);
    p.order=Some(PositionOrder::After(b));s.apply_position(TID,p).unwrap();assert_eq!(s.position_siblings(Some(root)),[a,b]);
}
#[test]
fn wrong_thread_and_wrong_parent_cannot_mutate() {
    let(mut s,root,a,_)=setup();let before=s.rect(a);let mut p=request(a);
    assert_eq!(s.apply_position(TID+1,p),Err(WindowError::WrongThread));assert_eq!(s.rect(a),before);
    p.order=Some(PositionOrder::After(root));assert_eq!(s.apply_position(TID,p),Err(WindowError::InvalidParent));assert_eq!(s.rect(a),before);
}
#[test]
fn full_queue_rejects_before_geometry_visibility_or_order_changes() {
    let(mut s,root,a,b)=setup();let before=s.rect(a);
    for _ in 0..MESSAGE_QUEUE_LIMIT {s.post_to_window(a,WinMessage {hwnd:Some(a),message:WM_PAINT,wparam:0,lparam:0}).unwrap();}
    let mut p=request(a);p.visible=Some(true);p.order=Some(PositionOrder::Top);
    assert_eq!(s.apply_position(TID,p),Err(WindowError::QueueFull));assert_eq!(s.rect(a),before);
    assert!(!s.get(a).unwrap().visible);assert_eq!(s.position_siblings(Some(root)),[a,b]);
}
#[test]
fn activation_and_hide_update_canonical_active_window() {
    let(mut s,root,_,_)=setup();let mut p=request(root);p.flags=0;p.visible=Some(true);
    s.apply_position(TID,p).unwrap();assert_eq!(s.active_window(),Some(root));
    p.flags=NOACTIVATE|HIDEWINDOW;p.visible=Some(false);s.apply_position(TID,p).unwrap();assert_eq!(s.active_window(),None);
}
#[test]
fn zero_statusbar_is_visible_without_empty_paint_and_client_bounds_are_owned() {
    let(mut s,_,a,_)=setup();let mut p=request(a);p.rect.right=0;p.rect.bottom=0;p.visible=Some(true);p.client=Some(p.rect);
    s.apply_position(TID,p).unwrap();assert!(s.get(a).unwrap().visible);
    assert_eq!(s.get(a).unwrap().client_rect,Some(p.rect));assert!(!s.dirty.iter().any(|(id,_)|*id==a));
}

#[test]
fn noredraw_updates_geometry_without_dirty_or_paint_notification() {
    let(mut s,_,a,_)=setup();let mut p=request(a);p.visible=Some(true);p.flags|=NOREDRAW;
    s.apply_position(TID,p).unwrap();assert_eq!(s.rect(a),Some(p.rect));assert!(s.get(a).unwrap().visible);
    assert!(!s.dirty.iter().any(|(id,_)|*id==a));
    assert!(s.peek_for_thread(TID,MessageFilter {hwnd:Some(a),first:WM_PAINT,last:WM_PAINT},false).is_none());
}
#[test]
fn zero_client_extent_does_not_fail_after_committing_nonzero_window() {
    let(mut s,_,a,_)=setup();let mut p=request(a);p.visible=Some(true);
    let client=WindowRect {left:4,top:4,right:4,bottom:4};p.client=Some(client);
    s.apply_position(TID,p).unwrap();assert_eq!(s.rect(a),Some(p.rect));assert_eq!(s.get(a).unwrap().client_rect,Some(client));
    assert_eq!(s.client_rect(a),Some(WindowRect {left:0,top:0,right:0,bottom:0}));
    assert!(!s.dirty.iter().any(|(id,_)|*id==a));
}
#[test]
fn notopmost_on_already_regular_window_preserves_order() {
    let(mut s,root,a,b)=setup();let mut p=request(a);p.order=Some(PositionOrder::NotTopmost);
    s.apply_position(TID,p).unwrap();assert_eq!(s.position_siblings(Some(root)),[a,b]);
}
#[test]
fn owner_lift_preserves_popup_order_and_popup_cannot_sink_below_owner(){
    let mut s=WindowManager::new();let root=s.create(TID,None,0).unwrap();
    let a=s.create(TID,None,0).unwrap();let b=s.create(TID,None,0).unwrap();
    s.set_popup_owner(a,Some(root)).unwrap();s.set_popup_owner(b,Some(root)).unwrap();
    let mut p=request(root);p.order=Some(PositionOrder::Top);s.apply_position(TID,p).unwrap();
    assert_eq!(s.position_siblings(None),[root,a,b]);
    p=request(a);p.order=Some(PositionOrder::Bottom);s.apply_position(TID,p).unwrap();
    let order=s.position_siblings(None);assert!(order.iter().position(|id|*id==root)<order.iter().position(|id|*id==a));
}
#[test]
fn popup_owner_cycles_and_child_owners_are_rejected_before_mutation(){
    let(mut s,root,a,_)=setup();let popup=s.create(TID,None,0).unwrap();
    s.set_popup_owner(popup,Some(root)).unwrap();
    assert_eq!(s.set_popup_owner(root,Some(popup)),Err(WindowError::InvalidParent));assert_eq!(s.get(root).unwrap().owner,None);
    assert_eq!(s.set_popup_owner(popup,Some(a)),Err(WindowError::InvalidParent));assert_eq!(s.get(popup).unwrap().owner,Some(root));
}
#[test]
fn lifting_owner_to_topmost_keeps_owned_popup_above_in_same_band(){
    let mut s=WindowManager::new();let root=s.create(TID,None,0).unwrap();let popup=s.create(TID,None,0).unwrap();
    s.set_popup_owner(popup,Some(root)).unwrap();let mut p=request(root);p.order=Some(PositionOrder::Topmost);
    s.apply_position(TID,p).unwrap();assert_eq!(s.position_siblings(None),[root,popup]);assert_ne!(s.get(popup).unwrap().ex_style&WS_EX_TOPMOST,0);
}
#[test]
fn combined_child_popup_bits_allow_top_level_ownership_for_both_ends(){
    let mut s=WindowManager::new();let owner=s.create(TID,None,0).unwrap();let popup=s.create(TID,None,0).unwrap();
    s.set_window_styles(owner,WS_CHILD|WS_POPUP,0).unwrap();s.set_window_styles(popup,WS_CHILD|WS_POPUP,0).unwrap();
    assert_eq!(s.set_popup_owner(popup,Some(owner)),Ok(()));assert_eq!(s.get(popup).unwrap().owner,Some(owner));
}
