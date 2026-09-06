use super::*;

#[test]
fn resize_uses_one_posted_slot_and_independent_paint_readiness() {
    let mut state=WindowManager::new();let id=state.create(7,None,1).unwrap();
    state.set_visible(id,true).unwrap();let old=WindowRect{left:0,top:0,right:10,bottom:10};state.set_rect(id,old).unwrap();
    let posted=WinMessage{hwnd:Some(id),message:WM_CLOSE,wparam:0,lparam:0};
    while state.post_to_window(id,posted).is_ok() {}
    let next=WindowRect{right:20,..old};
    assert_eq!(state.configure_compositor_window(id,next),Err(WindowError::QueueFull));
    assert_eq!(state.rect(id),Some(old));assert!(state.pending_paint_message(7).is_none());
    let close=MessageFilter{hwnd:Some(id),first:WM_CLOSE,last:WM_CLOSE};
    assert_eq!(state.peek_for_thread(7,close,true),Some(posted));
    assert_eq!(state.configure_compositor_window(id,next),Ok(()));
    assert_eq!(state.post_to_window(id,posted),Err(WindowError::QueueFull));
    let size=MessageFilter{hwnd:Some(id),first:WM_SIZE,last:WM_SIZE};
    assert_eq!(state.peek_for_thread(7,size,true).unwrap().message,WM_SIZE);
    let paint=MessageFilter{hwnd:Some(id),first:WM_PAINT,last:WM_PAINT};
    assert!(state.has_message_for_thread(7,paint));
    assert_eq!(state.peek_for_thread(7,paint,true).unwrap().message,WM_PAINT);
    state.begin_paint(id).unwrap();assert!(!state.has_message_for_thread(7,paint));
}
