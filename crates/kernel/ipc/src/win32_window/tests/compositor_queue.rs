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

fn rect(left:i32,top:i32,right:i32,bottom:i32)->WindowRect{WindowRect{left,top,right,bottom}}

/// A frame with a menu band and the child that covers its client area, as a
/// window manager places them: the frame's own rectangle becomes root-relative
/// once the compositor reports it, the child's stays in the frame's client
/// space, and the band is the frame's only nonclient inset.
fn banded_frame()->(WindowManager,WindowId,WindowId){
    let mut state=WindowManager::new();
    let frame=state.create(7,None,0x140001000).unwrap();
    state.set_rect(frame,rect(0,0,729,528)).unwrap();
    state.set_client_rect(frame,rect(0,19,729,528)).unwrap();
    let child=state.create(7,Some(frame),0x140002000).unwrap();
    state.set_rect(child,rect(0,0,729,509)).unwrap();
    (state,frame,child)
}

fn presented(state:&WindowManager,frame:WindowId,child:WindowId)->(i32,i32){
    let origin=nonclient_create::client_origin(state.rect(frame).unwrap(),state.client_rect_raw(frame).unwrap());
    let placed=state.rect(child).unwrap();
    (placed.left+origin.0,placed.top+origin.1)
}

#[test]
fn a_child_configure_is_read_in_the_parents_client_space(){
    let (mut state,frame,child)=banded_frame();
    // The compositor reports the child's position inside the parent's window,
    // which is where the parent's client origin already put it. Reading that
    // back as a client-relative rectangle would add the band a second time.
    assert_eq!(state.configure_compositor_window(child,rect(0,19,729,528)),Ok(()));
    assert_eq!(state.rect(child),Some(rect(0,0,729,509)));
    assert_eq!(presented(&state,frame,child),(0,19));
}

#[test]
fn a_configured_frame_keeps_its_nonclient_insets_and_reports_client_geometry(){
    let (mut state,frame,_child)=banded_frame();
    assert_eq!(state.configure_compositor_window(frame,rect(148,146,877,692)),Ok(()));
    assert_eq!(state.rect(frame),Some(rect(148,146,877,692)));
    // The band is still reserved against the rectangle the window now has.
    assert_eq!(state.client_rect_raw(frame),Some(rect(148,165,877,692)));
    assert_eq!(nonclient_create::client_origin(state.rect(frame).unwrap(),state.client_rect_raw(frame).unwrap()),(0,19));
    assert_eq!(state.client_rect(frame),Some(rect(0,0,729,527)));
    // WM_MOVE carries the client origin and WM_SIZE the client extent.
    let moved=MessageFilter{hwnd:Some(frame),first:WM_MOVE,last:WM_MOVE};
    assert_eq!(state.peek_for_thread(7,moved,true).unwrap().lparam,mouse_lparam(148,165));
    let sized=MessageFilter{hwnd:Some(frame),first:WM_SIZE,last:WM_SIZE};
    assert_eq!(state.peek_for_thread(7,sized,true).unwrap().lparam,mouse_lparam(729,527));
}

#[test]
fn a_child_of_a_configured_frame_still_lands_under_the_band(){
    let (mut state,frame,child)=banded_frame();
    assert_eq!(state.configure_compositor_window(frame,rect(148,146,877,692)),Ok(()));
    // The child is resized to the client extent the frame reported, then the
    // compositor echoes the position it gave that child back at the kernel.
    state.set_rect(child,rect(0,0,729,527)).unwrap();
    assert_eq!(state.configure_compositor_window(child,rect(0,19,729,546)),Ok(()));
    assert_eq!(presented(&state,frame,child),(0,19),"a child presented above its parent's client origin covers the menu band");
}
