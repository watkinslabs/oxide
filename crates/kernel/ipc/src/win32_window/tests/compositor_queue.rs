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

#[test]
fn refused_resize_preserves_outer_and_client_geometry(){
    let (mut state,frame,child)=banded_frame();
    let old=state.rect(frame);let client=state.client_rect_raw(frame);let placement=presented(&state,frame,child);
    assert_eq!(state.configure_compositor_window(frame,rect(100,200,829,201)),Err(WindowError::InvalidParent));
    assert_eq!(state.rect(frame),old,"a rejected resize must not commit its outer rectangle");
    assert_eq!(state.client_rect_raw(frame),client);
    assert_eq!(presented(&state,frame,child),placement);
    let any=MessageFilter{hwnd:Some(frame),first:0,last:0};
    assert!(state.peek_for_thread(7,any,true).is_none());
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

/// A window that changed size exposes area no paint covered and a frame band
/// sized from the window rectangle, so both the nonclient band and the
/// descendants take damage and the background is erased. A window that only
/// moved keeps every pixel it had.
#[test]
fn a_resize_invalidates_the_frame_band_and_the_children_while_a_move_invalidates_nothing(){
    let (mut state,frame,child)=banded_frame();
    state.set_visible(frame,true).unwrap();state.set_visible(child,true).unwrap();
    assert_eq!(state.configure_compositor_window(frame,rect(148,146,877,692)),Ok(()));
    let damage=state.erase_damage(frame).unwrap();
    assert!(damage.nonclient,"a resized window's frame band is repainted with it");
    assert!(damage.erase,"a resize reveals area with no pixels, so the background is erased");
    // The band sits above the client origin, so client-coordinate damage that
    // covers it starts above zero.
    assert_eq!(damage.region.bounds(),Some(rect(0,-19,729,527)));
    assert!(!state.erase_damage(child).unwrap().region.is_empty(),"a resize repaints the descendants");
    state.begin_paint(frame).unwrap();state.begin_paint(child).unwrap();
    let moved=rect(200,146,929,692);
    assert_eq!(state.configure_compositor_window(frame,moved),Ok(()));
    assert!(state.erase_damage(frame).unwrap().region.is_empty(),"a move carries the window's pixels with it");
}

/// An exposure is stated in the window's own coordinates; canonical damage is
/// stated in client coordinates, so the band the frame reserves comes off it.
#[test]
fn an_exposure_is_read_in_window_coordinates_and_recorded_in_client_coordinates(){
    let (mut state,frame,child)=banded_frame();
    state.set_visible(frame,true).unwrap();state.set_visible(child,true).unwrap();
    assert_eq!(state.expose_compositor_window(frame,rect(10,29,110,129)),Ok(()));
    let damage=state.erase_damage(frame).unwrap();
    assert_eq!(damage.region.bounds(),Some(rect(10,10,110,110)));
    // Nothing underneath the window changed: the display is restating pixels
    // the window already owns, so no background erase is requested.
    assert!(!damage.erase,"an exposure restates owned pixels and asks for no erase");
    assert!(damage.nonclient,"an exposure covers the frame band as well as the client area");
    let paint=MessageFilter{hwnd:Some(frame),first:WM_PAINT,last:WM_PAINT};
    assert!(state.has_message_for_thread(7,paint));
    assert_eq!(state.begin_paint(frame),Ok(Some(rect(10,10,110,110))));
    assert!(!state.erase_damage(child).unwrap().region.is_empty(),"an exposure repaints the descendants it covers");
}

/// Only the band, above the client origin: the client area takes no damage but
/// the window still owes a paint for its nonclient band.
#[test]
fn an_exposure_of_the_band_alone_paints_the_nonclient_area(){
    let (mut state,frame,_child)=banded_frame();
    state.set_visible(frame,true).unwrap();
    assert_eq!(state.expose_compositor_window(frame,rect(0,0,729,19)),Ok(()));
    let damage=state.erase_damage(frame).unwrap();
    assert_eq!(damage.region.bounds(),Some(rect(0,-19,729,0)));
    assert!(damage.nonclient);
    assert!(state.has_message_for_thread(7,MessageFilter{hwnd:Some(frame),first:WM_PAINT,last:WM_PAINT}));
    assert_eq!(state.begin_paint(frame),Ok(None),"nothing of the client area was exposed");
}

#[test]
fn an_empty_or_unknown_exposure_is_refused(){
    let (mut state,frame,_child)=banded_frame();
    state.set_visible(frame,true).unwrap();
    assert_eq!(state.expose_compositor_window(frame,rect(10,10,10,40)),Err(WindowError::InvalidParent));
    assert_eq!(state.expose_compositor_window(WindowId::from_raw(0x900).unwrap(),rect(0,0,4,4)),Err(WindowError::NoSuchWindow));
    assert!(state.erase_damage(frame).unwrap().region.is_empty());
}
