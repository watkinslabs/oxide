use super::*;
use ipc::win32_window::{RDW_INVALIDATE,RDW_ERASE,RDW_FRAME,PaintSessionError};
fn setup()->(u32,u32,u32){
    let group=Arc::new(thread_group::ThreadGroup);ENV.with(|e|*e.borrow_mut()=Env{task:Some(Task{tid:7,thread_group:group.clone()}),..Default::default()});
    let mut state=WindowManager::new();let id=state.create(7,None,0).unwrap();
    state.set_rect(id,WindowRect{left:0,top:0,right:4,bottom:4}).unwrap();
    let region=PaintRegion::from_rect(WindowRect{left:0,top:0,right:2,bottom:2}).unwrap();
    state.redraw_damage(id,Some(&region),RDW_INVALIDATE|RDW_ERASE|RDW_FRAME,false).unwrap();
    let mut gdi=GdiManager::new();let backing=gdi.acquire_window_dc(id.raw(),4,4).unwrap();let dc=gdi.create_dc(4,4).unwrap();
    *GDI.lock().unwrap()=Some(gdi);*GUI.lock()=vec![Entry{group:Arc::downgrade(&group),state,paint_callbacks:paint_callbacks::Queue::new(),sent:send::Queue::new()}];
    paint::reserve_for_current(id.raw() as u64).unwrap();GUI.lock()[0].state.bind_paint_dc(id,dc).unwrap();(id.raw(),dc,backing)
}
fn callbacks(hwnd:u32,dc:u32,destination:u64){
    assert_eq!(paint_prepare::prepare_for_current(hwnd,dc,destination),STATUS_PENDING);
    ENV.with(|e|{let e=e.borrow();assert_eq!(e.pending.unwrap().0,0x85);assert!(e.events.is_empty());assert!(e.copies.is_empty());});
    assert_eq!(send::execute_callback(),STATUS_PENDING);
    ENV.with(|e|{let e=e.borrow();assert_eq!(e.pending.unwrap().0,0x14);assert_eq!(e.events,[Event::Nc]);assert!(e.copies.is_empty());});
    assert!(GDI.lock().unwrap().as_ref().unwrap().contains_object(dc));
    assert_eq!(send::execute_callback(),0);
}
#[test]
fn null_terminal_retains_nonblack_callback_pixels_after_nc_then_erase_and_before_cleanup(){
    let _serial=SERIAL.lock().unwrap();let(hwnd,dc,backing)=setup();callbacks(hwnd,dc,0);
    ENV.with(|e|{let e=e.borrow();assert_eq!(e.events,[Event::Nc,Event::Erase,Event::Retain,Event::DeleteDc,Event::DeleteRegion]);
        assert!(e.copies.is_empty());assert!(e.pending.is_none());assert_eq!(e.milestones,0);});
    let gdi=GDI.lock().unwrap();let state=gdi.as_ref().unwrap();assert!(!state.contains_object(dc));assert_eq!(state.window_dc(hwnd),Some(backing));
    assert_eq!(&state.pixels(backing).unwrap()[..2],&[0x123456,0x654321]);assert!(state.pixels(backing).unwrap()[2..].iter().all(|p|*p==0));
    assert!(state.pending_output(hwnd,backing).is_some());drop(gdi);
    assert_eq!(GUI.lock()[0].state.paint_session(WindowId::from_raw(hwnd).unwrap()),Err(PaintSessionError::NotActive));
    assert!(!GUI.lock()[0].paint_callbacks.holds_dc(dc));
}
#[test]
fn invalid_pointer_runs_both_callbacks_before_faulting_copy_and_resource_cleanup(){
    let _serial=SERIAL.lock().unwrap();let(hwnd,dc,_)=setup();const BAD_POINTER:u64=0x8000;callbacks(hwnd,dc,BAD_POINTER);
    ENV.with(|e|{let e=e.borrow();assert_eq!(e.events,[Event::Nc,Event::Erase,Event::Copy,Event::DeleteDc,Event::DeleteRegion]);
        assert_eq!(e.copies.len(),1);assert_eq!(e.copies[0].0,BAD_POINTER);assert_eq!(e.copies[0].1.len(),28);assert_eq!(e.milestones,0);assert!(e.pending.is_none());});
    assert!(!GDI.lock().unwrap().as_ref().unwrap().contains_object(dc));
    assert_eq!(GUI.lock()[0].state.paint_session(WindowId::from_raw(hwnd).unwrap()),Err(PaintSessionError::NotActive));
}
