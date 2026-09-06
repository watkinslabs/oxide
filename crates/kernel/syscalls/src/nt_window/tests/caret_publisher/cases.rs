use super::*;
use std::sync::Arc;
use crate::environment::{ENV,SERIAL,Env,Task};
use ipc::win32_window::{WindowRect,WindowPosition};
use caret::{CaretRenderSink,live::*,publish::Current};
fn setup()->(u64,u64){
    let group=Arc::new(crate::thread_group::ThreadGroup);
    ENV.with(|e|*e.borrow_mut()=Env{task:Some(Task{tid:1,thread_group:group.clone(),nt:true}),..Default::default()});
    let mut state=WindowManager::new();let first=state.create(1,None,0).unwrap();let second=state.create(1,None,0).unwrap();
    state.apply_position(1,WindowPosition{window:first,rect:WindowRect{left:100,top:200,right:400,bottom:500},client:Some(WindowRect{left:105,top:220,right:395,bottom:495}),order:None,visible:None,flags:0x10,notify_geometry:false}).unwrap();
    *GUI.lock()=vec![GuiEntry{group:Arc::downgrade(&group),state}];(first.raw() as u64,second.raw() as u64)
}
#[test]fn client_origin_and_old_hwnd_transition_reach_owned_wire_pixels(){
    let _serial=SERIAL.lock().unwrap();let (first,second)=setup();let mut sink=Current;
    assert_eq!(create_caret_for_current(first,2,3,&mut sink),1);
    assert_eq!(set_caret_pos_for_current(7,9,&mut sink),1);
    assert!(ENV.with(|e|e.borrow().snapshots.is_empty()));
    assert_eq!(show_caret_for_current(first,&mut sink),1);
    ENV.with(|e|{let e=e.borrow();let (hwnd,s)=&e.snapshots[0];assert_eq!(*hwnd,first);assert_eq!((s.rect.x,s.rect.y,s.rect.width,s.rect.height),(12,29,2,3));assert_eq!(s.mask,vec![0x00ff_ffff;6]);assert!(s.visible);});
    assert_eq!(create_caret_for_current(second,1,2,&mut sink),1);
    ENV.with(|e|{let e=e.borrow();assert_eq!(e.snapshots[1].0,first);assert!(!e.snapshots[1].1.visible);});
    assert_eq!(show_caret_for_current(second,&mut sink),1);
    assert_eq!(destroy_caret_for_current(&mut sink),1);
    ENV.with(|e|{let e=e.borrow();assert_eq!(e.snapshots[2].0,second);assert!(e.snapshots[2].1.visible);assert_eq!(e.snapshots[3].0,second);assert!(!e.snapshots[3].1.visible);});
}
#[test]fn owner_personality_bad_dimensions_and_overflow_reject_before_transport(){
    let _serial=SERIAL.lock().unwrap();let (hwnd,_)=setup();let mut sink=Current;
    assert!(!sink.paint_caret_pixels(2,hwnd,(0,0,1,1),1));
    ENV.with(|e|e.borrow_mut().task.as_mut().unwrap().tid=2);assert!(!sink.paint_caret_pixels(2,hwnd,(0,0,1,1),1));
    ENV.with(|e|{let mut e=e.borrow_mut();let t=e.task.as_mut().unwrap();t.tid=1;t.nt=false;});assert!(!sink.paint_caret_pixels(1,hwnd,(0,0,1,1),1));
    ENV.with(|e|e.borrow_mut().task.as_mut().unwrap().nt=true);
    for rect in [(0,0,0,1),(1,0,0,1),(i32::MAX,0,i32::MAX,1),(i32::MIN,0,i32::MAX,1)]{assert!(!sink.paint_caret_pixels(1,hwnd,rect,1));}
    assert!(!sink.paint_caret_pixels(1,u64::MAX,(0,0,1,1),1));assert!(!sink.paint_caret_pixels(1,hwnd,(0,0,1,1),0));
    assert!(ENV.with(|e|e.borrow().snapshots.is_empty()));
}
#[test]fn failure_propagates_and_stops_move_before_paint(){
    let _serial=SERIAL.lock().unwrap();let (hwnd,_)=setup();let mut sink=Current;
    assert_eq!(create_caret_for_current(hwnd,1,2,&mut sink),1);assert_eq!(show_caret_for_current(hwnd,&mut sink),1);
    ENV.with(|e|{let mut e=e.borrow_mut();e.snapshots.clear();e.fail=true;});
    assert_eq!(set_caret_pos_for_current(4,5,&mut sink),0);
    ENV.with(|e|{let e=e.borrow();assert_eq!(e.snapshots.len(),1);assert!(!e.snapshots[0].1.visible);});
}
