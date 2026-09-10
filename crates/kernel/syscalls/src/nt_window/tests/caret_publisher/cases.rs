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
    assert!(!sink.paint_caret_pixels(2,hwnd,(0,0,1,1),1,ipc::win32_window::CaretPattern::Solid));
    ENV.with(|e|e.borrow_mut().task.as_mut().unwrap().tid=2);assert!(!sink.paint_caret_pixels(2,hwnd,(0,0,1,1),1,ipc::win32_window::CaretPattern::Solid));
    ENV.with(|e|{let mut e=e.borrow_mut();let t=e.task.as_mut().unwrap();t.tid=1;t.nt=false;});assert!(!sink.paint_caret_pixels(1,hwnd,(0,0,1,1),1,ipc::win32_window::CaretPattern::Solid));
    ENV.with(|e|e.borrow_mut().task.as_mut().unwrap().nt=true);
    for rect in [(0,0,0,1),(i32::MAX,0,i32::MAX,1),(i32::MIN,0,i32::MAX,1)]{assert!(!sink.paint_caret_pixels(1,hwnd,rect,1,ipc::win32_window::CaretPattern::Solid));}
    assert!(!sink.paint_caret_pixels(1,u64::MAX,(0,0,1,1),1,ipc::win32_window::CaretPattern::Solid));assert!(!sink.paint_caret_pixels(1,hwnd,(0,0,1,1),0,ipc::win32_window::CaretPattern::Solid));
    assert!(ENV.with(|e|e.borrow().snapshots.is_empty()));
}
#[test]fn failure_propagates_and_stops_move_before_paint(){
    let _serial=SERIAL.lock().unwrap();let (hwnd,_)=setup();let mut sink=Current;
    assert_eq!(create_caret_for_current(hwnd,1,2,&mut sink),1);assert_eq!(show_caret_for_current(hwnd,&mut sink),1);
    ENV.with(|e|{let mut e=e.borrow_mut();e.snapshots.clear();e.fail=true;});
    assert_eq!(set_caret_pos_for_current(4,5,&mut sink),0);
    ENV.with(|e|{let e=e.borrow();assert_eq!(e.snapshots.len(),1);assert!(!e.snapshots[0].1.visible);});
}

#[test]fn raw_gray_caret_retains_pattern_through_move_and_hide_show(){
    let _serial=SERIAL.lock().unwrap();let(hwnd,_)=setup();
    assert_eq!(crate::caret_raw::dispatch(caret::CREATE_CARET_ORDINAL,[hwnd,1,3,2]),Some(1));
    assert_eq!(show_caret_for_current(hwnd,&mut Current),1);
    assert_eq!(set_caret_pos_for_current(4,7,&mut Current),1);
    assert_eq!(hide_caret_for_current(hwnd,&mut Current),1);
    assert_eq!(show_caret_for_current(hwnd,&mut Current),1);
    ENV.with(|e|{let e=e.borrow();let visible:Vec<_>=e.snapshots.iter().filter(|(_,s)|s.visible).collect();
        assert_eq!(visible.len(),3);
        for(_,s)in visible{assert_eq!(s.mask,vec![0,0xffffff,0,0xffffff,0,0xffffff]);s.validate().unwrap();}
        assert_eq!((e.snapshots.last().unwrap().1.rect.x,e.snapshots.last().unwrap().1.rect.y),(9,27));
    });
}

#[test]fn gray_pattern_survives_blink_and_solid_replacement_erases_it(){
    let _serial=SERIAL.lock().unwrap();let(hwnd,_)=setup();
    assert_eq!(crate::caret_raw::dispatch(caret::CREATE_CARET_ORDINAL,[hwnd,1,2,2]),Some(1));
    assert_eq!(show_caret_for_current(hwnd,&mut Current),1);
    for visible in [false,true]{
        let deadline=caret::blink::deadline_for_current().unwrap();
        assert_eq!(caret::blink::expire_for_current(deadline),1);
        ENV.with(|e|{let e=e.borrow();let s=&e.snapshots.last().unwrap().1;
            assert_eq!(s.visible,visible);assert_eq!(s.mask,if visible{vec![0,0xffffff,0xffffff,0]}else{vec![]});});
    }
    assert_eq!(crate::caret_raw::dispatch(caret::CREATE_CARET_ORDINAL,[hwnd,0,2,2]),Some(1));
    ENV.with(|e|assert!(!e.borrow().snapshots.last().unwrap().1.visible));
    assert_eq!(show_caret_for_current(hwnd,&mut Current),1);
    ENV.with(|e|assert_eq!(e.borrow().snapshots.last().unwrap().1.mask,vec![0xffffff;4]));
}
#[test]fn invalid_gray_creation_preserves_existing_caret_and_zero_extent_uses_border(){
    let _serial=SERIAL.lock().unwrap();let(hwnd,_)=setup();
    assert_eq!(crate::caret_raw::dispatch(caret::CREATE_CARET_ORDINAL,[hwnd,1,0,3]),Some(1));
    assert_eq!(show_caret_for_current(hwnd,&mut Current),1);
    ENV.with(|e|assert_eq!(e.borrow().snapshots.last().unwrap().1.mask,vec![0,0xffffff,0]));
    let before=ENV.with(|e|e.borrow().snapshots.clone());
    for args in [[hwnd,2,3,3],[hwnd,0x100000001,3,3],[hwnd,1,65536,65536],[0,1,3,3]]{
        assert_eq!(crate::caret_raw::dispatch(caret::CREATE_CARET_ORDINAL,args),Some(0));
        ENV.with(|e|assert_eq!(e.borrow().snapshots,before));
    }
    assert_eq!(hide_caret_for_current(hwnd,&mut Current),1);assert_eq!(show_caret_for_current(hwnd,&mut Current),1);
    ENV.with(|e|assert_eq!(e.borrow().snapshots.last().unwrap().1.mask,vec![0,0xffffff,0]));
}

#[test]fn signed_caret_extents_keep_geometry_but_crop_bitmap_source_at_zero(){
    let _serial=SERIAL.lock().unwrap();let(hwnd,_)=setup();
    for(width,height,extent,pixels)in[
        (-2,3,(1,3),vec![0,0xffffff,0]),(3,-2,(3,1),vec![0,0xffffff,0]),(-2,-2,(1,1),vec![0]),
    ]{
        assert_eq!(crate::caret_raw::dispatch(caret::CREATE_CARET_ORDINAL,[hwnd,1,width as u64,height as u64]),Some(1));
        assert_eq!(show_caret_for_current(hwnd,&mut Current),1);
        ENV.with(|e|{let e=e.borrow();let s=&e.snapshots.last().unwrap().1;
            assert_eq!((s.rect.x,s.rect.y,s.rect.width,s.rect.height),(5,20,extent.0,extent.1));assert_eq!(s.mask,pixels);});
        let rect=GUI.lock()[0].state.caret_placement().unwrap().1;
        assert_eq!((rect.right-rect.left,rect.bottom-rect.top),(width,height));
    }
}
