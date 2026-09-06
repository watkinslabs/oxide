use super::*;
use ipc::win32_window::{WindowId,WindowRect,WindowPosition,RDW_INVALIDATE,RDW_ERASE,RDW_FRAME};
fn setup(flags:u32)->(u32,u32){
    let group=Arc::new(thread_group::ThreadGroup);ENV.with(|e|*e.borrow_mut()=Env{task:Some(Task{tid:7,thread_group:group.clone()}),..Default::default()});
    let mut state=WindowManager::new();let id=state.create(7,None,0).unwrap();
    state.apply_position(7,WindowPosition{window:id,rect:WindowRect{left:0,top:0,right:10,bottom:10},client:None,order:None,visible:None,flags:0x10,notify_geometry:false}).unwrap();
    if flags!=0{let region=PaintRegion::from_rect(WindowRect{left:0,top:0,right:2,bottom:2}).unwrap();state.redraw_damage(id,Some(&region),flags,false).unwrap();}
    state.begin_paint(id).unwrap();let mut gdi=GdiManager::new();let dc=gdi.create_dc(10,10).unwrap();state.bind_paint_dc(id,dc).unwrap();
    *GDI.lock().unwrap()=Some(gdi);*GUI.lock()=vec![Entry{group:Arc::downgrade(&group),state,paint_callbacks:paint_callbacks::Queue::new(),sent:send::Queue::new()}];(id.raw(),dc)
}
#[test]fn actual_begin_installs_exact_clip_then_only_final_callback_writes_paintstruct(){
    let _serial=SERIAL.lock().unwrap();let (hwnd,dc)=setup(RDW_INVALIDATE|RDW_ERASE);
    assert_eq!(paint_prepare::begin_for_current(hwnd,dc,4096,0,run),0x103);
    let (resources,p)=ENV.with(|e|{let e=e.borrow();assert!(e.bytes.is_empty());e.pending.unwrap()});
    assert!(resources.erase);assert!(!resources.delayed);assert!(!resources.empty_clip);assert_eq!(resources.dc,dc as u64);
    assert_eq!(paint_prepare::finish_for_current(p,Ok(false)),dc as u64);
    ENV.with(|e|assert_eq!(u32::from_le_bytes(e.borrow().bytes[8..12].try_into().unwrap()),0));
    assert!(GUI.lock()[0].state.validate_paint_session(WindowId::from_raw(hwnd).unwrap(),dc).is_ok());
}
#[test]fn actual_empty_clip_keeps_delayed_separate_and_retiring_cleanup_releases_dc(){
    let _serial=SERIAL.lock().unwrap();let (hwnd,dc)=setup(0);
    GUI.lock()[0].state.finish_paint_erase(WindowId::from_raw(hwnd).unwrap(),dc,true).unwrap();
    assert_eq!(paint_prepare::begin_for_current(hwnd,dc,4096,0,run),0x103);
    let (r,p)=ENV.with(|e|e.borrow().pending.unwrap());assert!(!r.erase);assert!(r.delayed);assert!(r.empty_clip);
    paint_prepare::discard_for_current(p);assert!(delete_paint_dc_current(dc).is_err());
    assert!(GUI.lock()[0].state.paint_session(WindowId::from_raw(hwnd).unwrap()).is_err());
}
#[test]fn actual_partial_nonclient_cannot_use_whole_window_sentinel(){
    let _serial=SERIAL.lock().unwrap();let (hwnd,dc)=setup(RDW_INVALIDATE|RDW_FRAME);
    assert_eq!(paint_prepare::begin_for_current(hwnd,dc,4096,1,run),0);
    assert!(ENV.with(|e|e.borrow().pending.is_none()));assert!(delete_paint_dc_current(dc).is_err());
}
fn return_send(result:Result<u64,()>)->u64{
    send::return_callback(result)
}
#[test]fn factory_partial_nc_uses_real_region_then_erase_and_terminal_milestone(){
    let _serial=SERIAL.lock().unwrap();let(hwnd,dc)=setup(RDW_INVALIDATE|RDW_ERASE|RDW_FRAME);
    assert_eq!(paint_prepare::prepare_for_current(hwnd,dc,4096),STATUS_PENDING);
    let region=ENV.with(|e|{let e=e.borrow();assert_eq!(e.milestones,0);assert!(e.bytes.is_empty());assert_eq!(e.messages[0].1,0x85);e.messages[0].2 as u32});
    assert!(region>1);assert_eq!(GDI.lock().unwrap().as_ref().unwrap().region_snapshot(region).unwrap().bounds(),Some(WindowRect{left:0,top:0,right:2,bottom:2}));
    assert_eq!(return_send(Ok(u64::MAX)),STATUS_PENDING);ENV.with(|e|assert_eq!(e.borrow().messages[1].1,0x14));
    assert_eq!(return_send(Ok(STATUS_PENDING)),dc as u64);
    ENV.with(|e|assert_eq!(e.borrow().milestones,1));assert!(GDI.lock().unwrap().as_ref().unwrap().region_snapshot(region).is_err());
}
#[test]fn foreign_destroy_keeps_active_resources_until_callback_returns_failed(){
    let _serial=SERIAL.lock().unwrap();let(hwnd,dc)=setup(RDW_INVALIDATE|RDW_ERASE|RDW_FRAME);
    assert_eq!(paint_prepare::prepare_for_current(hwnd,dc,4096),STATUS_PENDING);
    ENV.with(|e|e.borrow_mut().task.as_mut().unwrap().tid=8);
    {let mut entries=GUI.lock();entries[0].state.destroy(WindowId::from_raw(hwnd).unwrap()).unwrap();entries[0].paint_callbacks.cancel_window(hwnd as u64);}
    paint_callbacks::cancel_window_current(hwnd as u64);
    send::cancel_window(hwnd as u64);assert!(send::reply_pending());
    assert!(GUI.lock()[0].paint_callbacks.holds_dc(dc));
    assert!(GUI.lock()[0].paint_callbacks.take_window(hwnd as u64).is_none());
    ENV.with(|e|e.borrow_mut().task.as_mut().unwrap().tid=7);
    assert_eq!(return_send(Ok(1)),0);assert!(delete_paint_dc_current(dc).is_err());
    ENV.with(|e|{let e=e.borrow();assert_eq!(e.messages.len(),1);assert_eq!(e.milestones,0);assert!(e.bytes.is_empty());});
}
#[test]fn erase_foreign_destroy_and_recipient_exit_do_not_release_active_nc_resources_early(){
    let _serial=SERIAL.lock().unwrap();
    for recipient_exit in [false,true]{
        let(hwnd,_)=setup(0);let id=WindowId::from_raw(hwnd).unwrap();
        let region=PaintRegion::from_rect(WindowRect{left:0,top:0,right:2,bottom:2}).unwrap();
        GUI.lock()[0].state.redraw_damage(id,Some(&region),RDW_INVALIDATE|RDW_ERASE|RDW_FRAME,false).unwrap();
        ENV.with(|e|e.borrow_mut().task.as_mut().unwrap().tid=8);
        assert_eq!(redraw::erase::begin_for_current(hwnd,73),STATUS_PENDING);
        let nc=ENV.with(|e|e.borrow().messages[0].2 as u32);
        {let mut entries=GUI.lock();entries[0].state.destroy(id).unwrap();entries[0].paint_callbacks.cancel_window(hwnd as u64);}
        paint_callbacks::cancel_window_current(hwnd as u64);send::cancel_window(hwnd as u64);
        assert!(send::reply_pending());assert!(GDI.lock().unwrap().as_ref().unwrap().contains_object(nc));
        if recipient_exit{send::cancel_sender(7);assert!(!send::reply_pending());}
        assert_eq!(return_send(Ok(u64::MAX)),73);
        assert!(!GDI.lock().unwrap().as_ref().unwrap().contains_object(nc));
        paint_callbacks::cancel_window_current(hwnd as u64);
        ENV.with(|e|{let e=e.borrow();assert_eq!(e.messages.len(),1);assert_eq!(e.erase_finished,vec![(73,Err(()))]);
            assert_eq!(e.deletions.iter().filter(|h|**h==nc).count(),1);});
    }
}
#[test]fn factory_install_failure_and_thread_exit_release_owned_payloads(){
    let _serial=SERIAL.lock().unwrap();
    for fail in [false,true]{let(hwnd,dc)=setup(RDW_INVALIDATE|RDW_ERASE);
        ENV.with(|e|e.borrow_mut().fail_send=fail);
        assert_eq!(paint_prepare::prepare_for_current(hwnd,dc,4096),if fail{0}else{STATUS_PENDING});
        if !fail{paint_callbacks::cancel_current_thread();assert_eq!(return_send(Ok(0)),0);}
        assert!(delete_paint_dc_current(dc).is_err());ENV.with(|e|assert_eq!(e.borrow().milestones,0));
    }
}
#[test]fn immediate_erase_lresult_103_is_completion_not_pending_and_zero_retains_erase(){
    let _serial=SERIAL.lock().unwrap();
    for value in [0,STATUS_PENDING,u64::MAX]{let(hwnd,dc)=setup(RDW_INVALIDATE|RDW_ERASE);
        ENV.with(|e|e.borrow_mut().immediate=Some(value));
        assert_eq!(paint_prepare::prepare_for_current(hwnd,dc,4096),dc as u64);
        ENV.with(|e|{let e=e.borrow();assert_eq!(e.milestones,1);assert!(e.send.is_none());
            assert_eq!(u32::from_le_bytes(e.bytes[8..12].try_into().unwrap()),u32::from(value==0));});
    }
}
#[test]fn nested_child_nc_region_uses_canonical_screen_client_origin(){
    let _serial=SERIAL.lock().unwrap();let(parent,_)=setup(0);
    let child={let mut entries=GUI.lock();let state=&mut entries[0].state;
        state.apply_position(7,WindowPosition{window:WindowId::from_raw(parent).unwrap(),rect:WindowRect{left:100,top:200,right:140,bottom:240},client:Some(WindowRect{left:105,top:210,right:135,bottom:235}),order:None,visible:None,flags:0x10,notify_geometry:false}).unwrap();
        let child=state.create(7,WindowId::from_raw(parent),0).unwrap();
        state.apply_position(7,WindowPosition{window:child,rect:WindowRect{left:5,top:6,right:15,bottom:16},client:Some(WindowRect{left:7,top:9,right:14,bottom:15}),order:None,visible:None,flags:0x10,notify_geometry:false}).unwrap();
        let region=PaintRegion::from_rect(WindowRect{left:0,top:0,right:2,bottom:2}).unwrap();
        state.redraw_damage(child,Some(&region),RDW_INVALIDATE|RDW_FRAME,false).unwrap();state.begin_paint(child).unwrap();child
    };
    let dc=GDI.lock().unwrap().as_mut().unwrap().create_dc(10,10).unwrap();GUI.lock()[0].state.bind_paint_dc(child,dc).unwrap();
    assert_eq!(paint_prepare::prepare_for_current(child.raw(),dc,4096),STATUS_PENDING);
    let region=ENV.with(|e|e.borrow().messages[0].2 as u32);
    assert_eq!(GDI.lock().unwrap().as_ref().unwrap().region_snapshot(region).unwrap().bounds(),Some(WindowRect{left:112,top:219,right:114,bottom:221}));
    paint_callbacks::cancel_current_thread();
}
#[test]fn erase_payload_terminal_disposal_and_cross_thread_admission_use_erase_owner(){
    let _serial=SERIAL.lock().unwrap();let(hwnd,_)=setup(0);
    let id=WindowId::from_raw(hwnd).unwrap();let region=PaintRegion::from_rect(WindowRect{left:0,top:0,right:2,bottom:2}).unwrap();
    GUI.lock()[0].state.redraw_damage(id,Some(&region),RDW_INVALIDATE|RDW_ERASE,false).unwrap();
    ENV.with(|e|e.borrow_mut().task.as_mut().unwrap().tid=8);
    assert_eq!(redraw::erase::begin_for_current(hwnd,71),STATUS_PENDING);
    assert_eq!(return_send(Ok(0)),71);ENV.with(|e|assert_eq!(e.borrow().erase_finished,vec![(71,Ok(0))]));
    GUI.lock()[0].state.redraw_damage(id,Some(&region),RDW_INVALIDATE|RDW_ERASE,false).unwrap();
    assert_eq!(redraw::erase::begin_for_current(hwnd,72),STATUS_PENDING);
    let dc=ENV.with(|e|e.borrow().messages.last().unwrap().2 as u32);
    paint_callbacks::cancel_current_thread();send::cancel_sender(8);
    assert!(send::reply_pending());assert!(GUI.lock()[0].paint_callbacks.holds_dc(dc));
    assert!(GDI.lock().unwrap().as_ref().unwrap().contains_object(dc));
    ENV.with(|e|e.borrow_mut().task.as_mut().unwrap().tid=7);
    assert_eq!(return_send(Ok(1)),0);assert!(!GDI.lock().unwrap().as_ref().unwrap().contains_object(dc));
    paint_callbacks::reap_retired_current();paint_callbacks::cancel_window_current(hwnd as u64);
    ENV.with(|e|{let e=e.borrow();assert_eq!(e.erase_finished.len(),1);assert_eq!(e.deletions.iter().filter(|h|**h==dc).count(),1);});
}
