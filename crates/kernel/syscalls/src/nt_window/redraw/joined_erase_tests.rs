use super::*;
use win32_window::{WindowId,RDW_ERASE,RDW_ERASENOW,RDW_INVALIDATE,RDW_NOCHILDREN,RDW_UPDATENOW};

// Wine 10.20 dce.c erase_now: auxiliary callbacks leave client damage pending;
// NtUserRedrawWindow chooses UPDATENOW before ERASENOW.
#[test]
fn raw_erasenow_first_use_retains_pixels_without_beginpaint() {
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);
    assert_eq!(redraw::for_current(1,0,0,RDW_INVALIDATE|RDW_ERASE|RDW_ERASENOW|RDW_NOCHILDREN),STATUS_PENDING);
    let calls=CALLS.lock().unwrap().clone();assert_eq!(calls.len(),1);
    let(tid,hwnd,msg,dc,lp)=calls[0];assert_eq!((tid,hwnd,msg,lp),(2,1,0x14,0));
    GDI.lock().unwrap().fill_rect(dc as u32,win32_gdi::Rect{left:0,top:0,right:10,bottom:10},0xabcdef).unwrap();
    let callback=CALLBACK.with(|c|c.take().unwrap());
    assert_eq!(send::complete_callback(callback,1),1);
    assert!(!GDI.lock().unwrap().contains_object(dc as u32));
    let backing=nt_gdi::acquire_window_dc_for_current(1,10,10) as u32;
    assert!(GDI.lock().unwrap().pixels(backing).unwrap().iter().all(|p|*p==0xabcdef));
    assert_eq!(nt_gdi::release_window_dc_for_current(1,backing),0);
    let entries=GUI.lock();let id=WindowId::from_raw(1).unwrap();
    assert!(entries[0].state.paint_session(id).is_err());
    let pending=entries[0].state.erase_damage(id).unwrap();
    assert!(!pending.region.is_empty());assert!(!pending.erase);assert!(!pending.delayed_erase);
}

#[test]
fn raw_erasenow_cross_thread_runs_recipient_then_returns_sender_bool() {
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);
    let other=group.clone();
    let sender=std::thread::spawn(move||{current(&other,1);redraw::for_current(1,0,0,RDW_INVALIDATE|RDW_ERASE|RDW_ERASENOW|RDW_NOCHILDREN)});
    until(send::has_current);
    assert_eq!(send::pump_current(),Some(send::Outcome::Pending));
    let calls=CALLS.lock().unwrap().clone();assert_eq!(calls.len(),1);
    assert_eq!((calls[0].0,calls[0].1,calls[0].2),(2,1,0x14));
    let callback=CALLBACK.with(|c|c.take().unwrap());
    assert_eq!(send::complete_callback(callback,0),0x777);
    assert_eq!(sender.join().unwrap(),1);
    assert!(!GDI.lock().unwrap().contains_object(calls[0].3 as u32));
    assert!(GUI.lock()[0].state.erase_damage(WindowId::from_raw(1).unwrap()).unwrap().delayed_erase);
}

#[test]
fn raw_updatenow_wins_over_erasenow() {
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);
    assert_eq!(redraw::for_current(1,0,0,RDW_ERASENOW|RDW_UPDATENOW|RDW_NOCHILDREN),STATUS_PENDING);
    assert_eq!(*CALLS.lock().unwrap(),vec![(2,1,15,0,0)]);
    assert_eq!(complete_paint(1,0),1);
}

#[test]
fn raw_erasenow_allchildren_completes_both_without_consuming_parent_damage() {
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);
    assert_eq!(redraw::for_current(1,0,0,RDW_INVALIDATE|RDW_ERASE|RDW_ERASENOW|win32_window::RDW_ALLCHILDREN),STATUS_PENDING);
    // Inherited FRAME requests a real WM_NCPAINT for the child before erase.
    for (hwnd,msg) in [(1,0x14),(2,0x85),(2,0x14)] {
        let call=*CALLS.lock().unwrap().last().unwrap();assert_eq!((call.1,call.2),(hwnd,msg));
        let callback=CALLBACK.with(|c|c.take().unwrap());
        assert_eq!(send::complete_callback(callback,1),if (hwnd,msg)==(2,0x14){1}else{STATUS_PENDING});
    }
    for hwnd in [1,2]{assert!(!GUI.lock()[0].state.erase_damage(WindowId::from_raw(hwnd).unwrap()).unwrap().region.is_empty());}
}

#[test]
fn foreign_thread_disposal_releases_prepared_handles_without_resuming_sender() {
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,1);
    let dc=nt_gdi::create_paint_dc_for_current(10,10).unwrap();
    let region=win32_window::PaintRegion::from_rect(win32_window::WindowRect{left:0,top:0,right:10,bottom:10}).unwrap();
    let nc_region=nt_gdi::create_region_for_current(region.try_copy().unwrap()).unwrap();
    let client_region=nt_gdi::create_region_for_current(region).unwrap();
    let p=redraw::erase::ErasePrepared{hwnd:1,dc,nc_region,client_region,tid:1,redraw_token:71,
        layout:win32_gdi::PaintBacking{width:10,height:10,client:win32_gdi::Rect{left:0,top:0,right:10,bottom:10}}};
    current(&group,2);paint_callbacks::dispose_for_current(paint_callbacks::Completion::Erase(p));
    for h in [dc,nc_region,client_region]{assert!(!GDI.lock().unwrap().contains_object(h));}
    assert!(CALLBACK.with(|c|c.get()).is_none());assert!(CALLS.lock().unwrap().is_empty());
}

#[test]
fn raw_erase_cancel_keeps_live_dc_until_callback_returns_then_fails() {
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);
    assert_eq!(redraw::for_current(1,0,0,RDW_INVALIDATE|RDW_ERASE|RDW_ERASENOW|RDW_NOCHILDREN),STATUS_PENDING);
    let dc=CALLS.lock().unwrap()[0].3 as u32;
    paint_callbacks::cancel_window_current(1);
    assert!(GDI.lock().unwrap().contains_object(dc));
    let callback=CALLBACK.with(|c|c.take().unwrap());
    assert_eq!(send::complete_callback(callback,1),0);
    assert!(!GDI.lock().unwrap().contains_object(dc));
}

#[test]
fn raw_erase_geometry_change_rejects_old_surface_and_cleans_resources() {
    let _serial=SERIAL.lock().unwrap();let group=setup();current(&group,2);
    assert_eq!(redraw::for_current(1,0,0,RDW_INVALIDATE|RDW_ERASE|RDW_ERASENOW|RDW_NOCHILDREN),STATUS_PENDING);
    let dc=CALLS.lock().unwrap()[0].3 as u32;
    GUI.lock()[0].state.set_rect(WindowId::from_raw(1).unwrap(),win32_window::WindowRect{left:0,top:0,right:20,bottom:20}).unwrap();
    let callback=CALLBACK.with(|c|c.take().unwrap());
    assert_eq!(send::complete_callback(callback,1),0);
    assert!(!GDI.lock().unwrap().contains_object(dc));
}
