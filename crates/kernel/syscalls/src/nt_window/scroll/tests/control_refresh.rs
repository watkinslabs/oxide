use super::*;
use nt_window::scroll::{control_refresh as refresh,control_proc,bar_live,bar_raw};
use refresh_hosted::{STATE,latest,complete};
use win32_window::{WindowId,SB_CTL,ESB_DISABLE_BOTH,ESB_ENABLE_BOTH};

fn control(visible:bool)->u64{
    let(_,hwnd)=setup();let id=WindowId::from_raw(hwnd as u32).unwrap();let mut entries=nt_window::GUI.lock();
    entries[0].state.initialize_scroll_control(id).unwrap();entries[0].state.show(7,id,visible).unwrap();hwnd
}
fn word(bytes:&[u8],offset:usize)->u32{u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap())}
fn dc(call:&refresh_hosted::Call)->u32{u64::from_le_bytes(call.bytes[8..16].try_into().unwrap())as u32}

#[test]
fn actual_enable_route_retains_dc_through_drawing_and_returns_original_bool(){
    let _serial=TEST_LOCK.lock().unwrap();let hwnd=control(true);
    assert_eq!(bar_live::route(bar_raw::ENABLE_SCROLL_BAR,[hwnd,SB_CTL as u64,ESB_DISABLE_BOTH as u64,0]),Some(nt_window::STATUS_PENDING));
    let call=latest();let dc=dc(&call);assert_eq!(call.bytes.len(),104);
    assert_eq!(u64::from_le_bytes(call.bytes[..8].try_into().unwrap()),hwnd);
    assert_eq!((word(&call.bytes,16),word(&call.bytes,56),word(&call.bytes,60),word(&call.bytes,80)),(2,1,1,ESB_DISABLE_BOTH));
    STATE.with(|s|{let mut s=s.borrow_mut();assert_eq!(s.acquired,vec![(hwnd as u32,0,win32_gdi::DCX_CACHE)]);assert!(s.released.is_empty());
        s.gdi.write_dc_pixel(dc,3,4,0x123456).unwrap();});
    assert!(nt_window::GUI.lock()[0].paint_callbacks.holds_dc(dc));assert!(RASTER.with(|r|r.borrow().is_empty()));
    assert_eq!(complete(u64::MAX),1);assert!(!nt_window::GUI.lock()[0].paint_callbacks.holds_dc(dc));
    STATE.with(|s|{let mut s=s.borrow_mut();assert_eq!(s.released,vec![dc]);let backing=s.gdi.window_dc(hwnd as u32).unwrap();
        assert_eq!(s.gdi.pixels(backing).unwrap()[4*640+3],0x123456);assert!(s.gdi.write_dc_pixel(dc,3,4,0).is_err());});
    assert_eq!(complete(0),0);STATE.with(|s|assert_eq!(s.borrow().released,vec![dc]));
}

#[test]
fn refresh_parts_and_nested_callback_results_survive_without_a_second_registry(){
    let _serial=TEST_LOCK.lock().unwrap();let hwnd=control(true);
    assert_eq!(refresh::for_current(hwnd,true,false,u64::MAX),nt_window::STATUS_PENDING);let outer=latest();
    assert_eq!(refresh::for_current(hwnd,false,true,0x103),nt_window::STATUS_PENDING);let inner=latest();
    assert_ne!(outer.completion.argument,inner.completion.argument);assert_ne!(dc(&outer),dc(&inner));
    assert_eq!((word(&outer.bytes,56),word(&outer.bytes,60)),(1,0));assert_eq!((word(&inner.bytes,56),word(&inner.bytes,60)),(0,1));
    assert_eq!(nt_window::complete_callback(inner.completion,0),0x103);
    assert!(nt_window::GUI.lock()[0].paint_callbacks.holds_dc(dc(&outer)));
    assert_eq!(nt_window::complete_callback(outer.completion,123),u64::MAX);
}

#[test]
fn dc_and_callback_installation_failure_preserve_api_result_and_release_resources(){
    let _serial=TEST_LOCK.lock().unwrap();let hwnd=control(true);
    STATE.with(|s|s.borrow_mut().fail_dc=true);assert_eq!(refresh::for_current(hwnd,true,true,91),91);
    STATE.with(|s|{let mut s=s.borrow_mut();assert!(s.calls.is_empty());assert!(s.released.is_empty());s.fail_dc=false;s.fail_callback=true;});
    assert_eq!(refresh::for_current(hwnd,true,true,92),92);let call=latest();
    STATE.with(|s|assert_eq!(s.borrow().released,vec![dc(&call)]));
    assert!(!nt_window::GUI.lock()[0].paint_callbacks.holds_dc(dc(&call)));
}

#[test]
fn hidden_control_and_hidden_or_minimized_parent_do_not_invoke_drawing(){
    let _serial=TEST_LOCK.lock().unwrap();let hwnd=control(false);
    assert_eq!(refresh::for_current(hwnd,true,true,44),44);STATE.with(|s|{let s=s.borrow();assert!(s.calls.is_empty());assert_eq!(s.released.len(),1);});
    let hwnd=control(true);let parent=WindowId::from_raw(hwnd as u32).unwrap();
    let child={let mut entries=nt_window::GUI.lock();let state=&mut entries[0].state;let child=state.create(7,Some(parent),0).unwrap();
        state.initialize_scroll_control(child).unwrap();state.set_rect(child,win32_window::WindowRect{left:0,top:0,right:100,bottom:20}).unwrap();state.show(7,child,true).unwrap();state.show(7,parent,false).unwrap();child};
    assert_eq!(refresh::for_current(child.raw()as u64,true,true,45),45);
    {let mut entries=nt_window::GUI.lock();let state=&mut entries[0].state;state.show(7,parent,true).unwrap();state.set_style_bits(parent,0x20000000,0).unwrap();}
    assert_eq!(refresh::for_current(child.raw()as u64,true,true,46),46);STATE.with(|s|assert!(s.borrow().calls.is_empty()));
    let hwnd=control(true);let id=WindowId::from_raw(hwnd as u32).unwrap();
    nt_window::GUI.lock()[0].state.set_style_bits(id,0x20000000,0).unwrap();
    assert_eq!(refresh::for_current(hwnd,true,true,47),nt_window::STATUS_PENDING);assert_eq!(complete(0),47);
}

#[test]
fn wm_enable_changes_arrows_and_waits_for_refresh_without_mutating_visibility(){
    let _serial=TEST_LOCK.lock().unwrap();let hwnd=control(true);let id=WindowId::from_raw(hwnd as u32).unwrap();
    assert_eq!(control_proc::for_current(hwnd,0xa,0,0),Some(nt_window::STATUS_PENDING));
    {let entries=nt_window::GUI.lock();assert!(entries[0].state.is_enabled(id));assert!(entries[0].state.get(id).unwrap().visible);
        assert_eq!(entries[0].state.scroll_control_state(id).unwrap().flags,ESB_DISABLE_BOTH);}
    assert_eq!(complete(234),0);
    assert_eq!(control_proc::for_current(hwnd,0xa,1,0),Some(nt_window::STATUS_PENDING));
    assert_eq!(word(&latest().bytes,80),ESB_ENABLE_BOTH);assert_eq!(complete(u64::MAX),0);
}

#[test]
fn cancellation_and_foreign_thread_cannot_consume_another_refresh(){
    let _serial=TEST_LOCK.lock().unwrap();let hwnd=control(true);
    assert_eq!(refresh::for_current(hwnd,true,true,77),nt_window::STATUS_PENDING);let call=latest();
    let original=live::current().unwrap();let foreign=Box::leak(Box::new(Task{tid:8,thread_group:original.thread_group.clone()}));
    CURRENT.with(|c|*c.borrow_mut()=Some(foreign));assert_eq!(nt_window::complete_callback(call.completion,0),0);
    STATE.with(|s|assert!(s.borrow().released.is_empty()));CURRENT.with(|c|*c.borrow_mut()=Some(original));
    nt_window::GUI.lock()[0].paint_callbacks.cancel_window(hwnd);
    assert!(nt_window::GUI.lock()[0].paint_callbacks.take_window(hwnd).is_none());
    STATE.with(|s|s.borrow_mut().gdi.revoke_window_leases(hwnd as u32));
    assert_eq!(complete(999),77);assert_eq!(complete(999),0);STATE.with(|s|assert_eq!(s.borrow().released,vec![dc(&call)]));
}
