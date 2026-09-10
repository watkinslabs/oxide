use super::*;
use nt_window::scroll::control_proc;
use win32_window::{WindowId,WM_KEYDOWN,WM_KEYUP};
fn control(vertical:bool)->(u64,u64){
    let(_,parent)=setup();let id=WindowId::from_raw(parent as u32).unwrap();let mut entries=nt_window::GUI.lock();let state=&mut entries[0].state;
    let child=state.create(7,Some(id),0).unwrap();state.set_window_styles(child,win32_window::styles::WS_CHILD|vertical as u32,0).unwrap();
    state.set_rect(child,win32_window::WindowRect{left:0,top:0,right:40,bottom:80}).unwrap();
    state.initialize_scroll_control(child).unwrap();state.create_caret(7,child,2,2).unwrap();state.show_caret(7,Some(child)).unwrap();
    (parent,child.raw()as u64)
}
#[test]
fn keyboard_scroll_sends_parent_notification_and_discards_parent_result(){
    let _serial=TEST_LOCK.lock().unwrap();let(parent,hwnd)=control(true);
    assert_eq!(control_proc::for_current(hwnd,WM_KEYDOWN,0x28,0),Some(0));
    SEND_CALLS.with(|calls|assert_eq!(*calls.borrow(),vec![(parent,0x115,1,hwnd)]));
}

#[test]
fn all_navigation_keys_map_for_both_orientations_and_key_repeat_hides_caret_only_once(){
    let _serial=TEST_LOCK.lock().unwrap();
    for vertical in [false,true]{let(parent,hwnd)=control(vertical);
        for(key,code)in[(0x21,2),(0x22,3),(0x23,7),(0x24,6),(0x25,0),(0x26,0),(0x27,1),(0x28,1)]{
            CARET_CALLS.with(|calls|calls.borrow_mut().clear());SEND_CALLS.with(|calls|calls.borrow_mut().clear());
            assert_eq!(control_proc::for_current(hwnd,WM_KEYDOWN,key,1),Some(0));
            assert_eq!(control_proc::for_current(hwnd,WM_KEYDOWN,key,0x40000001),Some(0));
            CARET_CALLS.with(|calls|assert_eq!(*calls.borrow(),vec![(hwnd,false)]));
            let expected=(parent,if vertical{0x115}else{0x114},code,hwnd);
            SEND_CALLS.with(|calls|assert_eq!(*calls.borrow(),vec![expected,expected]));
            assert_eq!(control_proc::for_current(hwnd,WM_KEYUP,key,0xc0000001),Some(0));
            CARET_CALLS.with(|calls|assert_eq!(*calls.borrow(),vec![(hwnd,false),(hwnd,true)]));
            assert!(nt_window::GUI.lock()[0].state.set_caret_pos(7,4,5).unwrap().transition.new_visible);
        }
    }
}

#[test]
fn unknown_key_still_balances_caret_without_truncating_wparam_into_a_known_key(){
    let _serial=TEST_LOCK.lock().unwrap();let(_,hwnd)=control(true);
    for key in [0,0x41,0x1_0000_0028,u64::MAX]{
        assert_eq!(control_proc::for_current(hwnd,WM_KEYDOWN,key,0),Some(0));
        assert_eq!(control_proc::for_current(hwnd,WM_KEYUP,key,0),Some(0));
    }
    SEND_CALLS.with(|calls|assert!(calls.borrow().is_empty()));
    CARET_CALLS.with(|calls|assert_eq!(*calls.borrow(),[(hwnd,false),(hwnd,true)].repeat(4)));
}

#[test]
fn suspended_parent_scroll_returns_zero_only_when_send_completes(){
    let _serial=TEST_LOCK.lock().unwrap();let(_,hwnd)=control(true);SEND_PENDING.with(|pending|pending.set(true));
    assert_eq!(control_proc::for_current(hwnd,WM_KEYDOWN,0x28,0),Some(nt_window::STATUS_PENDING));
    let caller=SEND_CONT.with(|pending|pending.borrow_mut().take().unwrap());
    for result in [Ok(0),Ok(0x103),Ok(u64::MAX),Err(())]{assert_eq!((caller.resume)(caller.token,result),0);}
    CARET_CALLS.with(|calls|assert_eq!(*calls.borrow(),vec![(hwnd,false)]));
    assert_eq!(control_proc::for_current(hwnd,WM_KEYUP,0x28,0),Some(0));
}
