//! Actual scrollbar procedure entry; sizegrip replies preserve cursor return values.
use super::*;
use nt_window::scroll::control_proc;
use win32_window::{WindowId,WM_SETCURSOR};

fn sizegrip(rtl:bool)->(Arc<thread_group::ThreadGroup>,u64){
    let(group,parent)=setup();
    let mut entries=nt_window::GUI.lock();let state=&mut entries[0].state;
    let parent=WindowId::from_raw(parent as u32).unwrap();
    let child=state.create(7,Some(parent),0).unwrap();
    state.set_window_styles(child,win32_window::styles::WS_CHILD|16,if rtl{win32_window::styles::WS_EX_LAYOUTRTL}else{0}).unwrap();
    state.initialize_scroll_control(child).unwrap();
    (group,child.raw() as u64)
}

#[test]
fn sizegrip_cursor_installs_diagonal_and_returns_previous_cursor(){
    let _serial=TEST_LOCK.lock().unwrap();let(_group,hwnd)=sizegrip(false);
    assert_eq!(control_proc::for_current(hwnd,WM_SETCURSOR,hwnd,0),Some(0x1234_5678_9abc_def0));
    CURSOR_CALLS.with(|calls|assert_eq!(*calls.borrow(),[win32_window::IDC_SIZENWSE]));
    let(_rtl_group,rtl)=sizegrip(true);
    assert_eq!(control_proc::for_current(rtl,WM_SETCURSOR,rtl,0),Some(0x1234_5678_9abc_def0));
    CURSOR_CALLS.with(|calls|assert_eq!(*calls.borrow(),[win32_window::IDC_SIZENESW]));
}

#[test]
fn sizegrip_click_sends_parent_size_command_and_discards_its_result(){
    let _serial=TEST_LOCK.lock().unwrap();
    for rtl in [false,true] {
        let(_group,hwnd)=sizegrip(rtl);let point=0xffff_ffff_aa55_cc33;
        let parent=nt_window::GUI.lock()[0].state.relative_parent(WindowId::from_raw(hwnd as u32).unwrap()).unwrap().raw() as u64;
        for message in [win32_window::WM_LBUTTONDOWN,win32_window::hardware::WM_LBUTTONDBLCLK] {
            assert_eq!(control_proc::for_current(hwnd,message,0,point),Some(0));
            SEND_CALLS.with(|calls|assert_eq!(calls.borrow().last(),Some(&(parent,win32_window::nonclient_menu::WM_SYSCOMMAND,if rtl{0xf007}else{0xf008},point))));
        }
        SEND_PENDING.with(|pending|pending.set(true));
        assert_eq!(control_proc::for_current(hwnd,win32_window::WM_LBUTTONDOWN,0,point),Some(nt_window::STATUS_PENDING));
        let caller=SEND_CONT.with(|pending|pending.borrow_mut().take().unwrap());
        assert_eq!((caller.resume)(caller.token,Ok(u64::MAX)),0);
        assert_eq!((caller.resume)(caller.token,Err(())),0);
    }
}

#[test]
fn ordinary_scrollbar_cursor_delegates_to_default_procedure(){
    let _serial=TEST_LOCK.lock().unwrap();let(_group,hwnd)=setup();
    assert_eq!(control_proc::for_current(hwnd,WM_SETCURSOR,hwnd,0),None);
    CURSOR_CALLS.with(|calls|assert!(calls.borrow().is_empty()));
}
