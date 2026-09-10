//! Actual scrollbar enable route: window enabled state and visibility are independent.
use super::*;
use nt_window::scroll::{bar_live,bar_raw};
use win32_window::{SB_CTL,ESB_DISABLE_BOTH,ESB_ENABLE_BOTH,ESB_DISABLE_LTUP,WindowId};
fn control(visible:bool)->(Arc<thread_group::ThreadGroup>,u64){
    let(group,hwnd)=setup();let id=WindowId::from_raw(hwnd as u32).unwrap();
    let mut entries=nt_window::GUI.lock();
    entries[0].state.initialize_scroll_control_style(id,0).unwrap();
    entries[0].state.show(7,id,visible).unwrap();(group,hwnd)
}
fn enable(hwnd:u64,flags:u32)->Option<u64>{bar_live::route(bar_raw::ENABLE_SCROLL_BAR,[hwnd,SB_CTL as u64,flags as u64,0])}
fn state(hwnd:u64)->(bool,bool,u32){
    let entries=nt_window::GUI.lock();let state=&entries[0].state;let id=WindowId::from_raw(hwnd as u32).unwrap();
    (state.get(id).unwrap().visible,state.is_enabled(id),state.owned_scroll_state(id,SB_CTL).unwrap().flags)
}
#[test]
fn disabling_a_visible_control_keeps_it_visible_and_enabling_a_hidden_control_keeps_it_hidden(){
    let _serial=TEST_LOCK.lock().unwrap();let(_group,hwnd)=control(true);
    assert_eq!(enable(hwnd,ESB_DISABLE_BOTH),Some(1));
    assert_eq!(state(hwnd),(true,false,ESB_DISABLE_BOTH));
    assert_eq!(enable(hwnd,ESB_ENABLE_BOTH),Some(1));
    assert_eq!(state(hwnd),(true,true,ESB_ENABLE_BOTH));
    let(_hidden_group,hidden)=control(false);
    assert_eq!(enable(hidden,ESB_ENABLE_BOTH),Some(1));
    assert_eq!(state(hidden),(false,true,ESB_ENABLE_BOTH));
}
#[test]
fn partial_arrow_disable_preserves_enabled_state_and_explicit_show_still_changes_visibility(){
    let _serial=TEST_LOCK.lock().unwrap();let(_group,hwnd)=control(true);
    assert_eq!(enable(hwnd,ESB_DISABLE_BOTH),Some(1));
    assert_eq!(enable(hwnd,ESB_DISABLE_LTUP),Some(1));
    assert_eq!(state(hwnd),(true,false,ESB_DISABLE_LTUP));
    assert_eq!(bar_live::route(bar_raw::SHOW_SCROLL_BAR,[hwnd,SB_CTL as u64,0,0]),Some(1));
    assert_eq!(state(hwnd),(false,false,ESB_DISABLE_LTUP));
    assert_eq!(bar_live::route(bar_raw::SHOW_SCROLL_BAR,[hwnd,SB_CTL as u64,1,0]),Some(1));
    assert_eq!(state(hwnd),(true,false,ESB_DISABLE_LTUP));
}

#[test]
fn control_flags_are_separate_from_standard_bars_and_repeated_requests_succeed(){
    let _serial=TEST_LOCK.lock().unwrap();let(_group,hwnd)=control(true);
    let id=WindowId::from_raw(hwnd as u32).unwrap();
    assert_eq!(enable(hwnd,ESB_DISABLE_BOTH),Some(1));
    assert_eq!(enable(hwnd,ESB_DISABLE_BOTH),Some(1));
    let entries=nt_window::GUI.lock();let state=&entries[0].state;
    assert_eq!(state.owned_scroll_state(id,win32_window::SB_HORZ).unwrap().flags,ESB_ENABLE_BOTH);
    assert_eq!(state.owned_scroll_state(id,win32_window::SB_VERT).unwrap().flags,ESB_ENABLE_BOTH);
}
