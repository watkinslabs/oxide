//! Actual default-procedure dispatch; sent-message suspension is an explicit seam.
use super::*;
use ipc::win32_window::hardware::{WM_MOUSEACTIVATE, MA_ACTIVATE, MA_NOACTIVATE};
#[derive(Clone,Copy)]
pub(super) struct Continuation { pub token:u64, pub resume:fn(u64,Result<u64,()>)->u64 }
#[derive(Clone,Copy)]
pub(super) enum SendOutcome { Complete(u64), Failed, Pending }
pub(super) static SEND:Mutex<(SendOutcome,Option<Continuation>,Vec<(u64,u32,u64,u64)>)> = Mutex::new((SendOutcome::Failed,None,Vec::new()));
pub(super) fn send_resumable_current(hwnd:u64,message:u32,wparam:u64,lparam:u64,c:Continuation)->SendOutcome {
    assert!(nt_window::GUI.unlocked(), "parent procedure runs outside GUI lock");
    let mut state=SEND.lock().unwrap();state.1=Some(c);state.2.push((hwnd,message,wparam,lparam));state.0
}
fn run(hwnd:u64,hit:u16,message:u32)->Option<u64> {
    nt_window::production::dispatch(NtCall{service:nt::NtService::DefaultWindowProc,
        args:syscall::SyscallArgs{a0:hwnd,a1:WM_MOUSEACTIVATE as u64,a2:0xabc,
            a3:u64::from(hit)|(u64::from(message)<<16),a4:0,a5:0}})
}
pub(super) fn windows(child_style:bool)->(u64,u64){
    setup();let mut entries=nt_window::GUI.lock();let state=&mut entries[0].state;
    *state=WindowManager::new_in_block(ipc::win32_window::handle_space::FIRST_OWNER_BLOCK);
    let root=state.create(41,None,0x1234).unwrap();
    let child=state.create(41,Some(root),0x5678).unwrap();
    state.set_style_bits(child,if child_style{ipc::win32_window::styles::WS_CHILD}else{0},
        if child_style{0}else{ipc::win32_window::styles::WS_CHILD}).unwrap();
    *SEND.lock().unwrap()=(SendOutcome::Failed,None,Vec::new());(root.raw() as u64,child.raw() as u64)
}
#[test]
fn caption_left_down_defers_activation_but_client_and_other_buttons_activate(){
    let _serial=SERIAL.lock().unwrap();let(root,_)=windows(false);
    assert_eq!(run(root,2,ipc::win32_window::WM_LBUTTONDOWN),Some(MA_NOACTIVATE));
    assert_eq!(run(root,1,ipc::win32_window::WM_LBUTTONDOWN),Some(MA_ACTIVATE));
    assert_eq!(run(root,2,0x0204),Some(MA_ACTIVATE));
    assert!(SEND.lock().unwrap().2.is_empty());
}
#[test]
fn child_parent_result_preserves_veto_eat_and_all_lresult_bits(){
    let _serial=SERIAL.lock().unwrap();let(parent,child)=windows(true);
    for result in [1,2,3,4,u64::MAX] {
        SEND.lock().unwrap().0=SendOutcome::Complete(result);
        assert_eq!(run(child,1,ipc::win32_window::WM_LBUTTONDOWN),Some(result));
    }
    let state=SEND.lock().unwrap();assert_eq!(state.2.len(),5);
    for call in &state.2 {assert_eq!(*call,(parent,WM_MOUSEACTIVATE,0xabc,0x0201_0001));}
}
#[test]
fn zero_or_failed_parent_uses_child_fallback_and_owned_nonchild_does_not_forward(){
    let _serial=SERIAL.lock().unwrap();let(_,child)=windows(true);
    for outcome in [SendOutcome::Complete(0),SendOutcome::Failed] {
        SEND.lock().unwrap().0=outcome;
        assert_eq!(run(child,2,ipc::win32_window::WM_LBUTTONDOWN),Some(MA_NOACTIVATE));
    }
    let(_,owned)=windows(false);assert_eq!(run(owned,1,ipc::win32_window::WM_LBUTTONDOWN),Some(MA_ACTIVATE));
    assert!(SEND.lock().unwrap().2.is_empty());
}
#[test]
fn pending_parent_resumes_with_saved_fallback_without_a_second_send(){
    let _serial=SERIAL.lock().unwrap();let(_,child)=windows(true);
    SEND.lock().unwrap().0=SendOutcome::Pending;
    assert_eq!(run(child,2,ipc::win32_window::WM_LBUTTONDOWN),Some(0x103));
    let continuation=SEND.lock().unwrap().1.unwrap();
    for(result,expected)in[(Ok(0),MA_NOACTIVATE),(Err(()),MA_NOACTIVATE),(Ok(4),4)] {
        assert_eq!((continuation.resume)(continuation.token,result),expected);
    }
    assert_eq!(SEND.lock().unwrap().2.len(),1);
}

#[test]
fn combined_child_popup_style_uses_owner_as_the_parent_query_result(){
    let _serial=SERIAL.lock().unwrap();let(parent,child)=windows(true);
    let owner={let mut entries=nt_window::GUI.lock();let state=&mut entries[0].state;
        let id=WindowId::from_raw(child as u32).unwrap();
        state.set_style_bits(id,ipc::win32_window::styles::WS_POPUP,0).unwrap();
        let owner=state.create(41,None,0x9876).unwrap();state.set_popup_owner(id,Some(owner)).unwrap();owner.raw() as u64};
    SEND.lock().unwrap().0=SendOutcome::Complete(4);
    assert_eq!(run(child,1,ipc::win32_window::WM_LBUTTONDOWN),Some(4));
    let state=SEND.lock().unwrap();assert_ne!(parent,owner);assert_eq!(state.2[0].0,owner);
}
