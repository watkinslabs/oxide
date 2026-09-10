//! Real default dispatcher and cursor policy; cursor installation is observed separately.
use super::*;
use mouse_activate_fixture::{SEND,SendOutcome};
use cursor_policy::SetCursorStep;
static DESKTOP:std::sync::atomic::AtomicU32=std::sync::atomic::AtomicU32::new(1);
pub(super) fn desktop()->u32{DESKTOP.load(std::sync::atomic::Ordering::Relaxed)}
static APPLIED:Mutex<Vec<SetCursorStep>>=Mutex::new(Vec::new());
pub(crate) fn apply_default_step(step:SetCursorStep)->u64 {
    assert!(nt_window::GUI.unlocked());APPLIED.lock().unwrap().push(step);0x1234
}
fn run(hwnd:u64,wparam:u64,hit:u16)->Option<u64>{
    nt_window::production::dispatch(NtCall{service:nt::NtService::DefaultWindowProc,
        args:syscall::SyscallArgs{a0:hwnd,a1:ipc::win32_window::WM_SETCURSOR as u64,a2:wparam,
            a3:0x0201_0000|u64::from(hit),a4:0,a5:0}})
}
fn setup_cursor(child:bool)->(u64,u64){DESKTOP.store(1,std::sync::atomic::Ordering::Relaxed);APPLIED.lock().unwrap().clear();mouse_activate_fixture::windows(child)}
#[test]
fn cursor_parent_acceptance_returns_true_and_never_installs_another_cursor(){
    let _serial=SERIAL.lock().unwrap();let(parent,child)=setup_cursor(true);
    for result in [1,2,0x1234,u64::MAX]{
        SEND.lock().unwrap().0=SendOutcome::Complete(result);
        assert_eq!(run(child,0xabc,1),Some(1));
    }
    assert!(APPLIED.lock().unwrap().is_empty());
    for request in &SEND.lock().unwrap().2{assert_eq!(*request,(parent,ipc::win32_window::WM_SETCURSOR,0xabc,0x0201_0001));}
}
#[test]
fn cursor_resize_borders_and_nonchildren_bypass_parent_and_discard_install_result(){
    let _serial=SERIAL.lock().unwrap();let(root,child)=setup_cursor(true);
    for hit in 10..=17{assert_eq!(run(child,child,hit),Some(0));}
    assert_eq!(run(root,root,1),Some(0));
    assert!(SEND.lock().unwrap().2.is_empty());assert_eq!(APPLIED.lock().unwrap().len(),9);
}
#[test]
fn pending_cursor_parent_preserves_full_class_handle_and_applies_only_after_decline(){
    let _serial=SERIAL.lock().unwrap();let(_,child)=setup_cursor(true);
    SEND.lock().unwrap().0=SendOutcome::Pending;
    let class_hwnd=u64::MAX-7;
    assert_eq!(run(child,class_hwnd,1),Some(0x103));assert!(APPLIED.lock().unwrap().is_empty());
    let c=SEND.lock().unwrap().1.unwrap();assert_eq!((c.resume)(c.token,Ok(5)),1);
    assert!(APPLIED.lock().unwrap().is_empty());
    assert_eq!((c.resume)(c.token,Ok(0)),0);
    assert_eq!(*APPLIED.lock().unwrap(),[SetCursorStep::ClassCursor{hwnd:class_hwnd,beep:false}]);
}
#[test]
fn failed_parent_applies_oem_step_and_keeps_error_beep_intent(){
    let _serial=SERIAL.lock().unwrap();let(_,child)=setup_cursor(true);
    SEND.lock().unwrap().0=SendOutcome::Pending;
    assert_eq!(run(child,child,(-2i16) as u16),Some(0x103));
    let c=SEND.lock().unwrap().1.unwrap();assert_eq!((c.resume)(c.token,Err(())),0);
    assert_eq!(*APPLIED.lock().unwrap(),[SetCursorStep::OemCursor{id:ipc::win32_window::IDC_ARROW,beep:true}]);
}

#[test]
fn desktop_parent_is_not_sent_a_cursor_request(){
    let _serial=SERIAL.lock().unwrap();let(parent,child)=setup_cursor(true);
    DESKTOP.store(parent as u32,std::sync::atomic::Ordering::Relaxed);
    SEND.lock().unwrap().0=SendOutcome::Complete(1);
    assert_eq!(run(child,child,1),Some(0));assert!(SEND.lock().unwrap().2.is_empty());
    assert_eq!(APPLIED.lock().unwrap().len(),1);
}

#[test]
fn immediate_parent_decline_or_failure_applies_class_cursor_and_returns_zero(){
    let _serial=SERIAL.lock().unwrap();let(_,child)=setup_cursor(true);
    for outcome in [SendOutcome::Complete(0),SendOutcome::Failed]{
        SEND.lock().unwrap().0=outcome;assert_eq!(run(child,child,1),Some(0));
    }
    assert_eq!(*APPLIED.lock().unwrap(),[SetCursorStep::ClassCursor{hwnd:child,beep:false};2]);
}
