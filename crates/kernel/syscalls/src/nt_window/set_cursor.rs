//! Parent-first default cursor handling through the existing Send continuation.
use super::super::*;
use crate::nt_wine_window::cursor_raw::{set_cursor_step,apply_default_step,SetCursorStep};
use ipc::win32_window::{WM_SETCURSOR,parent_gets_first_chance,split_lparam};

/// # C: O(processes + windows + sends); # Sleeps: yes
pub(super) fn for_current(hwnd:u64,wparam:u64,lparam:i64)->u64 {
    let Some(cur)=sched::live::current()else{return 0;};
    let Some(window)=valid_window(hwnd)else{return 0;};
    let parent={
        let entries=GUI.lock();
        let Some(entry)=entries.iter().find(|entry|entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))else{return 0;};
        let Some(record)=entry.state.get(window)else{return 0;};
        if record.style & ipc::win32_window::styles::WS_CHILD != 0 {entry.state.relative_parent(window)}else{None}
    };
    let step=set_cursor_step(wparam,lparam as u64);
    let Some(parent)=parent else{return finish(step,Ok(0));};
    if !parent_gets_first_chance(true,false,split_lparam(lparam as u64).0)
        || desktop::resolve_for_current()==Some(parent.raw()) {return finish(step,Ok(0));}
    let continuation=match step {
        SetCursorStep::ClassCursor{hwnd,..}=>send::Continuation{token:hwnd,resume:class},
        SetCursorStep::OemCursor{id,beep:false}=>send::Continuation{token:id as u64,resume:oem},
        SetCursorStep::OemCursor{id,beep:true}=>send::Continuation{token:id as u64,resume:alert_oem},
    };
    match send::send_resumable_current(parent.raw() as u64,WM_SETCURSOR,wparam,lparam as u64,continuation) {
        send::SendOutcome::Complete(value)=>finish(step,Ok(value)),
        send::SendOutcome::Failed=>finish(step,Err(())),
        send::SendOutcome::Pending=>STATUS_PENDING,
    }
}
fn finish(step:SetCursorStep,result:Result<u64,()>)->u64 {
    if result.is_ok_and(|value|value!=0){return 1;}
    let _=apply_default_step(step);0
}
fn class(hwnd:u64,result:Result<u64,()>)->u64 {finish(SetCursorStep::ClassCursor{hwnd,beep:false},result)}
fn oem(id:u64,result:Result<u64,()>)->u64 {finish(SetCursorStep::OemCursor{id:id as u32,beep:false},result)}
fn alert_oem(id:u64,result:Result<u64,()>)->u64 {finish(SetCursorStep::OemCursor{id:id as u32,beep:true},result)}
