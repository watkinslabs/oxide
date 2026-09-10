//! Default mouse activation: parent response precedes caption/client policy.
use super::super::*;
use ipc::win32_window::hardware::{WM_MOUSEACTIVATE, default_mouse_activation};

/// # C: O(processes + windows + sends); # Sleeps: yes
pub(super) fn for_current(hwnd:u64,wparam:u64,lparam:i64)->u64 {
    let fallback=default_mouse_activation(lparam as u64);
    let Some(cur)=sched::live::current()else{return 0;};
    let Some(window)=valid_window(hwnd)else{return 0;};
    let parent={
        let entries=GUI.lock();
        let Some(entry)=entries.iter().find(|entry|entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))else{return 0;};
        let Some(record)=entry.state.get(window)else{return 0;};
        if record.style & ipc::win32_window::styles::WS_CHILD != 0 {entry.state.relative_parent(window)}else{None}
    };
    let Some(parent)=parent else{return fallback;};
    match send::send_resumable_current(parent.raw() as u64,WM_MOUSEACTIVATE,wparam,lparam as u64,
        send::Continuation{token:fallback,resume}) {
        send::SendOutcome::Complete(value)=>resume(fallback,Ok(value)),
        send::SendOutcome::Failed=>fallback,
        send::SendOutcome::Pending=>STATUS_PENDING,
    }
}

fn resume(fallback:u64,result:Result<u64,()>)->u64 {
    result.ok().filter(|value|*value!=0).unwrap_or(fallback)
}
