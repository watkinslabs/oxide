//! Cached-DC control redraw retains the original API result through the drawing callback.
use alloc::sync::Arc;
use ipc::win32_window::{WindowId,SB_CTL,ESB_ENABLE_BOTH,ESB_DISABLE_BOTH};
use crate::nt_window::{GUI,paint_callbacks,STATUS_PENDING};
use super::proc_abi::{DRAW_CALLBACK,REFRESH_COMPLETION};

/// WM_ENABLE synchronizes arrow state and redraws without changing window visibility.
/// # C: O(owner work + callback); # Sleeps: yes
pub(crate) fn enabled(hwnd:u64,enabled:bool)->u64{
    let flags=if enabled{ESB_ENABLE_BOTH}else{ESB_DISABLE_BOTH};
    if !super::bar_live::store_flags(hwnd,SB_CTL,flags){return 0;}
    for_current(hwnd,true,true,0)
}

/// Drawing is void; failure to obtain a DC cannot replace the original API result.
/// # C: O(owner work + callback); # Sleeps: yes
pub(crate) fn for_current(hwnd:u64,arrows:bool,interior:bool,result:u64)->u64{
    let Ok(hwnd)=u32::try_from(hwnd)else{return result;};
    let dc=crate::nt_gdi::get_dc_ex_for_current(hwnd,0,ipc::win32_gdi::DCX_CACHE) as u32;
    if dc==0{trace_failure(hwnd,0,b"dc");return result;}
    let Some(bytes)=super::control_draw::record(hwnd as u64,dc as u64,arrows,interior)else{discard(dc);return result;};
    let Some(token)=hold(hwnd,dc,result)else{discard(dc);trace_failure(hwnd,0,b"hold");return result;};
    let completion=sched::nt_callback::Completion{kind:REFRESH_COMPLETION,argument:token};
    let status=crate::nt_rtl::begin_user_callback(DRAW_CALLBACK,crate::nt_user_callback::Input::Record(&bytes),completion);
    if status==STATUS_PENDING{return status;}
    trace_failure(hwnd,status,b"callback");
    complete_callback(completion,status)
}

fn hold(hwnd:u32,dc:u32,result:u64)->Option<u64>{
    let cur=sched::live::current().filter(|cur|cur.is_nt_personality())?;
    let window=WindowId::from_raw(hwnd)?;
    let mut entries=GUI.lock();
    let entry=entries.iter_mut().find(|entry|entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
    entry.state.get(window)?;
    let resources=paint_callbacks::Resources{hwnd:hwnd as u64,dc:dc as u64,nc_region:0,erase:false,delayed:false,empty_clip:false};
    entry.paint_callbacks.hold(cur.tid as u64,resources,paint_callbacks::Completion::ControlRefresh{dc,result})
}

/// Callback return consumes only its sender-owned queue token, then releases DC outside GUI.
/// # C: O(processes + callbacks + DCs); # Sleeps: usercopy
pub(crate) fn complete_callback(completion:sched::nt_callback::Completion,_:u64)->u64{
    let Some(cur)=sched::live::current()else{return 0;};
    let held={let mut entries=GUI.lock();
        entries.iter_mut().find(|entry|entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))
            .and_then(|entry|entry.paint_callbacks.release_held(cur.tid as u64,completion.argument))};
    let Some((paint_callbacks::Completion::ControlRefresh{dc,result,..},_))=held else{return 0;};
    discard(dc);result
}

/// Cache release preserves canonical backing; revoked handles are already disposed by destruction.
/// # C: O(DCs + selected objects)
pub(crate) fn discard(dc:u32){let _=crate::nt_gdi::release_dc_lease_for_current(dc);}
fn trace_failure(hwnd:u32,status:u64,step:&'static[u8]){
    klog::write_raw(b"[WINDOWS-SCROLL-PAINT-FAIL] hwnd=");klog::write_hex_u64(hwnd as u64);
    klog::write_raw(b" step=");klog::write_raw(step);klog::write_raw(b" status=");klog::write_hex_u64(status);klog::write_raw(b"\n");
}
