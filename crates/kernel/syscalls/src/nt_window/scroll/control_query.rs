//! Control range/position queries consume the HWND-owned state without drawing or messages.
use alloc::sync::Arc;
use ipc::win32_window::{ScrollState,WindowId};
use crate::nt_window::GUI;

fn snapshot(hwnd:u64)->Option<ScrollState>{
    let cur=sched::live::current().filter(|cur|cur.is_nt_personality())?;
    let window=u32::try_from(hwnd).ok().and_then(WindowId::from_raw)?;
    let entries=GUI.lock();
    let entry=entries.iter().find(|entry|entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
    entry.state.scroll_control_state(window).ok()
}

/// Preserve signed position in the full LRESULT. # C: O(processes + windows)
pub(crate) fn position(hwnd:u64)->u64{snapshot(hwnd).map_or(0,|state|state.pos as i64 as u64)}

/// Optional destinations are written minimum first, maximum second, outside GUI.
/// # C: O(processes + windows + bounded usercopy); # Sleeps: usercopy
pub(crate) fn range(hwnd:u64,min:u64,max:u64)->u64{
    let Some(state)=snapshot(hwnd)else{return 0;};
    if min!=0&&uaccess::copy_to_user(min,&state.min.to_le_bytes()).is_err(){return 0;}
    if max!=0&&uaccess::copy_to_user(max,&state.max.to_le_bytes()).is_err(){return 0;}
    1
}
