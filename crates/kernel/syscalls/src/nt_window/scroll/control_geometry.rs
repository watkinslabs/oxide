//! Shared canonical scrollbar-control geometry for drawing and focus.
use alloc::sync::Arc;
use ipc::win32_window::WindowId;
use ipc::win32_gdi::{Rect,ScrollLayout,ScrollMetrics};
use crate::nt_window::GUI;
use super::proc_abi::{SBS_VERT,SM_CXVSCROLL};
pub(super) struct Geometry {pub rect:Rect,pub layout:ScrollLayout,pub style:u32,pub flags:u32,pub drawable:bool}

/// Geometry remains available for focus even if the control is hidden. # C: O(processes + windows²)
pub(super) fn for_current(hwnd:u64)->Option<Geometry>{
    let cur=sched::live::current().filter(|cur|cur.is_nt_personality())?;
    let window=u32::try_from(hwnd).ok().and_then(WindowId::from_raw)?;
    let(rect,style,state,drawable)={let entries=GUI.lock();
        let entry=entries.iter().find(|entry|entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
        let rect=entry.state.client_rect(window)?;
        (Rect{left:rect.left,top:rect.top,right:rect.right,bottom:rect.bottom},entry.state.get(window)?.style,
            entry.state.scroll_control_state(window).ok()?,entry.state.drawable(window))};
    let length=if style&SBS_VERT!=0{rect.bottom.checked_sub(rect.top)?}else{rect.right.checked_sub(rect.left)?};
    let layout=ipc::win32_gdi::scrollbar_layout(length,state,ScrollMetrics{arrow_size:ipc::win32_gdi::system_metric_default(SM_CXVSCROLL)?,dpi:96}).ok()?;
    Some(Geometry{rect,layout,style,flags:state.flags,drawable})
}
