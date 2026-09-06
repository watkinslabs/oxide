//! Position backing update runs after GUI commit and before bridge geometry publication.
use super::*;
use ipc::win32_window::WindowRect;

/// Pair order is destination/new then source/old, in HWND parent coordinates.
/// No new DC identity, GUI lock across GDI, or I/O under GDI ownership.
/// # C: O(processes + DCs + frame pixels); # Sleeps: client lifetime gate
pub(crate) fn position_preserve_for_current(hwnd:u32,old_window:WindowRect,new_window:WindowRect,valid:Option<[WindowRect;2]>,flags:u32)->Result<(),u64>{
    let current=sched::live::current().filter(|c|c.is_nt_personality()).ok_or(STATUS_INVALID_HANDLE)?;
    let _gate=lifecycle::ClientGate::acquire_current().map_err(|_|STATUS_INVALID_HANDLE)?;
    if crate::nt_window::window_rect_for_current(hwnd).map(|(rect,_)|rect)!=Some(new_window){return Err(STATUS_INVALID_HANDLE);}
    let projection={
        let mut entries=GDI.lock();
        let Some(entry)=entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(&current.thread_group)))else{return Ok(());};
        entry.state.preserve_window_position(hwnd,old_window,new_window,valid,flags).map_err(|error|match error{
            ipc::win32_gdi::GdiError::NoSuchObject=>STATUS_INVALID_HANDLE,_=>STATUS_INVALID_PARAMETER,
        })?;
        match(entry.client,entry.state.window_dc(hwnd)){
            (Some(binding),Some(dc))=>{let(width,height,_)=entry.state.surface(dc).ok_or(STATUS_INVALID_HANDLE)?;Some((binding,dc,width,height))},
            _=>None,
        }
    };
    if let Some((binding,dc,width,height))=projection{binding.update_dc_dimensions(dc,width,height).map_err(|_|STATUS_INVALID_HANDLE)?;}
    Ok(())
}
