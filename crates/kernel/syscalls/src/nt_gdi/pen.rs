//! Canonical pen creation/selection through the existing client lifetime gate.
use super::*;
const PS_NULL:i32=5;
#[path="pen/shared.rs"]
mod shared;
#[path="pen/raster.rs"]
mod raster;
pub(crate) use raster::{pen_line_for_current,pen_rectangle_for_current};

/// Source API's brush argument is ignored; NULL_PEN is already projected stock state. # C: O(processes + pens)
pub(crate) fn create_pen_for_current(style:i32,width:i32,colorref:u32)->u64 {
    let Ok(_gate)=lifecycle::ClientGate::acquire_current() else {return 0;};
    if style==PS_NULL {return ipc::win32_gdi::stock_object(8).map_or(0,|p|u64::from(p.handle));}
    let Ok(color)=syscall::nt_gdi_client::colorref_to_xrgb(colorref) else {return 0;};
    let Some(current)=sched::live::current() else {return 0;};
    let group=Arc::clone(&current.thread_group);
    let bound={let mut entries=GDI.lock();
        let Ok(index)=lifecycle::entry_for_current(&mut entries,&group) else {return 0;};entries[index].client.is_some()};
    let pid=if bound {let Ok(pid)=client::current_process_id() else {return 0;};Some(pid)}else{None};
    let (binding,handle)={
        let mut entries=GDI.lock();let Ok(index)=lifecycle::entry_for_current(&mut entries,&group) else {return 0;};
        let Ok(handle)=entries[index].state.create_pen(style,width,color) else {return 0;};
        (entries[index].client,handle)
    };
    if let (Some(binding),Some(pid))=(binding,pid) {
        if lifecycle::publish_or_rollback(binding,handle,||binding.publish_handle(handle,pid),||{
            let mut entries=GDI.lock();let index=lifecycle::entry_for_current(&mut entries,&group).map_err(|_|ipc::win32_gdi::GdiError::NoSuchObject)?;
            entries[index].state.delete_pen(handle)
        }).is_err(){return 0;}
    }
    u64::from(handle)
}

/// Drop final pending-deletion projections only after canonical selection completes. # C: O(objects + pens * DCs)
pub(crate) fn select_pen_for_current(dc:u64,pen:u64)->u64 {
    let (Ok(dc),Ok(pen))=(u32::try_from(dc),u32::try_from(pen)) else {return 0;};
    let Ok(_gate)=lifecycle::ClientGate::acquire_current() else {return 0;};
    let Some(current)=sched::live::current() else {return 0;};
    let (binding,previous,removed)={
        let mut entries=GDI.lock();
        let Some(entry)=entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(&current.thread_group))) else {return 0;};
        let before=entry.state.live_handles();
        let Ok(previous)=entry.state.select_pen(dc,pen) else {return 0;};
        let after=entry.state.live_handles();
        (entry.client,previous,before.into_iter().filter(|h|!after.contains(h)).collect::<Vec<_>>())
    };
    if let Some(binding)=binding {for handle in removed {if binding.delete_handle(handle).is_err(){return 0;}}}
    u64::from(previous)
}
