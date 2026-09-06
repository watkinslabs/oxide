//! Canonical session snapshot produces a real screen-space nonclient region before Send.
use alloc::sync::Arc;
use ipc::win32_window::{WindowId,WindowManager,WindowRect,PaintRegion};
use super::{Prepared,whole_window_covered};
use super::super::{GUI,paint_callbacks};

fn client_screen_origin(state:&WindowManager,id:WindowId)->Option<(i32,i32)>{
    let record=state.get(id)?;let own=record.client_rect.unwrap_or(state.rect(id)?);
    let (mut x,mut y)=(own.left,own.top);let mut parent=record.parent;let mut remaining=state.len();
    while let Some(id)=parent{
        remaining=remaining.checked_sub(1)?;
        let record=state.get(id)?;let client=record.client_rect.unwrap_or(state.rect(id)?);
        x=x.checked_add(client.left)?;y=y.checked_add(client.top)?;parent=record.parent;
    }Some((x,y))
}
enum Nonclient{None,Whole,Region(PaintRegion)}
/// Raw BeginPaint calls after canonical reservation and fresh HDC binding; owns HDC on all paths.
/// # C: O(processes + windows + region); # Sleeps: yes (allocation and Send outside GUI)
pub(crate) fn prepare_for_current(hwnd:u32,dc:u32,destination:u64)->u64{
    let tid=sched::live::current().map_or(0,|c|c.tid as u64);
    let mut prepared=Prepared{hwnd,dc,destination,nc_region:0,tid};
    let snapshot=(||{
        if !prepared.valid(){return None;}
        let cur=sched::live::current().filter(|c|c.is_nt_personality())?;let id=WindowId::from_raw(hwnd)?;
        let entries=GUI.lock();let entry=entries.iter().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
        let record=entry.state.get(id)?;if record.owner_tid!=tid{return None;}
        let session=entry.state.validate_paint_session(id,dc).ok()?;
        if !session.nonclient||session.region.is_empty(){return Some(Nonclient::None);}
        let bounds=entry.state.rect(id)?;let client=record.client_rect.unwrap_or(bounds);
        let frame=WindowRect{left:bounds.left.checked_sub(client.left)?,top:bounds.top.checked_sub(client.top)?,
            right:bounds.right.checked_sub(client.left)?,bottom:bounds.bottom.checked_sub(client.top)?};
        if whole_window_covered(&session.region,frame){return Some(Nonclient::Whole);}
        let (x,y)=client_screen_origin(&entry.state,id)?;
        Some(Nonclient::Region(session.region.translated(x,y).ok()?))
    })();
    prepared.nc_region=match snapshot{
        Some(Nonclient::None)=>0,Some(Nonclient::Whole)=>1,
        Some(Nonclient::Region(region))=>match crate::nt_gdi::create_region_for_current(region){Ok(handle)=>handle,Err(_)=>{super::live::discard_for_current(prepared);return 0;}},
        None=>{super::live::discard_for_current(prepared);return 0;}
    };
    super::live::begin_for_current(hwnd,dc,destination,prepared.nc_region,run)
}
fn run(resources:paint_callbacks::Resources,prepared:Prepared)->u64{
    paint_callbacks::for_current(resources,paint_callbacks::Completion::Paint(prepared))
}
