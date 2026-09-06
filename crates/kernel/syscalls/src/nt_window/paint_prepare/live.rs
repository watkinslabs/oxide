use super::{Prepared,Owner,finish,whole_window_covered};
use super::super::{GUI,paint_callbacks::Resources};
use alloc::sync::Arc;
use ipc::win32_window::{WindowId,WindowRect};
struct Current;
impl Owner for Current {
    fn commit(&mut self,p:Prepared,erase:bool)->Option<WindowRect>{
        let cur=sched::live::current().filter(|c|c.is_nt_personality()&&c.tid as u64==p.tid)?;
        let id=WindowId::from_raw(p.hwnd)?;
        let mut entries=GUI.lock();let entry=entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
        if entry.state.get(id)?.owner_tid!=p.tid{return None;}
        entry.state.validate_paint_session(id,p.dc).ok()?;
        entry.state.finish_paint_erase(id,p.dc,erase).ok()?;
        entry.state.paint_rect(id).ok()
    }
    fn copy(&mut self,destination:u64,bytes:&[u8])->bool{uaccess::copy_to_user(destination,bytes).is_ok()}
    fn retain(&mut self,p:Prepared)->bool{
        let Some((layout,region))=crate::nt_window::paint::presentation_for_current(p.hwnd)else{return false;};
        if region.is_empty(){return true;}
        crate::nt_gdi::retain_erase_for_current(p.hwnd,p.dc,&region,layout).is_ok()
    }
    fn abort(&mut self,p:Prepared){
        let Some(cur)=sched::live::current()else{return;};let Some(id)=WindowId::from_raw(p.hwnd)else{return;};
        let mut entries=GUI.lock();let Some(entry)=entries.iter_mut().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))else{return;};
        if entry.state.get(id).is_some_and(|record|record.owner_tid==p.tid){let _=entry.state.end_paint_session(id,p.dc);}
    }
    fn delete(&mut self,handle:u32){let _=crate::nt_gdi::delete_paint_dc_current(handle);}
}
/// Takes ownership of a fresh bound paint HDC and optional nonclient HRGN on every path.
/// Erase flags come from the canonical session; `run` retains Prepared in the existing callback queue.
/// # C: O(processes + windows + region); # Sleeps: yes (callbacks after unlock)
pub(crate) fn begin_for_current(hwnd:u32,dc:u32,destination:u64,nc_region:u32,
    run:fn(Resources,Prepared)->u64)->u64{
    let tid=sched::live::current().map_or(0,|c|c.tid as u64);
    let prepared=Prepared{hwnd,dc,destination,nc_region,tid};
    let snapshot=(||{
        if !prepared.valid(){return None;}
        let cur=sched::live::current().filter(|c|c.is_nt_personality())?;let id=WindowId::from_raw(hwnd)?;
        let entries=GUI.lock();let entry=entries.iter().find(|e|e.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
        if entry.state.get(id)?.owner_tid!=tid{return None;}
        let session=entry.state.validate_paint_session(id,dc).ok()?;
        let region=entry.state.paint_region(id).ok()?;
        // Nonclient damage requires the owner's real region (or validated whole-window sentinel).
        if session.nonclient&&!session.region.is_empty()&&nc_region==0{return None;}
        if session.nonclient&&nc_region==1{
            let bounds=entry.state.rect(id)?;let client=entry.state.get(id)?.client_rect.unwrap_or(bounds);
            let frame=WindowRect{left:bounds.left.checked_sub(client.left)?,top:bounds.top.checked_sub(client.top)?,
                right:bounds.right.checked_sub(client.left)?,bottom:bounds.bottom.checked_sub(client.top)?};
            if !whole_window_covered(&session.region,frame){return None;}
        }
        Some((Resources{hwnd:hwnd as u64,dc:dc as u64,nc_region:if session.nonclient{nc_region as u64}else{0},
            erase:session.erase,delayed:session.delayed_erase,empty_clip:region.is_empty()},region))
    })();
    let Some((resources,region))=snapshot else{prepared.discard(&mut Current);return 0;};
    if crate::nt_gdi::set_paint_region_for_current(dc as u64,region).is_err(){prepared.discard(&mut Current);return 0;}
    run(resources,prepared)
}
/// Existing callback queue calls exactly once on original sender after final Send or cancellation.
/// # C: O(processes + windows + usercopy)
pub(crate) fn finish_for_current(prepared:Prepared,result:Result<bool,()>)->u64{
    if !sched::live::current().is_some_and(|c|c.is_nt_personality()&&c.tid as u64==prepared.tid){return 0;}
    let result=finish(&mut Current,prepared,result);
    if result!=0{crate::nt_milestone::paint_begin();}
    result
}
/// Queue teardown drains owned payloads before GDI/MM teardown, without entering a user callback.
/// # C: O(processes + windows)
pub(crate) fn discard_for_current(prepared:Prepared){
    prepared.discard(&mut Current);
}
