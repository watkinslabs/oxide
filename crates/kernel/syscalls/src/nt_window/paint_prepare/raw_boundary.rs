//! Production terminal preparation policy over the raw paint fixture's canonical owners.
use super::*;
pub(crate) mod caret {
    use super::*;
    pub(crate) fn begin_for_current(hwnd:u64)->bool{change(hwnd,false)}
    pub(crate) fn end_for_current(hwnd:u64)->bool{change(hwnd,true)}
    fn change(hwnd:u64,show:bool)->bool{
        let mut state=STATE.lock().unwrap();
        let window=if hwnd==0{None}else{let Some(id)=u32::try_from(hwnd).ok().and_then(WindowId::from_raw)else{return false;};Some(id)};
        let Some(tid)=state.windows.get(state.window).map(|record|record.owner_tid)else{return false;};
        // Raw Begin/EndPaint deliberately ignores NoCaret; no fabricated caret is created here.
        if show{state.windows.show_caret(tid,window).is_ok()}else{state.windows.hide_caret(tid,window).is_ok()}
    }
}
#[path="policy.rs"]mod policy;
struct Current;
impl policy::Owner for Current{
    fn commit(&mut self,p:policy::Prepared,erase:bool)->Option<WindowRect>{
        let mut state=STATE.lock().unwrap();let window=WindowId::from_raw(p.hwnd)?;
        if state.windows.get(window)?.owner_tid!=p.tid{return None;}
        state.windows.validate_paint_session(window,p.dc).ok()?;
        state.windows.finish_paint_erase(window,p.dc,erase).ok()?;
        state.windows.paint_rect(window).ok()
    }
    fn copy(&mut self,address:u64,bytes:&[u8])->bool{uaccess::copy_to_user(address,bytes).is_ok()}
    fn retain(&mut self,p:policy::Prepared)->bool{
        let Some(window)=WindowId::from_raw(p.hwnd)else{return false;};
        let state=STATE.lock().unwrap();
        let Ok(region)=state.windows.paint_region(window)else{return false;};
        if region.is_empty(){return true;}
        let Some(bounds)=state.windows.rect(window)else{return false;};
        let client=state.windows.get(window).and_then(|record|record.client_rect).unwrap_or(bounds);
        let layout=ipc::win32_gdi::PaintBacking{width:bounds.right-bounds.left,height:bounds.bottom-bounds.top,
            client:ipc::win32_gdi::Rect{left:client.left-bounds.left,top:client.top-bounds.top,
                right:client.right-bounds.left,bottom:client.bottom-bounds.top}};
        drop(state);
        nt_gdi::retain_erase_for_current(p.hwnd,p.dc,&region,layout).is_ok()
    }
    fn abort(&mut self,p:policy::Prepared){let mut state=STATE.lock().unwrap();let Some(window)=WindowId::from_raw(p.hwnd)else{return;};
        if state.windows.end_paint_session(window,p.dc).is_ok(){state.ended+=1;}}
    fn delete(&mut self,handle:u32){let mut state=STATE.lock().unwrap();if state.gdi.delete_object(handle).is_ok(){state.deletes+=1;}}
}
pub(crate) fn prepare_for_current(hwnd:u32,dc:u32,ps:u64)->u64{
    let tid={let state=STATE.lock().unwrap();WindowId::from_raw(hwnd).and_then(|id|state.windows.get(id)).map_or(0,|record|record.owner_tid)};
    let prepared=policy::Prepared{hwnd,dc,destination:ps,nc_region:0,tid,kernel:false};
    let snapshot={let state=STATE.lock().unwrap();WindowId::from_raw(hwnd).and_then(|id|{
        let session=state.windows.validate_paint_session(id,dc).ok()?;
        if session.nonclient||session.erase{return None;} // callback execution belongs to the joined preparation harness
        Some((state.windows.paint_region(id).ok()?,session.delayed_erase))
    })};
    let Some((region,delayed))=snapshot else{return policy::finish(&mut Current,prepared,Err(()));};
    if nt_gdi::set_paint_region_for_current(dc as u64,region).is_err(){return policy::finish(&mut Current,prepared,Err(()));}
    let result=policy::finish(&mut Current,prepared,Ok(delayed));
    if result!=0{nt_milestone::paint_begin();}result
}
