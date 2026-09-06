//! Preparation resources travel in the existing callback completion, not another registry.
use ipc::win32_window::WindowRect;
use ipc::win32_window::PaintRegion;
const PAINT_PREFIX_BYTES:usize=28;
const WHOLE_WINDOW_REGION:u32=1;
/// Bounding boxes do not prove whole-window coverage; preserve holes and overflow failure.
/// # C: O(region rectangles * subtraction fragments)
pub(crate) fn whole_window_covered(region:&PaintRegion,window:WindowRect)->bool{
    if window.right<=window.left||window.bottom<=window.top{return false;}
    let Ok(mut missing)=PaintRegion::from_rect(window)else{return false;};
    missing.subtract(region).is_ok()&&missing.is_empty()
}
#[derive(Clone,Copy,Debug)]
pub(crate) struct Prepared {
    pub hwnd:u32,pub dc:u32,pub destination:u64,pub nc_region:u32,pub tid:u64,
}
pub(crate) trait Owner {
    /// Validate original owner and exact active HDC, then finish admitted erase flags.
    fn commit(&mut self,p:Prepared,erase:bool)->Option<WindowRect>;
    fn copy(&mut self,destination:u64,bytes:&[u8])->bool;
    /// Merge callback drawing from the temporary DC into the canonical window
    /// backing before a NULL-PAINTSTRUCT session is discarded.
    fn retain(&mut self,p:Prepared)->bool;
    /// Remove only a matching active session, never callback-time pending damage.
    fn abort(&mut self,p:Prepared);
    fn delete(&mut self,handle:u32);
}
impl Prepared {
    /// # C: O(1)
    pub(crate) fn valid(self)->bool{self.hwnd!=0&&self.dc!=0}
    /// Release only owned handles; HRGN=1 is a non-owning whole-window sentinel. # C: O(owner lookup)
    pub(crate) fn discard(self,owner:&mut impl Owner){
        owner.abort(self);
        if self.dc!=0{owner.delete(self.dc);}
        self.release_region(owner);
    }
    fn release_region(self,owner:&mut impl Owner){if self.nc_region>WHOLE_WINDOW_REGION&&self.nc_region!=self.dc{owner.delete(self.nc_region);}}
}
/// Terminal callback result only; pending sends never enter this function.
/// # C: O(owner lookup + usercopy)
pub(crate) fn finish(owner:&mut impl Owner,p:Prepared,result:Result<bool,()>)->u64{
    let result=(||{
        if !p.valid(){return None;}
        let erase=result.ok()?;let rect=owner.commit(p,erase)?;
        if p.destination==0 { let _=owner.retain(p); return None; }
        if p.destination.checked_add(PAINT_PREFIX_BYTES as u64-1).is_none(){return None;}
        let mut bytes=[0;PAINT_PREFIX_BYTES];bytes[..8].copy_from_slice(&(p.dc as u64).to_le_bytes());
        bytes[8..12].copy_from_slice(&u32::from(erase).to_le_bytes());
        for(i,n)in [rect.left,rect.top,rect.right,rect.bottom].into_iter().enumerate(){bytes[12+i*4..16+i*4].copy_from_slice(&n.to_le_bytes());}
        owner.copy(p.destination,&bytes).then_some(p.dc as u64)
    })();
    match result{Some(dc)=>{p.release_region(owner);dc},None=>{p.discard(owner);0}}
}
#[cfg(test)]
#[path="tests.rs"]mod tests;
