//! DCE revocation and storage lifetime remain in the canonical GDI owner.
use super::*;

impl GdiManager {
    /// Application deletion of owned/class DCEs succeeds without removing state.
    /// Backing deletion revokes aliases before releasing its pixels. # C: O(DCs² + selected objects)
    pub fn delete_dc_object(&mut self, dc:u32)->Result<(),GdiError>{
        let state=&self.dcs.iter().find(|(id,_)|*id==dc).ok_or(GdiError::NoSuchObject)?.1;
        if state.lease.as_ref().is_some_and(|lease|lease.owner!=LeaseOwner::Cached){return Ok(());}
        self.revoke_matching(|lease|lease.backing==dc);
        let index=self.dcs.iter().position(|(id,_)|*id==dc).ok_or(GdiError::NoSuchObject)?;
        let (_,state)=self.dcs.remove(index);
        if let Some(region)=state.lease.and_then(|lease|lease.clip_handle){let _=self.delete_region(region);}
        self.window_dcs.retain(|(_,backing)|*backing!=dc);
        self.collect_lease_selections();Ok(())
    }

    /// A child may own leases into a surviving parent's backing. # C: O(DCs² + selected objects)
    pub fn revoke_window_leases(&mut self,hwnd:u32){
        self.revoke_matching(|lease|lease.hwnd==hwnd);
        self.collect_lease_selections();
    }

    /// Failed publication cannot leave even an owned DCE active or holding transferred HRGN.
    /// # C: O(DCs + selected objects)
    pub fn revoke_dc_lease(&mut self,dc:u32)->Result<(),GdiError>{
        let index=self.dcs.iter().position(|(id,state)|*id==dc&&state.lease.is_some()).ok_or(GdiError::NoSuchObject)?;
        let (_,state)=self.dcs.remove(index);
        if let Some(region)=state.lease.and_then(|lease|lease.clip_handle){let _=self.delete_region(region);}
        self.collect_lease_selections();Ok(())
    }

    fn revoke_matching(&mut self,mut matches:impl FnMut(&DcLease)->bool){
        let mut index=0;
        while index<self.dcs.len(){
            if self.dcs[index].1.lease.as_ref().is_some_and(&mut matches){
                let (_,state)=self.dcs.remove(index);
                if let Some(region)=state.lease.and_then(|lease|lease.clip_handle){let _=self.delete_region(region);}
            }else{index+=1;}
        }
    }
    fn collect_lease_selections(&mut self){self.collect_deleted_fonts();self.collect_deleted_brushes();self.collect_deleted_pens();}
}

#[cfg(test)]
#[path = "tests/lifetime.rs"]
mod tests;
