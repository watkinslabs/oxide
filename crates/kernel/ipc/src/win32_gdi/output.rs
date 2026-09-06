//! Pending rendered output belongs to canonical backing, not GUI invalidation.
use super::{GdiManager,GdiError,Rect};
use alloc::vec::Vec;

#[derive(Clone,Copy,Debug,Default,Eq,PartialEq)]
pub struct PendingOutput { generation:u64, damage:Option<Rect>, in_flight:Option<OutputToken> }
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct OutputToken { pub hwnd:u32,pub dc:u32,pub generation:u64,pub damage:Rect }

impl PendingOutput {
    /// One operation's already-clipped backing bounds; no allocation. # C: O(1)
    pub(crate) fn record(&mut self,damage:Option<Rect>){
        let Some(rect)=damage.filter(|r|r.left<r.right&&r.top<r.bottom)else{return;};
        merge(&mut self.damage,rect);self.generation=self.generation.saturating_add(1);
    }
    /// Resizing invalidates old coordinates and any in-flight snapshot. # C: O(1)
    pub(crate) fn resized(&mut self,width:i32,height:i32){
        self.resized_with_redraw(width,height,true);
    }
    /// NOREDRAW retains prior output only within the new backing, never new damage. # C: O(1)
    pub(crate) fn resized_with_redraw(&mut self,width:i32,height:i32,redraw:bool){
        self.generation=self.generation.saturating_add(1);
        self.damage=if width<=0||height<=0{None}else if redraw{Some(Rect{left:0,top:0,right:width,bottom:height})}
        else{self.damage.map(|r|Rect{left:r.left.max(0),top:r.top.max(0),right:r.right.min(width),bottom:r.bottom.min(height)})
            .filter(|r|r.left<r.right&&r.top<r.bottom)};
    }
}

pub(super) fn merge(bounds:&mut Option<Rect>,rect:Rect){
    *bounds=Some(match *bounds{Some(old)=>Rect{left:old.left.min(rect.left),top:old.top.min(rect.top),
        right:old.right.max(rect.right),bottom:old.bottom.max(rect.bottom)},None=>rect});
}

impl GdiManager {
    /// Explicit presentation is output demand, not fabricated raster damage. # C: O(windows + DCs)
    pub fn request_output(&mut self,hwnd:u32,dc:u32)->Result<OutputToken,GdiError>{
        if self.window_dc(hwnd)!=Some(dc){return Err(GdiError::NoSuchObject);}
        let (_,state)=self.dcs.iter_mut().find(|(id,_)|*id==dc).ok_or(GdiError::NoSuchObject)?;
        if state.lease.is_some(){return Err(GdiError::NoSuchObject);}
        if state.width<=0||state.height<=0{return Err(GdiError::InvalidDimensions);}
        let damage=Rect{left:0,top:0,right:state.width,bottom:state.height};
        state.pending_output.record(Some(damage));
        Ok(OutputToken{hwnd,dc,generation:state.pending_output.generation,damage})
    }
    /// Reserve one backing submission under the same lock as frame capture. # C: O(windows + DCs)
    pub fn reserve_output(&mut self,token:OutputToken)->bool{
        if self.pending_output(token.hwnd,token.dc)!=Some(token){return false;}
        let Some((_,state))=self.dcs.iter_mut().find(|(id,_)|*id==token.dc)else{return false;};
        if state.pending_output.in_flight.is_some(){return false;}
        state.pending_output.in_flight=Some(token);true
    }
    /// Failed submission releases the reservation, never dirty coverage. # C: O(windows + DCs)
    pub fn finish_output(&mut self,token:OutputToken,presented:bool)->bool{
        if self.window_dc(token.hwnd)!=Some(token.dc){return false;}
        let Some((_,state))=self.dcs.iter_mut().find(|(id,_)|*id==token.dc)else{return false;};
        if state.pending_output.in_flight!=Some(token){return false;}
        state.pending_output.in_flight=None;
        presented&&self.acknowledge_output(token)
    }
    /// Only canonical window backing identities are eligible for publication. # C: O(windows × DCs)
    pub fn pending_outputs(&self)->Result<Vec<OutputToken>,GdiError>{
        let mut out=Vec::new();out.try_reserve(self.window_dcs.len()).map_err(|_|GdiError::HandleLimit)?;
        for &(hwnd,dc) in &self.window_dcs{if let Some(token)=self.pending_output(hwnd,dc){out.push(token);}}
        Ok(out)
    }
    /// Capture with pixels under the same owner lock; does not consume output. # C: O(windows + DCs)
    pub fn pending_output(&self,hwnd:u32,dc:u32)->Option<OutputToken>{
        if self.window_dc(hwnd)!=Some(dc){return None;}
        let state=&self.dcs.iter().find(|(id,_)|*id==dc)?.1;
        if state.lease.is_some()||state.width<=0||state.height<=0{return None;}
        Some(OutputToken{hwnd,dc,generation:state.pending_output.generation,damage:state.pending_output.damage?})
    }
    /// ACK never clears newer writes, resized storage, or a replacement backing. # C: O(windows + DCs)
    pub fn acknowledge_output(&mut self,token:OutputToken)->bool{
        if self.window_dc(token.hwnd)!=Some(token.dc){return false;}
        let Some((_,state))=self.dcs.iter_mut().find(|(id,_)|*id==token.dc)else{return false;};
        let pending=&mut state.pending_output;
        if pending.generation==u64::MAX||pending.generation!=token.generation||pending.damage!=Some(token.damage){return false;}
        pending.damage=None;true
    }
}

#[cfg(test)]
#[path = "tests/output.rs"]
mod tests;
#[cfg(test)]
#[path = "tests/output_raster.rs"]
mod raster_tests;
#[cfg(test)]
#[path = "tests/output_resize.rs"]
mod resize_tests;
