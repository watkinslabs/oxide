//! Generation-stamped RGB XOR presentation; canonical caret semantics stay outside transport.
use super::{Error,Rect,u32_at,u64_at};
use alloc::vec::Vec;
pub const HEADER_BYTES:usize=32;
pub const MAX_MASK_BYTES:usize=256*1024;
pub const RGB_XOR:u32=1;
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct Snapshot {pub generation:u64,pub rect:Rect,pub visible:bool,pub mask:Vec<u32>}
fn count(rect:Rect,visible:bool)->Result<usize,Error>{
    rect.validate_window()?;
    if !visible{return Ok(0);}
    rect.validate()?;
    let n=(rect.width as usize).checked_mul(rect.height as usize).ok_or(Error::Overflow)?;
    if n>MAX_MASK_BYTES/4{return Err(Error::Length);}Ok(n)
}
/// Validate before allocating an owned mask. # C: O(mask bytes)
pub fn validate_payload(p:&[u8])->Result<(),Error>{
    if p.len()<HEADER_BYTES||p.len()>HEADER_BYTES+MAX_MASK_BYTES{return Err(Error::Length);}
    if u64_at(p,0)?==0||u32_at(p,24)?>1||u32_at(p,28)?!=RGB_XOR{return Err(Error::Payload);}
    let rect=Rect::decode_window(&p[8..24])?;
    let n=count(rect,u32_at(p,24)?==1)?;
    if p.len()!=HEADER_BYTES+n*4{return Err(Error::Length);}
    if p[HEADER_BYTES..].chunks_exact(4).any(|pixel|pixel[3]!=0){return Err(Error::Payload);}Ok(())
}
impl Snapshot {
    /// Uniform invert caret; caller has already resolved the requested shape and dimensions. # C: O(rect pixels)
    pub fn solid(generation:u64,rect:Rect,visible:bool)->Result<Self,Error>{
        let n=count(rect,visible)?;let mut mask=Vec::new();mask.try_reserve_exact(n).map_err(|_|Error::Allocation)?;mask.resize(n,0x00ff_ffff);
        let s=Self{generation,rect,visible,mask};s.validate()?;Ok(s)
    }
    /// # C: O(mask pixels)
    pub fn validate(&self)->Result<(),Error>{
        if self.generation==0{return Err(Error::Payload);}
        if self.mask.len()!=count(self.rect,self.visible)?{return Err(Error::Length);}
        if self.mask.iter().any(|p|p&0xff00_0000!=0){return Err(Error::Payload);}Ok(())
    }
    /// # C: O(mask bytes)
    pub fn decode(p:&[u8])->Result<Self,Error>{
        validate_payload(p)?;let mut mask=Vec::new();
        mask.try_reserve_exact((p.len()-HEADER_BYTES)/4).map_err(|_|Error::Allocation)?;
        for bytes in p[HEADER_BYTES..].chunks_exact(4){mask.push(u32::from_le_bytes(bytes.try_into().map_err(|_|Error::Length)?));}
        Ok(Self{generation:u64_at(p,0)?,rect:Rect::decode_window(&p[8..24])?,visible:u32_at(p,24)?==1,mask})
    }
    /// # C: O(mask pixels)
    pub fn encode(&self)->Result<Vec<u8>,Error>{
        self.validate()?;let mut p=Vec::new();p.try_reserve_exact(HEADER_BYTES+self.mask.len()*4).map_err(|_|Error::Allocation)?;
        p.extend_from_slice(&self.generation.to_le_bytes());p.extend_from_slice(&self.rect.encode_window()?);
        p.extend_from_slice(&(self.visible as u32).to_le_bytes());p.extend_from_slice(&RGB_XOR.to_le_bytes());
        for pixel in &self.mask{p.extend_from_slice(&pixel.to_le_bytes());}Ok(p)
    }
}
#[cfg(test)]
#[path="tests/caret.rs"]mod tests;
