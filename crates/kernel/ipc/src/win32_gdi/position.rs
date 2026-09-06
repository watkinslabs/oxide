//! NCCALCSIZE preservation mutates only the existing canonical window backing.
use super::*;
use crate::win32_window::WindowRect;
const SWP_NOREDRAW:u32=0x0008;

impl GdiManager {
    /// Destination/source rectangles use new/old parent coordinates respectively.
    /// Validate and allocate before changing pixels, dimensions or output generation.
    /// Missing backing is a no-op: no pixels have been retained for this HWND.
    /// # C: O(DCs + new pixels + preserved pixels)
    pub fn preserve_window_position(&mut self,hwnd:u32,old:WindowRect,new:WindowRect,valid:Option<[WindowRect;2]>,flags:u32)->Result<(),GdiError>{
        let (ow,oh)=extent(old)?;let(nw,nh)=extent(new)?;
        let count=(nw as usize).checked_mul(nh as usize).filter(|n|*n<=MAX_SURFACE_PIXELS).ok_or(GdiError::InvalidDimensions)?;
        let pair=valid.map(|[dst,src]|{
            let dst=local(dst,new)?;let src=local(src,old)?;
            let (dw,dh)=extent(dst)?;let(sw,sh)=extent(src)?;
            if dw==0||dh==0||(dw,dh)!=(sw,sh)||dst.left<0||dst.top<0||dst.right>nw||dst.bottom>nh
                ||src.left<0||src.top<0||src.right>ow||src.bottom>oh{return Err(GdiError::InvalidDimensions);}
            Ok((dst,src,dw as usize,dh as usize))
        }).transpose()?;
        let Some(dc)=self.window_dc(hwnd)else{return Ok(());};
        let (_,state)=self.dcs.iter_mut().find(|(handle,_)|*handle==dc).ok_or(GdiError::NoSuchObject)?;
        if state.lease.is_some()||(state.width,state.height)!=(ow,oh){return Err(GdiError::InvalidDimensions);}
        if (ow,oh)==(nw,nh)&&pair.as_ref().is_none_or(|(dst,src,_,_)|dst==src){return Ok(());}
        let mut pixels=Vec::new();pixels.try_reserve_exact(count).map_err(|_|GdiError::InvalidDimensions)?;pixels.resize(count,0);
        if let Some((dst,src,width,height))=pair{
            for y in 0..height{
                let source=(src.top as usize+y)*ow as usize+src.left as usize;
                let destination=(dst.top as usize+y)*nw as usize+dst.left as usize;
                pixels[destination..destination+width].copy_from_slice(&state.pixels[source..source+width]);
            }
        }
        state.width=nw;state.height=nh;state.pixels=pixels;state.pending_output.resized_with_redraw(nw,nh,flags&SWP_NOREDRAW==0);Ok(())
    }
}
fn extent(r:WindowRect)->Result<(i32,i32),GdiError>{
    Ok((r.right.checked_sub(r.left).filter(|n|*n>=0).ok_or(GdiError::InvalidDimensions)?,r.bottom.checked_sub(r.top).filter(|n|*n>=0).ok_or(GdiError::InvalidDimensions)?))
}
fn local(r:WindowRect,origin:WindowRect)->Result<WindowRect,GdiError>{
    let sub=|a:i32,b:i32|a.checked_sub(b).ok_or(GdiError::InvalidDimensions);
    Ok(WindowRect{left:sub(r.left,origin.left)?,top:sub(r.top,origin.top)?,right:sub(r.right,origin.left)?,bottom:sub(r.bottom,origin.top)?})
}
#[cfg(test)]
#[path="tests/position.rs"]mod tests;
