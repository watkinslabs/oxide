//! Stroke coverage consumes the canonical lease-aware raster target; 31fk§8.
use super::{GdiManager,GdiError,Pen,PS_NULL,PS_SOLID,PS_INSIDEFRAME,coverage};
use crate::win32_gdi::{Rect,BrushStyle};
use crate::win32_gdi::dc_lease::DcRaster;
const RGB:u32=0xffffff;

#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct PenRasterState {
    pub position:(i32,i32),pub rop:u16,pub clockwise:bool,
    pub pen_color:u32,pub brush_color:u32,pub background:u32,pub opaque:bool,
}
impl GdiManager {
    /// Unbound DC defaults; bound callers supply admitted shared attributes. # C: O(DCs)
    pub fn pen_raster_state(&self,dc:u32)->Result<PenRasterState,GdiError>{
        let state=&self.dcs.iter().find(|(id,_)|*id==dc).ok_or(GdiError::NoSuchObject)?.1;
        state.ensure_active()?;
        let text=self.text_state(dc)?.attributes;
        Ok(PenRasterState{position:text.current_position,rop:13,clockwise:false,
            pen_color:state.dc_pen_color,brush_color:state.dc_brush_color,
            background:text.background,opaque:text.background_mode==2})
    }
    /// Endpoint position commits only after successful drawing; shared callers own their copyout.
    /// # C: O(DCs + pens + visible major-axis span)
    pub fn pen_line_to(&mut self,dc:u32,end:(i32,i32),shared:Option<PenRasterState>)->Result<(),GdiError>{
        let state=shared.unwrap_or(self.pen_raster_state(dc)?);
        let pen=self.stroke_pen(dc,state)?;
        let mut target=self.raster_dc(dc)?;
        stroke(&mut target,pen,state,state.position,end,0)?;
        drop(target);
        if shared.is_none(){self.set_text_position(dc,end)?;}
        Ok(())
    }
    /// Rectangle never changes current position. # C: O(DCs + objects + clipped area)
    pub fn pen_rectangle(&mut self,dc:u32,rect:Rect,shared:Option<PenRasterState>)->Result<(),GdiError>{
        let state=shared.unwrap_or(self.pen_raster_state(dc)?);
        let pen=self.stroke_pen(dc,state)?;
        let dc_state=&self.dcs.iter().find(|(id,_)|*id==dc).ok_or(GdiError::NoSuchObject)?.1;
        let brush=self.brush_style(dc_state.brush.unwrap_or(self.stock_object(0).ok_or(GdiError::NoSuchObject)?.handle),state.brush_color)?;
        let (left,right)=(rect.left.min(rect.right),rect.left.max(rect.right));
        let (top,bottom)=(rect.top.min(rect.bottom),rect.top.max(rect.bottom));
        let mut target=self.raster_dc(dc)?;
        if left==right||top==bottom{return Ok(());}
        let (right,bottom)=(right-1,bottom-1);
        let points=if state.clockwise{[(right,bottom),(left,bottom),(left,top),(right,top)]}
            else{[(right,top),(left,top),(left,bottom),(right,bottom)]};
        let mut phase=0;
        for index in 0..4 {let a=points[index];let b=points[(index+1)%4];
            stroke(&mut target,pen,state,a,b,phase)?;
            phase+=(i64::from(a.0)-i64::from(b.0)).abs().max((i64::from(a.1)-i64::from(b.1)).abs()) as u64;
        }
        if let BrushStyle::Solid(color)=brush {
            let inset=i32::from(pen.style!=PS_NULL);let clip=target.bounds();
            let (right,bottom)=if pen.style==PS_NULL{(right+1,bottom+1)}else{(right,bottom)};
            for y in (top+inset).max(clip.top)..bottom.min(clip.bottom){
                for x in (left+inset).max(clip.left)..right.min(clip.right){target.update(x,y,|old|rop2(state.rop,color,old));}
            }
        }
        Ok(())
    }
    fn stroke_pen(&self,dc:u32,state:PenRasterState)->Result<Pen,GdiError>{
        if !(1..=16).contains(&state.rop)||state.pen_color>RGB||state.brush_color>RGB||state.background>RGB{return Err(GdiError::InvalidDimensions);}
        let dc=&self.dcs.iter().find(|(id,_)|*id==dc).ok_or(GdiError::NoSuchObject)?.1;
        dc.ensure_active()?;
        let pen=self.pen_description(dc.pen,state.pen_color)?;
        if pen.style!=PS_NULL&&pen.width>1{return Err(GdiError::InvalidDimensions);}
        Ok(pen)
    }
}
fn stroke(target:&mut DcRaster<'_>,pen:Pen,state:PenRasterState,start:(i32,i32),end:(i32,i32),phase:u64)->Result<(),GdiError>{
    if pen.style==PS_NULL{return Ok(());}
    coverage::line(start,end,target.bounds(),|x,y,step|{
        let foreground=dash_on(pen.style,phase+step);
        if foreground||state.opaque {let color=if foreground{pen.color}else{state.background};
            target.update(x,y,|old|rop2(state.rop,color,old));}
        Ok(())
    })
}
fn dash_on(style:u32,step:u64)->bool{
    let pattern:&[u64]=match style{PS_SOLID|PS_INSIDEFRAME=>return true,1=>&[18,6],2=>&[3,3],
        3=>&[9,6,3,6],4=>&[9,3,3,3,3,3],_=>return false};
    let mut phase=step%pattern.iter().sum::<u64>();
    for (index,length) in pattern.iter().enumerate(){if phase<*length{return index%2==0;}phase-=length;}
    false
}
fn rop2(mode:u16,source:u32,destination:u32)->u32{
    let table=mode-1;let mut result=0;
    for index in 0..4 {if table&(1<<index)!=0 {
        result|=if index&2!=0{source}else{!source}&if index&1!=0{destination}else{!destination};
    }}result&RGB
}

#[cfg(test)]
#[path="tests/raster.rs"]
mod tests;
