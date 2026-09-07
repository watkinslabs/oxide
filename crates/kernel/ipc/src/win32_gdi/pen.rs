//! Canonical pen metadata and selection lifetime; 31fk§8.
use super::{GdiManager,GdiError};
use super::stock::{stock_object,StockDescription,StockStyle};
pub const TYPE_PEN:u32=0x300000;
pub const DEFAULT_DC_PEN_HANDLE:u32=0x00800000|TYPE_PEN|39;
pub const PS_SOLID:u32=0;
pub const PS_NULL:u32=5;
pub const PS_INSIDEFRAME:u32=6;
#[path="pen/coverage.rs"]
mod coverage;
#[path="pen/raster.rs"]
mod raster;
#[path="pen/ext.rs"]
mod ext;
pub use ext::{admit_ext_pen, ExtPenRequest, PS_STYLE_MASK, PS_TYPE_MASK, PS_GEOMETRIC, PS_USERSTYLE, PS_ALTERNATE, BS_SOLID, BS_NULL, MAX_STYLE_ENTRIES};
pub use raster::PenRasterState;

/// A dash pattern in the units the stroke phase counts. An empty pattern means
/// the line style's own table decides the dashes.
#[derive(Clone,Copy,Debug,Eq,PartialEq,Default)]
pub struct DashPattern {pub entries:[u32;ext::MAX_STYLE_ENTRIES],pub count:u8}

impl DashPattern {
    /// Build a pattern from validated style entries, scaled by `scale`. # C: O(N_entries)
    pub fn new(entries:&[u32],scale:u32)->DashPattern {
        let mut pattern=DashPattern::default();
        for (slot,entry) in pattern.entries.iter_mut().zip(entries.iter().take(ext::MAX_STYLE_ENTRIES)) {*slot=entry.saturating_mul(scale);}
        pattern.count=entries.len().min(ext::MAX_STYLE_ENTRIES) as u8;pattern
    }
    /// Length of one full on/off cycle. An odd entry count runs the pattern
    /// twice, so each entry alternates its role on the second pass. # C: O(N_entries)
    pub fn cycle(&self)->u64 {
        let sum:u64=self.entries.iter().take(self.count as usize).map(|entry|u64::from(*entry)).sum();
        if self.count%2==1 {sum*2} else {sum}
    }
    /// Whether the pattern paints at this distance along the run. # C: O(N_entries)
    pub fn covers(&self,step:u64)->bool {
        let cycle=self.cycle();
        if self.count==0||cycle==0 {return true;}
        let mut phase=step%cycle;
        for index in 0..2*self.count as usize {
            let length=u64::from(self.entries[index%self.count as usize]);
            if phase<length {return index%2==0;}
            phase-=length;
        }
        false
    }
}

#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct Pen {pub style:u32,pub width:u32,pub color:u32,pub pattern:DashPattern,deleted:bool}

impl GdiManager {
    /// Null creation returns its immutable stock identity. # C: O(1) amortized
    pub fn create_pen(&mut self,style:i32,width:i32,color:u32)->Result<u32,GdiError> {
        if style==PS_NULL as i32 {return Ok(stock_object(8).ok_or(GdiError::NoSuchObject)?.handle);}
        if !(0..=PS_INSIDEFRAME as i32).contains(&style) {return Err(GdiError::InvalidDimensions);}
        self.create_pen_pattern(style as u32,width,color,DashPattern::default())
    }

    /// Create a pen whose dashes come from an explicit pattern rather than
    /// from its line style's table. # C: O(1) amortized
    pub(super) fn create_pen_pattern(&mut self,style:u32,width:i32,color:u32,pattern:DashPattern)->Result<u32,GdiError> {
        if color>0xffffff {return Err(GdiError::InvalidDimensions);}
        let width=width.checked_abs().ok_or(GdiError::InvalidDimensions)? as u32;
        self.pens.try_reserve(1).map_err(|_|GdiError::HandleLimit)?;
        let handle=self.allocate(TYPE_PEN)?;
        self.pens.push((handle,Pen {style,width,color,pattern,deleted:false}));Ok(handle)
    }
    /// DC_PEN color is supplied by its owning DC, not mutated stock metadata. # C: O(pens)
    pub fn pen_description(&self,handle:u32,dc_color:u32)->Result<Pen,GdiError> {
        if let Some(description)=self.stock_description(handle) {
            return match description {
                StockDescription::Pen(p)=>Ok(Pen {style:if p.style==StockStyle::Null {PS_NULL}else{PS_SOLID},
                    width:p.width as u32,color:if p.dc_color {dc_color}else{p.color},pattern:DashPattern::default(),deleted:false}),
                _=>Err(GdiError::NoSuchObject),
            };
        }
        self.pens.iter().find(|(id,_)|*id==handle).map(|(_,p)|*p).ok_or(GdiError::NoSuchObject)
    }
    /// Validate DC then pen before changing selection; collect only released deleted objects. # C: O(pens * DCs)
    pub fn select_pen(&mut self,dc:u32,pen:u32)->Result<u32,GdiError> {
        let index=self.dcs.iter().position(|(id,_)|*id==dc).ok_or(GdiError::NoSuchObject)?;
        self.dcs[index].1.ensure_active()?;
        self.pen_description(pen,self.dcs[index].1.dc_pen_color)?;
        let previous=self.dcs[index].1.pen;self.dcs[index].1.pen=pen;
        self.collect_deleted_pens();Ok(previous)
    }
    /// Snapshot selected logical pen from the canonical DC. # C: O(DCs + pens)
    pub fn selected_pen(&self,dc:u32)->Result<Pen,GdiError> {
        let state=&self.dcs.iter().find(|(id,_)|*id==dc).ok_or(GdiError::NoSuchObject)?.1;
        state.ensure_active()?;
        self.pen_description(state.pen,state.dc_pen_color)
    }
    /// Keep selected deleted pens alive until all referencing DCs release them. # C: O(pens * DCs)
    pub fn delete_pen(&mut self,handle:u32)->Result<(),GdiError> {
        if let Some(description)=self.stock_description(handle) {
            return if matches!(description,StockDescription::Pen(_)){Ok(())}else{Err(GdiError::NoSuchObject)};
        }
        self.pens.iter_mut().find(|(id,_)|*id==handle).ok_or(GdiError::NoSuchObject)?.1.deleted=true;
        self.collect_deleted_pens();Ok(())
    }
    /// DC destruction and reset call after releasing their selection. # C: O(pens * DCs)
    pub fn collect_deleted_pens(&mut self) {
        let dcs=&self.dcs;
        self.pens.retain(|(handle,pen)|!pen.deleted || dcs.iter().any(|(_,dc)|dc.pen==*handle));
    }
}

#[cfg(test)]
#[path="tests/pen.rs"]
mod tests;
