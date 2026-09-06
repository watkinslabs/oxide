//! Canonical selected brushes and source-independent raster operations; 31fk§4.
use super::{GdiError, GdiManager};
use super::stock::{StockDescription, StockStyle};

pub const TYPE_BRUSH: u32 = 0x10_0000;
const WHITE_BRUSH: u32 = 0;
const RGB_MASK: u32 = 0x00ff_ffff;
const SOURCE_MASK: u8 = 0x33;
const PATTERN_MASK: u8 = 0x0f;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrushStyle { Solid(u32), Hollow }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Brush { pub style: BrushStyle, deleted: bool }

impl GdiManager {
    /// Store an XRGB solid brush in the process object owner. # C: O(1)
    pub fn create_solid_brush(&mut self, color: u32) -> Result<u32, GdiError> {
        self.create_brush(BrushStyle::Solid(color & RGB_MASK))
    }

    /// Allocate a typed brush identity, never reusing a deleted slot. # C: O(1)
    pub fn create_brush(&mut self, style: BrushStyle) -> Result<u32, GdiError> {
        let handle = self.allocate(TYPE_BRUSH)?;
        self.brushes.push((handle, Brush { style, deleted: false }));
        Ok(handle)
    }

    /// Return immutable brush attributes; DC_BRUSH color resolves in its DC. # C: O(brushes)
    pub fn brush_style(&self, handle: u32, dc_color: u32) -> Result<BrushStyle, GdiError> {
        if let Some(description) = self.stock_description(handle) {
            return match description {
                StockDescription::Brush(brush) => Ok(match brush.style {
                    StockStyle::Null => BrushStyle::Hollow,
                    StockStyle::Solid => BrushStyle::Solid(if brush.dc_color { dc_color } else { brush.color }),
                }),
                _ => Err(GdiError::NoSuchObject),
            };
        }
        self.brushes.iter().find(|(id, _)| *id == handle).map(|(_, brush)| brush.style).ok_or(GdiError::NoSuchObject)
    }

    /// Select only a live brush, returning the actual previous stock/dynamic identity. # C: O(DCs + brushes)
    pub fn select_brush(&mut self, dc: u32, brush: u32) -> Result<u32, GdiError> {
        self.brush_style(brush, RGB_MASK)?;
        let default = self.stock_object(WHITE_BRUSH).ok_or(GdiError::NoSuchObject)?.handle;
        let state = &mut self.dcs.iter_mut().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1;
        state.ensure_active()?;
        let previous = state.brush.unwrap_or(default);
        state.brush = Some(brush);
        self.collect_deleted_brushes();
        Ok(previous)
    }

    /// Selected objects survive deletion until their final DC releases them. # C: O(DCs + brushes)
    pub fn delete_brush(&mut self, handle: u32) -> Result<(), GdiError> {
        if self.is_system_brush(handle) { return Ok(()); }
        if let Some(description) = self.stock_description(handle) {
            return if matches!(description, StockDescription::Brush(_)) { Ok(()) } else { Err(GdiError::NoSuchObject) };
        }
        let brush = &mut self.brushes.iter_mut().find(|(id, _)| *id == handle).ok_or(GdiError::NoSuchObject)?.1;
        brush.deleted = true;
        self.collect_deleted_brushes();
        Ok(())
    }

    /// Parent DC deletion calls this after removing its selection. # C: O(brushes * DCs)
    pub fn collect_deleted_brushes(&mut self) {
        let dcs = &self.dcs;
        self.brushes.retain(|(id, brush)| !brush.deleted || dcs.iter().any(|(_, dc)| dc.brush == Some(*id)));
    }

    /// DC_BRUSH color belongs to the DC, not to the immutable stock object. # C: O(DCs)
    pub fn set_dc_brush_color(&mut self, dc: u32, color: u32) -> Result<u32, GdiError> {
        let state = &mut self.dcs.iter_mut().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1;
        state.ensure_active()?;
        Ok(core::mem::replace(&mut state.dc_brush_color, color & RGB_MASK))
    }

    /// Apply all source-independent ROP3 truth tables to clipped canonical pixels. # C: O(DCs + brushes + clipped pixels)
    pub fn pat_blt(&mut self, dc: u32, x: i32, y: i32, width: i32, height: i32, rop: u32) -> Result<(), GdiError> {
        self.pat_blt_color(dc, x, y, width, height, rop, None)
    }

    /// Bound DC_BRUSH reads use a fresh shared XRGB snapshot, never a private color mirror.
    /// # C: O(DCs + brushes + clipped pixels)
    pub fn pat_blt_shared_color(&mut self, dc: u32, x: i32, y: i32, width: i32, height: i32, rop: u32, color: u32) -> Result<(), GdiError> {
        self.pat_blt_color(dc, x, y, width, height, rop, Some(color & RGB_MASK))
    }

    fn pat_blt_color(&mut self, dc: u32, x: i32, y: i32, width: i32, height: i32, rop: u32, shared_color: Option<u32>) -> Result<(), GdiError> {
        let table = (rop >> 16) as u8;
        if (table >> 2) & SOURCE_MASK != table & SOURCE_MASK { return Err(GdiError::InvalidDimensions); }
        let state = &self.dcs.iter().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1;
        state.ensure_active()?;
        let handle = state.brush.unwrap_or(self.stock_object(WHITE_BRUSH).ok_or(GdiError::NoSuchObject)?.handle);
        let brush = self.brush_style(handle, shared_color.unwrap_or(state.dc_brush_color))?;
        let uses_brush = table & PATTERN_MASK != (table >> 4) & PATTERN_MASK;
        if brush == BrushStyle::Hollow && uses_brush { return Ok(()); }
        let pattern = match brush { BrushStyle::Solid(color) => color, BrushStyle::Hollow => 0 };
        let mut target = self.raster_dc(dc)?;
        let clip = target.bounds();
        let (left, right) = signed_extent(x, width, clip.left, clip.right);
        let (top, bottom) = signed_extent(y, height, clip.top, clip.bottom);
        for row in top..bottom { for col in left..right {
            target.update(col, row, |old| raster(table, pattern, old));
        } }
        Ok(())
    }
}

fn signed_extent(origin: i32, size: i32, low: i32, high: i32) -> (i32, i32) {
    let start = i64::from(origin); let end = start + i64::from(size);
    let (start, end) = if size < 0 { (end + 1, start + 1) } else { (start, end) };
    (start.clamp(i64::from(low), i64::from(high)) as i32, end.clamp(i64::from(low), i64::from(high)) as i32)
}

fn raster(table: u8, pattern: u32, destination: u32) -> u32 {
    let mut result = 0;
    for (bit, mask) in [(0, !pattern & !destination), (1, !pattern & destination), (4, pattern & !destination), (5, pattern & destination)] {
        if table & (1 << bit) != 0 { result |= mask; }
    }
    result & RGB_MASK
}

#[cfg(test)]
#[path = "tests/brush.rs"]
mod tests;
