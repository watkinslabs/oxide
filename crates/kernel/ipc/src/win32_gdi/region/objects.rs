//! Canonical HRGN identities with existing exact PaintRegion geometry; 31fk§6.
use super::{GdiManager, GdiError, Rect};
use super::super::clip::complexity_of;
use super::{query, shapes};
use crate::win32_window::{PaintRegion, WindowRect};
pub const TYPE_REGION: u32 = 0x040000;
pub const RGN_AND: i32 = 1;
pub const RGN_OR: i32 = 2;
pub const RGN_XOR: i32 = 3;
pub const RGN_DIFF: i32 = 4;
pub const RGN_COPY: i32 = 5;

impl GdiManager {
    /// Validate identity before allocating replacement geometry; no new handle. # C: O(regions)
    pub fn set_rect_region(&mut self,handle:u32,rect:Rect)->Result<(),GdiError>{
        let index=self.regions.iter().position(|(id,_)|*id==handle).ok_or(GdiError::NoSuchObject)?;
        let bounds=WindowRect{left:rect.left.min(rect.right),top:rect.top.min(rect.bottom),
            right:rect.left.max(rect.right),bottom:rect.top.max(rect.bottom)};
        let region=PaintRegion::from_rect(bounds).map_err(|_|GdiError::HandleLimit)?;
        self.regions[index].1=region;Ok(())
    }
    /// Snapshot aliases and calculate exact geometry before replacing the destination. # C: PaintRegion Boolean-operation cost
    pub fn combine_region(&mut self, destination:u32, source1:u32, source2:u32, mode:i32) -> Result<u32,GdiError> {
        if !self.regions.iter().any(|(id,_)| *id == destination) { return Err(GdiError::NoSuchObject); }
        let mut left = self.region_snapshot(source1)?;
        if mode != RGN_COPY {
            let mut right = self.region_snapshot(source2)?;
            let result = match mode {
                RGN_AND => query::intersect_into(&mut left, &right).map_err(|_| crate::win32_window::WindowError::NoMemory),
                RGN_OR => left.union(&right),
                RGN_XOR => {
                    right.subtract(&left).map_err(|_| GdiError::HandleLimit)?;
                    left.subtract(&self.region_snapshot(source2)?).map_err(|_| GdiError::HandleLimit)?;
                    left.union(&right)
                },
                RGN_DIFF => left.subtract(&right),
                _ => return Err(GdiError::InvalidDimensions),
            };
            result.map_err(|_| GdiError::HandleLimit)?;
        }
        self.replace_region(destination,left)?;
        Ok(self.region_box(destination)?.0)
    }
    /// Transfer exact geometry after reserving owner capacity, before exposing an identity. # C: O(1) amortized
    pub fn create_region(&mut self, region: PaintRegion) -> Result<u32, GdiError> {
        self.regions.try_reserve(1).map_err(|_| GdiError::HandleLimit)?;
        let handle = self.allocate(TYPE_REGION)?;
        self.regions.push((handle,region)); Ok(handle)
    }
    /// Empty and reversed rectangles retain normal region-object identity. # C: O(1)
    pub fn create_rect_region(&mut self, rect: Rect) -> Result<u32, GdiError> {
        let rect = WindowRect { left: rect.left.min(rect.right), top: rect.top.min(rect.bottom),
            right: rect.left.max(rect.right), bottom: rect.top.max(rect.bottom) };
        let region = PaintRegion::from_rect(rect).map_err(|_| GdiError::HandleLimit)?;
        self.create_region(region)
    }
    /// Exact owned copy, never a borrowed region crossing a callback boundary. # C: O(regions + rectangles)
    pub fn region_snapshot(&self, handle: u32) -> Result<PaintRegion, GdiError> {
        self.regions.iter().find(|(id,_)| *id == handle).ok_or(GdiError::NoSuchObject)?.1.try_copy()
            .map_err(|_| GdiError::HandleLimit)
    }
    /// Replace only a live canonical region, preserving its published identity. # C: O(regions)
    pub fn replace_region(&mut self, handle: u32, region: PaintRegion) -> Result<(), GdiError> {
        self.regions.iter_mut().find(|(id,_)| *id == handle).ok_or(GdiError::NoSuchObject)?.1 = region; Ok(())
    }
    /// Canonical band count determines complexity; the box is the band extent. # C: O(regions + rectangles² log rectangles)
    pub fn region_box(&self, handle: u32) -> Result<(u32,Rect), GdiError> {
        let region = &self.regions.iter().find(|(id,_)| *id == handle).ok_or(GdiError::NoSuchObject)?.1;
        Ok(complexity_of(region))
    }

    /// Rounded-rectangle identity, degenerating to a plain rectangle at small corners. # C: O(ellipse height)
    pub fn create_round_rect_region(&mut self, rect: Rect, ellipse_width: i32, ellipse_height: i32) -> Result<u32, GdiError> {
        let region = shapes::round_rect_region(rect.left, rect.top, rect.right, rect.bottom, ellipse_width, ellipse_height)?;
        self.create_region(region)
    }

    /// Ellipse inscribed in the bounding rectangle. # C: O(height)
    pub fn create_elliptic_region(&mut self, rect: Rect) -> Result<u32, GdiError> {
        let region = shapes::elliptic_region(rect.left, rect.top, rect.right, rect.bottom)?;
        self.create_region(region)
    }

    /// Region identity from an RGNDATA rectangle array. # C: O(N_rects²)
    pub fn create_region_from_data(&mut self, bytes: &[u8]) -> Result<u32, GdiError> {
        let region = query::region_from_data(bytes)?;
        self.create_region(region)
    }

    /// Canonical RGNDATA image of one region identity. # C: O(rectangles² log rectangles)
    pub fn region_data(&self, handle: u32) -> Result<alloc::vec::Vec<u8>, GdiError> {
        let region = &self.regions.iter().find(|(id,_)| *id == handle).ok_or(GdiError::NoSuchObject)?.1;
        query::region_data_bytes(region)
    }

    /// Identity of coverage, independent of how the rectangles were stored. # C: O(rectangles² log rectangles)
    pub fn regions_equal(&self, first: u32, second: u32) -> Result<bool, GdiError> {
        let first = &self.regions.iter().find(|(id,_)| *id == first).ok_or(GdiError::NoSuchObject)?.1;
        let second = &self.regions.iter().find(|(id,_)| *id == second).ok_or(GdiError::NoSuchObject)?.1;
        query::equal_region(first, second)
    }

    /// Translate one region in place and report its resulting complexity. # C: O(rectangles)
    pub fn offset_region(&mut self, handle: u32, x: i32, y: i32) -> Result<u32, GdiError> {
        let region = &self.regions.iter().find(|(id,_)| *id == handle).ok_or(GdiError::NoSuchObject)?.1;
        let moved = query::offset_region(region, x, y)?;
        let kind = complexity_of(&moved).0;
        self.replace_region(handle, moved)?;
        Ok(kind)
    }

    /// Half-open point membership. # C: O(regions + rectangles)
    pub fn region_contains_point(&self, handle: u32, x: i32, y: i32) -> Result<bool, GdiError> {
        let region = &self.regions.iter().find(|(id,_)| *id == handle).ok_or(GdiError::NoSuchObject)?.1;
        Ok(query::pt_in_region(region, x, y))
    }

    /// Any overlap with the ordered rectangle. # C: O(regions + rectangles)
    pub fn region_overlaps_rect(&self, handle: u32, rect: Rect) -> Result<bool, GdiError> {
        let region = &self.regions.iter().find(|(id,_)| *id == handle).ok_or(GdiError::NoSuchObject)?.1;
        Ok(query::rect_in_region(region, rect))
    }
    /// Region consumers own snapshots; deleting an identity never invalidates those copies. # C: O(regions)
    pub fn delete_region(&mut self, handle: u32) -> Result<(), GdiError> {
        let index = self.regions.iter().position(|(id,_)| *id == handle).ok_or(GdiError::NoSuchObject)?;
        self.regions.remove(index); Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/region.rs"]
mod tests;
