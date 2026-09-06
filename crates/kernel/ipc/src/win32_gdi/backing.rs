//! Paint storage merge into the existing canonical window DC; 31fk§1.
use super::{GdiError, GdiManager, Rect, MAX_SURFACE_PIXELS};
use crate::win32_window::{PaintRegion, WindowRect};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PaintBacking { pub width: i32, pub height: i32, pub client: Rect }

impl GdiManager {
    /// Initialize a temporary client-origin paint surface from retained window pixels.
    /// Storage copy preserves attributes and ignores drawing clips. # C: O(DCs + client pixels)
    pub fn seed_paint(&mut self, hwnd: u32, paint_dc: u32, layout: PaintBacking) -> Result<(), GdiError> {
        let backing = self.window_dc(hwnd).ok_or(GdiError::NoSuchObject)?;
        let src = self.dcs.iter().position(|(dc, _)| *dc == backing).ok_or(GdiError::NoSuchObject)?;
        let dst = self.dcs.iter().position(|(dc, _)| *dc == paint_dc).ok_or(GdiError::NoSuchObject)?;
        let client = layout.client;
        let width = client.right.checked_sub(client.left).ok_or(GdiError::InvalidDimensions)?;
        let height = client.bottom.checked_sub(client.top).ok_or(GdiError::InvalidDimensions)?;
        if self.dcs[src].1.lease.is_some() || self.dcs[dst].1.lease.is_some() || src == dst || layout.width <= 0 || layout.height <= 0 || client.left < 0 || client.top < 0
            || width < 0 || height < 0 || client.right > layout.width || client.bottom > layout.height
            || (self.dcs[src].1.width, self.dcs[src].1.height) != (layout.width, layout.height)
            || width > self.dcs[dst].1.width || height > self.dcs[dst].1.height { return Err(GdiError::InvalidDimensions); }
        let (source, target) = if src < dst {
            let (first, last) = self.dcs.split_at_mut(dst); (&first[src].1, &mut last[0].1)
        } else {
            let (first, last) = self.dcs.split_at_mut(src); (&last[0].1, &mut first[dst].1)
        };
        for y in 0..height {
            let start = (y + client.top) as usize * source.width as usize + client.left as usize;
            let out = y as usize * target.width as usize;
            target.pixels[out..out + width as usize].copy_from_slice(&source.pixels[start..start + width as usize]);
        }
        Ok(())
    }

    /// Merge admitted client-origin damage without applying destination drawing clips.
    /// Caller snapshots authoritative window/client geometry before taking GDI.
    /// # C: O(DCs + damage pixels + resized surface pixels)
    pub fn retain_paint(&mut self, hwnd: u32, paint_dc: u32, damage: Rect, layout: PaintBacking) -> Result<u32, GdiError> {
        self.retain_paint_rects(hwnd, paint_dc, &[WindowRect { left: damage.left, top: damage.top,
            right: damage.right, bottom: damage.bottom }], layout)
    }

    /// Validate complete admitted coverage before resize or writes; holes remain untouched.
    /// # C: O(DCs + region rectangles + damage pixels + resized surface pixels)
    pub fn retain_paint_region(&mut self, hwnd: u32, paint_dc: u32, region: &PaintRegion, layout: PaintBacking) -> Result<u32, GdiError> {
        self.retain_paint_rects(hwnd, paint_dc, region.rects(), layout)
    }

    fn retain_paint_rects(&mut self, hwnd: u32, paint_dc: u32, damage: &[WindowRect], layout: PaintBacking) -> Result<u32, GdiError> {
        let backing = self.window_dc(hwnd).ok_or(GdiError::NoSuchObject)?;
        let src = self.dcs.iter().position(|(dc, _)| *dc == paint_dc).ok_or(GdiError::NoSuchObject)?;
        if self.dcs[src].1.lease.is_some() { return Err(GdiError::InvalidDimensions); }
        if backing == paint_dc { return Err(GdiError::InvalidDimensions); }
        let client = layout.client;
        let cw = client.right.checked_sub(client.left).ok_or(GdiError::InvalidDimensions)?;
        let ch = client.bottom.checked_sub(client.top).ok_or(GdiError::InvalidDimensions)?;
        if layout.width <= 0 || layout.height <= 0 || client.left < 0 || client.top < 0 || cw < 0 || ch < 0
            || client.right > layout.width || client.bottom > layout.height
            || (layout.width as usize).checked_mul(layout.height as usize).is_none_or(|n| n > MAX_SURFACE_PIXELS) {
            return Err(GdiError::InvalidDimensions);
        }
        for r in damage {
            if r.left < 0 || r.top < 0 || r.right <= r.left || r.bottom <= r.top || r.right > cw || r.bottom > ch
                || r.right > self.dcs[src].1.width || r.bottom > self.dcs[src].1.height { return Err(GdiError::InvalidDimensions); }
        }
        // resize_dc validates and allocates before mutation; source is a distinct DC.
        self.resize_dc(backing, layout.width, layout.height)?;
        let dst = self.dcs.iter().position(|(dc, _)| *dc == backing).ok_or(GdiError::NoSuchObject)?;
        let (source, target) = if src < dst {
            let (first, last) = self.dcs.split_at_mut(dst); (&first[src].1, &mut last[0].1)
        } else {
            let (first, last) = self.dcs.split_at_mut(src); (&last[0].1, &mut first[dst].1)
        };
        let mut changed=None;
        for r in damage {
            let count = (r.right - r.left) as usize;
            for y in r.top..r.bottom {
                let start = y as usize * source.width as usize + r.left as usize;
                let out = (y + client.top) as usize * target.width as usize + (r.left + client.left) as usize;
                for column in 0..count{
                    let next=source.pixels[start+column];
                    if target.pixels[out+column]!=next{
                        target.pixels[out+column]=next;
                        let x=r.left+client.left+column as i32;let y=y+client.top;
                        super::output::merge(&mut changed,Rect{left:x,top:y,right:x+1,bottom:y+1});
                    }
                }
            }
        }
        target.pending_output.record(changed);Ok(backing)
    }
}

#[cfg(test)]
#[path = "tests/backing.rs"]
mod tests;
