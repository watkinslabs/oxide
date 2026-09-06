use super::*;
use super::super::{WindowId, WindowManager, PaintSession, WindowPresentRecord};
const EMPTY: WindowRect = WindowRect { left: 0, top: 0, right: 0, bottom: 0 };

impl WindowManager {
    /// Non-consuming exact auxiliary-work snapshot before GDI allocation. # C: O(windows + region)
    pub fn erase_damage(&self, id: WindowId) -> Result<PaintDamage, WindowError> {
        self.get(id).ok_or(WindowError::NoSuchWindow)?;
        self.dirty.iter().find(|(window, _)| *window == id).map_or_else(|| Ok(PaintDamage::default()), |(_, damage)| damage.try_copy())
    }
    /// Commit prepared resources only if pending coverage/flags have not changed. # C: O(windows + region)
    pub fn take_erase_damage_if(&mut self, id: WindowId, expected: &PaintDamage) -> Result<(), WindowError> {
        self.get(id).ok_or(WindowError::NoSuchWindow)?;
        if !self.dirty.iter().find(|(window, _)| *window == id).is_some_and(|(_, damage)| damage == expected) { return Err(WindowError::InvalidParent); }
        self.take_erase_damage(id).map(|_| ())
    }
    /// Client-local region to canonical screen coordinates through stored parent client origins.
    /// # C: O(windows² + region * depth)
    pub fn paint_region_to_screen(&self, mut id: WindowId, region: &PaintRegion) -> Result<PaintRegion, WindowError> {
        let mut mapped = region.try_copy()?;
        for _ in 0..self.windows.len() {
            let record = self.get(id).ok_or(WindowError::NoSuchWindow)?;
            let origin = record.client_rect.or_else(|| self.rect(id)).ok_or(WindowError::NoSuchWindow)?;
            mapped = mapped.translated(origin.left, origin.top)?;
            let Some(parent) = record.parent else { return Ok(mapped); }; id = parent;
        }
        Err(WindowError::InvalidParent)
    }
    /// Union client damage into canonical update state. # C: O(windows + region operations)
    pub fn invalidate(&mut self, id: WindowId, rect: Option<WindowRect>) -> Result<(), WindowError> {
        let input = rect.map(PaintRegion::from_rect).transpose()?;
        self.redraw_damage(id, input.as_ref(), RDW_INVALIDATE, false)
    }
    /// Apply one window's already-mapped redraw request; traversal owns descendants.
    /// # C: O(windows + region operations)
    pub fn redraw_damage(&mut self, id: WindowId, region: Option<&PaintRegion>, flags: u32, nested: bool) -> Result<(), WindowError> {
        let record = self.get(id).ok_or(WindowError::NoSuchWindow)?;
        let client = self.client_rect(id).ok_or(WindowError::NoSuchWindow)?;
        let window = self.rect(id).ok_or(WindowError::NoSuchWindow)?;
        let origin = record.client_rect.unwrap_or(window);
        let frame = WindowRect {
            left: window.left.checked_sub(origin.left).ok_or(WindowError::InvalidParent)?,
            top: window.top.checked_sub(origin.top).ok_or(WindowError::InvalidParent)?,
            right: window.right.checked_sub(origin.left).ok_or(WindowError::InvalidParent)?,
            bottom: window.bottom.checked_sub(origin.top).ok_or(WindowError::InvalidParent)?,
        };
        let index = self.dirty.iter().position(|(window, _)| *window == id);
        let mut next = match index { Some(index) => self.dirty[index].1.try_copy()?, None => PaintDamage::default() };
        next.apply(region, client, frame, flags, nested)?;
        if !next.pending() { if let Some(index) = index { self.dirty.remove(index); } }
        else if let Some(index) = index { self.dirty[index].1 = next; }
        else { self.dirty.try_reserve(1).map_err(|_| WindowError::NoMemory)?; self.dirty.push((id, next)); }
        Ok(())
    }
    /// Transfer exact damage into the existing canonical paint session. # C: O(windows + dirty + region)
    pub fn begin_paint(&mut self, id: WindowId) -> Result<Option<WindowRect>, WindowError> {
        let client = self.client_rect(id).ok_or(WindowError::NoSuchWindow)?;
        if self.painting.iter().any(|(window, _)| *window == id) { return Err(WindowError::PaintActive); }
        let index = self.dirty.iter().position(|(window, _)| *window == id);
        let pending = match index { Some(index) => self.dirty[index].1.try_copy()?, None => PaintDamage::default() };
        let damage = pending.region.clipped(client)?.bounds();
        let parents = self.paint_parent_validation(id, &pending.region)?;
        self.painting.try_reserve(1).map_err(|_| WindowError::NoMemory)?;
        self.painting.push((id, PaintSession { damage, dc: 0, region: pending.region,
            erase: pending.erase, delayed_erase: pending.delayed_erase, nonclient: pending.nonclient }));
        if let Some(index) = index { self.dirty.remove(index); }
        for (parent, damage) in parents {
            if let Some(index) = self.dirty.iter().position(|(window, _)| *window == parent) {
                if damage.pending() { self.dirty[index].1 = damage; } else { self.dirty.remove(index); }
            }
        }
        Ok(damage)
    }
    /// # C: O(windows + dirty + region)
    pub fn begin_paint_rect(&mut self, id: WindowId) -> Result<WindowRect, WindowError> { self.begin_paint(id).map(|region| region.unwrap_or(EMPTY)) }
    /// Bounding projection only; clipping must use paint_region. # C: O(painting)
    pub fn paint_rect(&self, id: WindowId) -> Result<WindowRect, WindowError> {
        self.painting.iter().find(|(window, _)| *window == id).map(|(_, session)| session.damage.unwrap_or(EMPTY)).ok_or(WindowError::PaintNotActive)
    }
    /// Exact active client coverage for GDI clip and presentation. # C: O(windows + painting + region)
    pub fn paint_region(&self, id: WindowId) -> Result<PaintRegion, WindowError> {
        let client = self.client_rect(id).ok_or(WindowError::NoSuchWindow)?;
        self.painting.iter().find(|(window, _)| *window == id).ok_or(WindowError::PaintNotActive)?.1.region.clipped(client)
    }
    /// Reserve erase/nonclient work without consuming client paint damage.
    /// Clear flags before callbacks so re-invalidation cannot be overwritten. # C: O(windows + region)
    pub fn take_erase_damage(&mut self, id: WindowId) -> Result<PaintDamage, WindowError> {
        let client = self.client_rect(id).ok_or(WindowError::NoSuchWindow)?;
        let Some(index) = self.dirty.iter().position(|(window, _)| *window == id) else { return Ok(PaintDamage::default()); };
        let snapshot = self.dirty[index].1.try_copy()?;
        let clipped = if snapshot.nonclient { Some(snapshot.region.clipped(client)?) } else { None };
        let damage = &mut self.dirty[index].1;
        if let Some(clipped) = clipped { damage.region = clipped; }
        damage.erase = false; damage.nonclient = false; damage.delayed_erase = false;
        if !damage.pending() { self.dirty.remove(index); }
        Ok(snapshot)
    }
    /// Merge delayed erase only; never copy an old callback snapshot onto live damage. # C: O(dirty)
    pub fn finish_erase_damage(&mut self, id: WindowId, needed: bool) {
        if needed { if let Some((_, damage)) = self.dirty.iter_mut().find(|(window, _)| *window == id) {
            if !damage.region.is_empty() { damage.delayed_erase = true; }
        } }
    }
    /// Complete erase only against the exact admitted paint HDC. # C: O(painting)
    pub fn finish_paint_erase(&mut self, id: WindowId, dc: u32, needed: bool) -> Result<(), WindowError> {
        let (_, session) = self.painting.iter_mut().find(|(window, session)| *window == id && session.dc == dc && dc != 0)
            .ok_or(WindowError::PaintNotActive)?;
        session.erase = false; session.delayed_erase = needed; session.nonclient = false; Ok(())
    }
    /// # C: O(windows + painting)
    pub fn present_record(&self, id: WindowId) -> Result<WindowPresentRecord, WindowError> {
        let record = self.get(id).ok_or(WindowError::NoSuchWindow)?;
        if !record.visible { return Err(WindowError::NotVisible); }
        let bounds = self.rect(id).ok_or(WindowError::NoSuchWindow)?;
        if bounds.right <= bounds.left || bounds.bottom <= bounds.top { return Err(WindowError::NoSuchWindow); }
        let damage = self.painting.iter().find(|(window, _)| *window == id).map(|(_, session)| session.damage).ok_or(WindowError::PaintNotActive)?;
        Ok(WindowPresentRecord { window: id, bounds, damage })
    }
    /// Drop only admitted paint; callback-time invalidation remains pending. # C: O(painting)
    pub fn end_paint(&mut self, id: WindowId) -> Result<(), WindowError> {
        let index = self.painting.iter().position(|(window, _)| *window == id).ok_or(WindowError::PaintNotActive)?;
        self.painting.remove(index); Ok(())
    }
}
