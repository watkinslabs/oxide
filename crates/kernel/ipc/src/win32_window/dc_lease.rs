//! Canonical GetDCEx visibility/context snapshot; 31fk§7.
use super::*;
use crate::win32_gdi::{dc_lease_flags, LeaseOwner, DCX_CACHE, DCX_CLIPCHILDREN, DCX_PARENTCLIP, DCX_WINDOW};

const WS_VISIBLE: u32 = 0x1000_0000;

/// Snapshot consumed by the syscall/GDI adapter. `visible` is logical lease
/// coverage; all region subtraction is complete before this value is returned.
#[derive(Debug, Eq, PartialEq)]
pub struct DcLeaseContext {
    pub hwnd: u32,
    pub backing_hwnd: u32,
    pub backing_width: i32,
    pub backing_height: i32,
    pub origin: (i32, i32),
    pub screen_origin: (i32, i32),
    pub logical_width: i32,
    pub logical_height: i32,
    pub flags: u32,
    pub owner: LeaseOwner,
    pub visible: PaintRegion,
}

impl WindowManager {
    /// Build the complete GetDCEx snapshot from canonical HWND state. # C: O(windows² + regions²)
    pub fn dc_lease_context(&self, hwnd: WindowId, requested_flags: u32) -> Result<DcLeaseContext, WindowError> {
        let record = self.get(hwnd).ok_or(WindowError::NoSuchWindow)?;
        let outer = self.rect(hwnd).ok_or(WindowError::NoSuchWindow)?;
        let client = record.client_rect.or_else(|| self.rect(hwnd)).ok_or(WindowError::NoSuchWindow)?;
        let parent = record.parent;
        let parent_style = parent.and_then(|id| self.get(id)).map_or(0, |r| r.style);
        let top_level = parent.is_none();
        let class_style = record.class_atom.and_then(|atom| self.classes.iter().find(|class| class.atom == atom)).map_or(0, |class| class.style);
        let flags = dc_lease_flags(requested_flags, record.style, class_style, parent_style, top_level);
        let logical_window = flags & DCX_WINDOW != 0;
        let logical_width = extent(if logical_window { outer } else { client }, true)?;
        let logical_height = extent(if logical_window { outer } else { client }, false)?;
        let client_screen = self.client_screen_origin(hwnd)?;
        let window_screen = self.window_screen_origin(hwnd, client, outer, client_screen)?;
        let screen_origin = if logical_window { window_screen } else { client_screen };
        let origin = if logical_window { (0, 0) } else {
            (client.left.checked_sub(outer.left).ok_or(WindowError::InvalidParent)?, client.top.checked_sub(outer.top).ok_or(WindowError::InvalidParent)?)
        };
        let backing = if flags & DCX_PARENTCLIP != 0 { parent.ok_or(WindowError::InvalidParent)? } else { hwnd };
        let backing_outer = self.rect(backing).ok_or(WindowError::NoSuchWindow)?;
        let backing_client = self.get(backing).ok_or(WindowError::NoSuchWindow)?.client_rect.or_else(|| self.rect(backing)).ok_or(WindowError::NoSuchWindow)?;
        let backing_client_screen = self.client_screen_origin(backing)?;
        let backing_screen = self.window_screen_origin(backing, backing_client, backing_outer, backing_client_screen)?;
        let backing_width = extent(backing_outer, true)?;
        let backing_height = extent(backing_outer, false)?;
        let origin = if backing == hwnd { origin } else {
            (screen_origin.0.checked_sub(backing_screen.0).ok_or(WindowError::InvalidParent)?, screen_origin.1.checked_sub(backing_screen.1).ok_or(WindowError::InvalidParent)?)
        };
        let mut visible = self.base_region(hwnd, flags, window_screen, client_screen, outer, client)?;
        if flags & DCX_CLIPCHILDREN != 0 { self.subtract_children(hwnd, &mut visible)?; }
        self.subtract_ancestor_siblings(hwnd, &mut visible)?;
        self.clip_ancestors(hwnd, &mut visible)?;
        visible = translate_region(&visible, screen_origin)?;
        let owner = if flags & DCX_CACHE != 0 || class_style & (0x20 | 0x40) == 0 { LeaseOwner::Cached }
            else if class_style & 0x40 != 0 { LeaseOwner::Class(record.class_atom.unwrap_or(0)) }
            else { LeaseOwner::Window(hwnd.raw()) };
        Ok(DcLeaseContext { hwnd: hwnd.raw(), backing_hwnd: backing.raw(), backing_width, backing_height,
            origin, screen_origin, logical_width, logical_height, flags, owner, visible })
    }

    fn client_screen_origin(&self, id: WindowId) -> Result<(i32, i32), WindowError> {
        let marker = PaintRegion::from_rect(WindowRect { left: 0, top: 0, right: 1, bottom: 1 })?;
        let mapped = self.paint_region_to_screen(id, &marker)?;
        let rect = mapped.bounds().ok_or(WindowError::InvalidParent)?;
        Ok((rect.left, rect.top))
    }

    fn window_screen_origin(&self, _id: WindowId, client: WindowRect, outer: WindowRect, client_screen: (i32, i32)) -> Result<(i32, i32), WindowError> {
        Ok((client_screen.0.checked_sub(client.left.checked_sub(outer.left).ok_or(WindowError::InvalidParent)?).ok_or(WindowError::InvalidParent)?, client_screen.1.checked_sub(client.top.checked_sub(outer.top).ok_or(WindowError::InvalidParent)?).ok_or(WindowError::InvalidParent)?))
    }

    fn base_region(&self, id: WindowId, flags: u32, window_screen: (i32, i32), client_screen: (i32, i32), outer: WindowRect, client: WindowRect) -> Result<PaintRegion, WindowError> {
        if !self.ancestors_visible(id)? { return Ok(PaintRegion::default()); }
        let (origin, bounds) = if flags & DCX_PARENTCLIP != 0 {
            let parent = self.get(id).ok_or(WindowError::NoSuchWindow)?.parent.ok_or(WindowError::InvalidParent)?;
            let parent_record = self.get(parent).ok_or(WindowError::NoSuchWindow)?;
            let parent_rect = self.rect(parent).ok_or(WindowError::NoSuchWindow)?;
            let parent_client = parent_record.client_rect.unwrap_or(parent_rect);
            (self.client_screen_origin(parent)?, WindowRect { left: 0, top: 0, right: extent(parent_client, true)?, bottom: extent(parent_client, false)? })
        } else if flags & DCX_WINDOW != 0 { (window_screen, WindowRect { left: 0, top: 0, right: extent(outer, true)?, bottom: extent(outer, false)? }) }
        else { (client_screen, WindowRect { left: 0, top: 0, right: extent(client, true)?, bottom: extent(client, false)? }) };
        let screen = WindowRect { left: origin.0.checked_add(bounds.left).ok_or(WindowError::InvalidParent)?, top: origin.1.checked_add(bounds.top).ok_or(WindowError::InvalidParent)?, right: origin.0.checked_add(bounds.right).ok_or(WindowError::InvalidParent)?, bottom: origin.1.checked_add(bounds.bottom).ok_or(WindowError::InvalidParent)? };
        PaintRegion::from_rect(screen)
    }

    fn ancestors_visible(&self, mut id: WindowId) -> Result<bool, WindowError> {
        for _ in 0..=self.windows.len() { let record = self.get(id).ok_or(WindowError::NoSuchWindow)?; if !record.visible || record.style & WS_VISIBLE == 0 { return Ok(false); } let Some(parent) = record.parent else { return Ok(true); }; id = parent; }
        Err(WindowError::InvalidParent)
    }

    fn subtract_children(&self, id: WindowId, region: &mut PaintRegion) -> Result<(), WindowError> {
        for (child, child_record) in &self.windows { if child_record.parent == Some(id) && child_record.visible && child_record.style & WS_VISIBLE != 0 { let cut = self.window_screen_region(*child)?; region.subtract(&cut)?; } }
        Ok(())
    }

    fn subtract_ancestor_siblings(&self, mut id: WindowId, region: &mut PaintRegion) -> Result<(), WindowError> {
        for _ in 0..=self.windows.len() {
            let record = self.get(id).ok_or(WindowError::NoSuchWindow)?;
            let Some(parent) = record.parent else { return Ok(()); };
            // The server clips siblings only for a child whose own style has
            // WS_CLIPSIBLINGS. Top-level sibling clipping belongs to the
            // native compositor and is deliberately outside this region.
            if record.style & 0x0400_0000 != 0 {
                let siblings = self.position_siblings(Some(parent));
                let Some(index) = siblings.iter().position(|candidate| *candidate == id) else { return Err(WindowError::NoSuchWindow); };
                for sibling in siblings.into_iter().skip(index + 1) {
                    let sibling_record = self.get(sibling).ok_or(WindowError::NoSuchWindow)?;
                    if sibling_record.visible && sibling_record.style & WS_VISIBLE != 0 { region.subtract(&self.window_screen_region(sibling)?)?; }
                }
            }
            id = parent;
        }
        Err(WindowError::InvalidParent)
    }

    fn clip_ancestors(&self, mut id: WindowId, region: &mut PaintRegion) -> Result<(), WindowError> {
        loop {
            let record = self.get(id).ok_or(WindowError::NoSuchWindow)?;
            let Some(parent_id) = record.parent else { return Ok(()); };
            let parent = self.get(parent_id).ok_or(WindowError::NoSuchWindow)?;
            if !parent.visible || parent.style & WS_VISIBLE == 0 { *region = PaintRegion::default(); return Ok(()); }
            let parent_client = parent.client_rect.or_else(|| self.rect(parent_id)).ok_or(WindowError::NoSuchWindow)?;
            let parent_client_origin = self.client_screen_origin(parent_id)?;
            let clip = PaintRegion::from_rect(WindowRect {
                left: parent_client_origin.0,
                top: parent_client_origin.1,
                right: parent_client_origin.0.checked_add(extent(parent_client, true)?).ok_or(WindowError::InvalidParent)?,
                bottom: parent_client_origin.1.checked_add(extent(parent_client, false)?).ok_or(WindowError::InvalidParent)?,
            })?;
            let mut outside = region.try_copy()?;
            outside.subtract(&clip)?;
            region.subtract(&outside)?;
            id = parent_id;
        }
    }

    fn window_screen_region(&self, id: WindowId) -> Result<PaintRegion, WindowError> {
        let rect = self.rect(id).ok_or(WindowError::NoSuchWindow)?;
        let record = self.get(id).ok_or(WindowError::NoSuchWindow)?;
        let client = record.client_rect.or_else(|| self.rect(id)).ok_or(WindowError::NoSuchWindow)?;
        let client_origin = self.client_screen_origin(id)?;
        let origin = self.window_screen_origin(id, client, rect, client_origin)?;
        PaintRegion::from_rect(WindowRect { left: origin.0, top: origin.1, right: origin.0.checked_add(extent(rect, true)?).ok_or(WindowError::InvalidParent)?, bottom: origin.1.checked_add(extent(rect, false)?).ok_or(WindowError::InvalidParent)? })
    }
}

fn extent(r: WindowRect, horizontal: bool) -> Result<i32, WindowError> {
    let value = if horizontal { r.right.checked_sub(r.left) } else { r.bottom.checked_sub(r.top) };
    value.filter(|value| *value >= 0).ok_or(WindowError::InvalidParent)
}

fn translate_region(region: &PaintRegion, origin: (i32, i32)) -> Result<PaintRegion, WindowError> { region.translated(origin.0.checked_neg().ok_or(WindowError::InvalidParent)?, origin.1.checked_neg().ok_or(WindowError::InvalidParent)?) }

#[cfg(test)]
#[path = "dc_lease_tests.rs"]
mod tests;
