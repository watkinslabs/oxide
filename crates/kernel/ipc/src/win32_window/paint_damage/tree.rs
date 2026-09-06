use super::*;
use super::super::{WindowManager, WindowId};
const WS_MINIMIZE: u32 = 0x2000_0000;
const WS_CLIPCHILDREN: u32 = 0x0200_0000;
const WS_EX_LAYOUTRTL: u32 = 0x0040_0000;

impl WindowManager {
    /// Redraw in canonical parent/client coordinates; injected mapper owns cross-window DPI conversion.
    /// Mapper returns parent-client coverage scaled into the child's DPI, before child-origin subtraction.
    /// # C: O(windows² + region operations); # Sleeps: no
    pub fn redraw_tree<F>(&mut self, root: WindowId, input: Option<&PaintRegion>, flags: u32, mut map: F) -> Result<(), WindowError>
    where F: FnMut(WindowId, WindowId, &PaintRegion) -> Result<PaintRegion, WindowError> {
        let record = self.get(root).ok_or(WindowError::NoSuchWindow)?;
        let mut ancestor = Some(root);
        for depth in 0..=self.windows.len() {
            let Some(id) = ancestor else { break; };
            if depth == self.windows.len() { return Err(WindowError::InvalidParent); }
            let record = self.get(id).ok_or(WindowError::NoSuchWindow)?;
            if !record.visible { return Ok(()); } ancestor = record.parent;
        }
        let input = if flags & (RDW_INVALIDATE | RDW_VALIDATE) == 0 { None }
            else if record.ex_style & WS_EX_LAYOUTRTL != 0 {
                input.map(|r| r.mirrored(self.client_rect(root).ok_or(WindowError::NoSuchWindow)?.right)).transpose()?
            } else { input.map(PaintRegion::try_copy).transpose()? };
        let mut stack = Vec::new(); stack.try_reserve(1).map_err(|_| WindowError::NoMemory)?;
        stack.push((root, input, flags, false));
        let mut visited = 0usize;
        while let Some((id, input, flags, nested)) = stack.pop() {
            visited += 1; if visited > self.windows.len() { return Err(WindowError::InvalidParent); }
            self.redraw_damage(id, input.as_ref(), flags, nested)?;
            let record = self.get(id).ok_or(WindowError::NoSuchWindow)?;
            if flags & RDW_NOCHILDREN != 0 || record.style & WS_MINIMIZE != 0
                || record.style & WS_CLIPCHILDREN != 0 && flags & RDW_ALLCHILDREN == 0 { continue; }
            let client = self.client_rect(id).ok_or(WindowError::NoSuchWindow)?;
            let coverage = match input { Some(region) => region.clipped(client)?, None => PaintRegion::from_rect(client)? };
            let child_flags = if flags & RDW_INVALIDATE != 0 { flags | RDW_FRAME | RDW_ERASE } else { flags };
            for (child, record) in &self.windows {
                if record.parent != Some(id) || !record.visible { continue; }
                let frame = self.rect(*child).ok_or(WindowError::NoSuchWindow)?;
                let origin = record.client_rect.unwrap_or(frame);
                let clipped = map(id, *child, &coverage)?.clipped(frame)?;
                if clipped.is_empty() { continue; }
                let local = clipped.translated(origin.left.checked_neg().ok_or(WindowError::InvalidParent)?,
                    origin.top.checked_neg().ok_or(WindowError::InvalidParent)?)?;
                stack.try_reserve(1).map_err(|_| WindowError::NoMemory)?;
                stack.push((*child, Some(local), child_flags, true));
            }
        }
        Ok(())
    }
}
