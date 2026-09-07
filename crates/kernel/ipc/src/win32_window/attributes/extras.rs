//! Help context, layered appearance and window region, stored beside the
//! window record so no call invents a second window table.
use super::*;

impl WindowManager {
    fn attributes(&self, id: WindowId) -> Option<&WindowAttributes> {
        self.attributes.iter().find(|(window, _)| *window == id).map(|(_, entry)| entry)
    }

    fn attributes_mut(&mut self, id: WindowId) -> Result<&mut WindowAttributes, WindowError> {
        self.get(id).ok_or(WindowError::NoSuchWindow)?;
        if let Some(index) = self.attributes.iter().position(|(window, _)| *window == id) {
            return Ok(&mut self.attributes[index].1);
        }
        self.attributes.try_reserve(1).map_err(|_| WindowError::NoMemory)?;
        self.attributes.push((id, WindowAttributes::default()));
        Ok(&mut self.attributes.last_mut().expect("just pushed").1)
    }

    /// Discard the attributes of a destroyed window. # C: O(N_windows)
    pub fn forget_attributes(&mut self, id: WindowId) {
        self.attributes.retain(|(window, _)| *window != id);
    }

    /// Help context identifier; a window that never set one answers zero.
    /// # C: O(N_windows)
    pub fn help_context(&self, id: WindowId) -> u32 {
        self.attributes(id).map_or(0, |entry| entry.help_context)
    }

    /// Set the help context identifier. # C: O(N_windows)
    pub fn set_help_context(&mut self, id: WindowId, context: u32) -> Result<(), WindowError> {
        self.attributes_mut(id)?.help_context = context;
        Ok(())
    }

    /// Layered appearance, present only after it has been set. # C: O(N_windows)
    pub fn layered_attributes(&self, id: WindowId) -> Option<LayeredAttributes> {
        self.attributes(id).and_then(|entry| entry.layered)
    }

    /// Set the layered appearance and mark the window layered. # C: O(N_windows)
    pub fn set_layered_attributes(&mut self, id: WindowId, attributes: LayeredAttributes) -> Result<(), WindowError> {
        self.attributes_mut(id)?.layered = Some(attributes);
        self.set_ex_style_bits(id, WS_EX_LAYERED, 0)?;
        Ok(())
    }

    /// A per-pixel layered update is refused for a window that is not layered,
    /// that carries an unknown flag, or that already has colour-key or alpha
    /// attributes set; a resize is refused outright when the caller forbade
    /// one. # C: O(N_windows)
    pub fn admit_layered_update(&self, id: WindowId, flags: u32, size: Option<(i32, i32)>)
        -> Result<(), WindowError> {
        let record = self.get(id).ok_or(WindowError::NoSuchWindow)?;
        if flags & !(ULW_COLORKEY | ULW_ALPHA | ULW_OPAQUE | ULW_EX_NORESIZE) != 0 { return Err(WindowError::InvalidParameter); }
        if record.ex_style & WS_EX_LAYERED == 0 { return Err(WindowError::InvalidParameter); }
        if self.layered_attributes(id).is_some() { return Err(WindowError::InvalidParameter); }
        let Some((width, height)) = size else { return Ok(()) };
        if width <= 0 || height <= 0 { return Err(WindowError::InvalidParameter); }
        let rect = self.rect(id).ok_or(WindowError::NoSuchWindow)?;
        let resized = width != rect.right - rect.left || height != rect.bottom - rect.top;
        if flags & ULW_EX_NORESIZE != 0 && resized { return Err(WindowError::InvalidParameter); }
        Ok(())
    }

    /// Window region as a rectangle list, absent when the window has none.
    /// # C: O(N_windows)
    pub fn window_region(&self, id: WindowId) -> Option<&[WindowRect]> {
        self.attributes(id).and_then(|entry| entry.region.as_deref())
    }

    /// Install or clear the window region. An installed region is stored in
    /// window coordinates, as the caller supplies it. # C: O(N_windows + N_rects)
    pub fn set_window_region(&mut self, id: WindowId, region: Option<&[WindowRect]>) -> Result<(), WindowError> {
        let stored = match region {
            None => None,
            Some(rects) => {
                let mut owned = Vec::new();
                owned.try_reserve_exact(rects.len()).map_err(|_| WindowError::NoMemory)?;
                owned.extend_from_slice(rects);
                Some(owned)
            }
        };
        self.attributes_mut(id)?.region = stored;
        Ok(())
    }

    /// Whether the non-client area is drawn active. # C: O(N_windows)
    pub fn nc_activated(&self, id: WindowId) -> bool {
        self.attributes(id).is_some_and(|entry| entry.nc_activated)
    }

    /// Set the non-client active state. # C: O(N_windows)
    pub fn set_nc_activated(&mut self, id: WindowId, active: bool) -> Result<(), WindowError> {
        self.attributes_mut(id)?.nc_activated = active;
        Ok(())
    }

    /// Display affinity: no window here is excluded from capture, so the query
    /// answers only whether the window exists. # C: O(N_windows)
    pub fn display_affinity(&self, id: WindowId) -> Result<u32, WindowError> {
        self.get(id).ok_or(WindowError::NoSuchWindow)?;
        Ok(WDA_NONE)
    }
}
