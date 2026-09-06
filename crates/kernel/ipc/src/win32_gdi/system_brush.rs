//! Canonical default system-color roles and protected brush identities; 31fk§5.
use super::{GdiError, GdiManager};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemColor { Window, WindowText, Face, ButtonShadow, ButtonText, ButtonHighlight, DarkShadow, Light, Scrollbar }

impl SystemColor {
    /// Decode represented system-color indices without inventing a fallback. # C: O(1)
    pub fn from_index(index: u32) -> Option<Self> {
        match index { 5 => Some(Self::Window), 8 => Some(Self::WindowText), 15 => Some(Self::Face),
            16 => Some(Self::ButtonShadow), 18 => Some(Self::ButtonText), 20 => Some(Self::ButtonHighlight),
            21 => Some(Self::DarkShadow), 22 => Some(Self::Light), 0 => Some(Self::Scrollbar), _ => None }
    }
    /// Initial canonical XRGB palette; no COLORREF conversion at owner boundary. # C: O(1)
    pub const fn color(self) -> u32 {
        match self { Self::Window | Self::ButtonHighlight => 0x00ff_ffff, Self::WindowText | Self::ButtonText => 0,
            Self::Face | Self::Light | Self::Scrollbar => 0x00d4_d0c8, Self::ButtonShadow => 0x0080_8080, Self::DarkShadow => 0x0040_4040 }
    }
    const fn slot(self) -> usize { match self { Self::Window => 0, Self::WindowText => 1, Self::Face => 2,
        Self::ButtonShadow => 3, Self::ButtonText => 4, Self::ButtonHighlight => 5, Self::DarkShadow => 6, Self::Light => 7, Self::Scrollbar => 8 } }
}

#[derive(Default)]
pub struct SystemBrushes { handles: [Option<u32>; 9] }

impl GdiManager {
    /// Allocate at most one canonical solid brush for each represented role. # C: O(brushes)
    pub fn system_brush(&mut self, role: SystemColor) -> Result<u32, GdiError> {
        if let Some(handle) = self.system_brushes.handles[role.slot()] {
            return if self.contains_object(handle) { Ok(handle) } else { Err(GdiError::NoSuchObject) };
        }
        let handle = self.create_solid_brush(role.color())?;
        self.system_brushes.handles[role.slot()] = Some(handle);
        Ok(handle)
    }
    /// Both generic and brush-specific deletion check protection before mutation. # C: O(1)
    pub fn is_system_brush(&self, handle: u32) -> bool {
        self.system_brushes.handles.iter().any(|candidate| *candidate == Some(handle))
    }
}

#[cfg(test)]
#[path = "tests/system_brush.rs"]
mod tests;
