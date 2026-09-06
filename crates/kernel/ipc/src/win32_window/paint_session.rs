//! Canonical HWND paint-session ownership (`31fj`).

use super::{WindowId, WindowManager, WindowRect, PaintRegion};

/// One admitted paint transaction and the exact fresh canonical paint HDC.
#[derive(Debug, Eq, PartialEq)]
pub struct PaintSession { pub damage: Option<WindowRect>, pub dc: u32, pub region: PaintRegion, pub erase: bool, pub nonclient: bool, pub delayed_erase: bool }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PaintSessionError { Active, NotActive, DcMismatch, Unbound, InvalidDc, NoMemory }

impl PaintSession {
    /// Fallible exact-region snapshot; no implicit allocating Clone. # C: O(N_rectangles)
    pub fn try_copy(&self) -> Result<Self, PaintSessionError> {
        self.copy_with(PaintRegion::try_copy)
    }
    fn copy_with(&self, copy: impl FnOnce(&PaintRegion) -> Result<PaintRegion, super::WindowError>) -> Result<Self, PaintSessionError> {
        Ok(Self { damage: self.damage, dc: self.dc, region: copy(&self.region).map_err(|_| PaintSessionError::NoMemory)?,
            erase: self.erase, nonclient: self.nonclient, delayed_erase: self.delayed_erase })
    }
    fn validate_dc(&self, dc: u32) -> Result<(), PaintSessionError> {
        if self.dc == 0 { return Err(PaintSessionError::Unbound); }
        if self.dc != dc { return Err(PaintSessionError::DcMismatch); }
        Ok(())
    }
    fn bind_with(&mut self, dc: u32, copy: impl FnOnce(&PaintRegion) -> Result<PaintRegion, super::WindowError>) -> Result<Self, PaintSessionError> {
        if dc == 0 { return Err(PaintSessionError::InvalidDc); }
        if self.dc != 0 { return Err(PaintSessionError::Active); }
        let mut snapshot = self.copy_with(copy)?;
        self.dc = dc; snapshot.dc = dc; Ok(snapshot)
    }
}

impl WindowManager {
    /// Attach one fresh canonical paint HDC to an existing reservation.
    /// # C: O(N_painting + N_rectangles)
    pub fn bind_paint_dc(&mut self, window: WindowId, dc: u32) -> Result<PaintSession, PaintSessionError> {
        if dc == 0 { return Err(PaintSessionError::InvalidDc); }
        let (_, session) = self.painting.iter_mut().find(|(candidate, _)| *candidate == window).ok_or(PaintSessionError::NotActive)?;
        session.bind_with(dc, PaintRegion::try_copy)
    }

    /// Return the canonical session for one HWND without consuming it.
    /// # C: O(N_painting + N_rectangles)
    pub fn paint_session(&self, window: WindowId) -> Result<PaintSession, PaintSessionError> {
        self.painting.iter().find(|(candidate, _)| *candidate == window).ok_or(PaintSessionError::NotActive)?.1.try_copy()
    }

    /// Validate EndPaint's exact fresh HDC without consuming the session.
    /// # C: O(N_painting + N_rectangles)
    pub fn validate_paint_session(&self, window: WindowId, dc: u32) -> Result<PaintSession, PaintSessionError> {
        let (_, session) = self.painting.iter().find(|(candidate, _)| *candidate == window).ok_or(PaintSessionError::NotActive)?;
        session.validate_dc(dc)?;
        session.try_copy()
    }

    /// Consume a session only after EndPaint validation and presentation.
    /// # C: O(N_painting)
    pub fn end_paint_session(&mut self, window: WindowId, dc: u32) -> Result<PaintSession, PaintSessionError> {
        let index = self.painting.iter().position(|(candidate, _)| *candidate == window).ok_or(PaintSessionError::NotActive)?;
        self.painting[index].1.validate_dc(dc)?;
        Ok(self.painting.remove(index).1)
    }

    /// Consume a session during canonical HWND destruction.
    /// # C: O(N_painting)
    pub fn remove_paint_session(&mut self, window: WindowId) -> Option<PaintSession> {
        let index = self.painting.iter().position(|(candidate, _)| *candidate == window)?;
        Some(self.painting.remove(index).1)
    }
}

#[cfg(test)]
#[path = "paint_session/tests.rs"]
mod tests;
