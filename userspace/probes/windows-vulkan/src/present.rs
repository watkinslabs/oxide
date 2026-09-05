use crate::Capability;

const XRGB8888_MASK: u64 = 1;
const ARGB8888_MASK: u64 = 2;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SurfaceFormat { Xrgb8888, Argb8888 }

impl SurfaceFormat {
    fn mask(self) -> u64 {
        match self { Self::Xrgb8888 => XRGB8888_MASK, Self::Argb8888 => ARGB8888_MASK }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SurfaceDescription {
    pub device_ready: bool,
    pub surface_alive: bool,
    pub present_supported: bool,
    pub width: u32,
    pub height: u32,
    pub format: SurfaceFormat,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SurfaceState { Ready, Acquired, Lost }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PresentError { Unsupported, InvalidState }

pub struct PresentSession {
    capability: Capability,
    description: SurfaceDescription,
    state: SurfaceState,
}

impl PresentSession {
    /// Admit one surface only when the native device and WSI facts agree. # C: O(1)
    pub fn create(capability: Capability, description: SurfaceDescription) -> Result<Self, PresentError> {
        if !description.device_ready || !description.surface_alive || !description.present_supported
            || description.width == 0 || description.height == 0
            || description.width > capability.max_width || description.height > capability.max_height
            || capability.format_mask & description.format.mask() == 0 {
            return Err(PresentError::Unsupported);
        }
        Ok(Self { capability, description, state: SurfaceState::Ready })
    }

    /// Reserve the ready surface for one present operation. # C: O(1)
    pub fn acquire(&mut self) -> Result<(), PresentError> {
        if self.state != SurfaceState::Ready || !self.description.surface_alive { return Err(PresentError::InvalidState); }
        self.state = SurfaceState::Acquired;
        Ok(())
    }

    /// Return the acquired surface to the ready state after queue submission. # C: O(1)
    pub fn present(&mut self) -> Result<(), PresentError> {
        if self.state != SurfaceState::Acquired || !self.description.present_supported { return Err(PresentError::InvalidState); }
        self.state = SurfaceState::Ready;
        Ok(())
    }

    /// Retire a surface after the native WSI reports loss or device removal. # C: O(1)
    pub fn lose(&mut self) { self.state = SurfaceState::Lost; }

    pub fn state(&self) -> SurfaceState { self.state }

    pub fn dimensions(&self) -> (u32, u32) { (self.description.width, self.description.height) }

    pub fn max_dimensions(&self) -> (u32, u32) { (self.capability.max_width, self.capability.max_height) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability() -> Capability {
        Capability { version: 1, render_node: true, three_d: true, max_width: 4096, max_height: 2160, format_mask: XRGB8888_MASK | ARGB8888_MASK }
    }

    fn surface() -> SurfaceDescription {
        SurfaceDescription { device_ready: true, surface_alive: true, present_supported: true, width: 1280, height: 720, format: SurfaceFormat::Xrgb8888 }
    }

    #[test]
    fn present_requires_acquire_and_returns_to_ready() {
        let mut session = PresentSession::create(capability(), surface()).unwrap();
        assert_eq!(session.state(), SurfaceState::Ready);
        assert_eq!(session.present(), Err(PresentError::InvalidState));
        session.acquire().unwrap();
        assert_eq!(session.state(), SurfaceState::Acquired);
        session.present().unwrap();
        assert_eq!(session.state(), SurfaceState::Ready);
        session.acquire().unwrap();
        session.present().unwrap();
        assert_eq!(session.state(), SurfaceState::Ready);
    }

    #[test]
    fn admission_rejects_unsupported_device_surface_and_format() {
        assert!(matches!(PresentSession::create(capability(), SurfaceDescription { device_ready: false, ..surface() }), Err(PresentError::Unsupported)));
        assert!(matches!(PresentSession::create(capability(), SurfaceDescription { surface_alive: false, ..surface() }), Err(PresentError::Unsupported)));
        assert!(matches!(PresentSession::create(capability(), SurfaceDescription { present_supported: false, ..surface() }), Err(PresentError::Unsupported)));
        assert!(matches!(PresentSession::create(capability(), SurfaceDescription { width: 4097, ..surface() }), Err(PresentError::Unsupported)));
        assert_eq!(PresentSession::create(capability(), SurfaceDescription { format: SurfaceFormat::Argb8888, ..surface() }).unwrap().dimensions(), (1280, 720));
    }

    #[test]
    fn loss_is_terminal_and_cannot_reacquire_or_present() {
        let mut session = PresentSession::create(capability(), surface()).unwrap();
        session.lose();
        assert_eq!(session.state(), SurfaceState::Lost);
        assert_eq!(session.acquire(), Err(PresentError::InvalidState));
        assert_eq!(session.present(), Err(PresentError::InvalidState));
    }
}
