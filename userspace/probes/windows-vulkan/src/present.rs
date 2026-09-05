use crate::{Capability, KNOWN_FORMATS, ARGB8888, XRGB8888};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SurfaceFormat { Xrgb8888, Argb8888 }

impl SurfaceFormat {
    fn mask(self) -> u64 {
        match self { Self::Xrgb8888 => XRGB8888, Self::Argb8888 => ARGB8888 }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SurfaceDescription {
    /// Stable identity of the process-scoped present session.
    pub session: u64,
    pub window: u64,
    pub window_owner: u64,
    pub device: u64,
    pub queue: u64,
    pub resource: u64,
    pub device_ready: bool,
    pub surface_alive: bool,
    pub present_supported: bool,
    pub width: u32,
    pub height: u32,
    pub format: SurfaceFormat,
}

/// Identity transferred from the canonical user32 owner to the Vulkan queue.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SurfaceHandoff { pub session: u64, pub window: u64, pub window_owner: u64, pub device: u64, pub queue: u64, pub resource: u64 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HandoffResult { Submitted, Rejected }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SurfaceState { Ready, Acquired, Lost }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PresentError { Unsupported, InvalidState, NotOwned, QueueRejected }

pub struct PresentSession {
    capability: Capability,
    description: SurfaceDescription,
    state: SurfaceState,
}

impl PresentSession {
    /// Admit one surface only when the native device and WSI facts agree. # C: O(1)
    pub fn create(capability: Capability, description: SurfaceDescription) -> Result<Self, PresentError> {
        if capability.version != crate::CAPABILITY_VERSION || !capability.render_node || !capability.three_d
            || capability.format_mask == 0 || capability.format_mask & !KNOWN_FORMATS != 0
            || description.session == 0 || description.window == 0 || description.window_owner == 0
            || description.device == 0 || description.queue == 0 || description.resource == 0
            || !description.device_ready || !description.surface_alive || !description.present_supported
            || description.width == 0 || description.height == 0
            || description.width > capability.max_width || description.height > capability.max_height
            || capability.format_mask & description.format.mask() == 0 {
            return Err(PresentError::Unsupported);
        }
        Ok(Self { capability, description, state: SurfaceState::Ready })
    }

    /// Validate and reserve one canonical window/resource handoff. # C: O(1)
    pub fn acquire(&mut self, handoff: SurfaceHandoff) -> Result<(), PresentError> {
        if self.state != SurfaceState::Ready || !self.description.surface_alive { return Err(PresentError::InvalidState); }
        if handoff.session == 0 || handoff.session != self.description.session
            || handoff.window == 0 || handoff.window != self.description.window
            || handoff.window_owner == 0 || handoff.window_owner != self.description.window_owner
            || handoff.device == 0 || handoff.device != self.description.device
            || handoff.queue == 0 || handoff.queue != self.description.queue
            || handoff.resource == 0 || handoff.resource != self.description.resource {
            return Err(PresentError::NotOwned);
        }
        self.state = SurfaceState::Acquired;
        Ok(())
    }

    /// Commit a queue submission or roll the reservation back on rejection. # C: O(1)
    pub fn present(&mut self, result: HandoffResult) -> Result<(), PresentError> {
        if self.state != SurfaceState::Acquired || !self.description.present_supported { return Err(PresentError::InvalidState); }
        self.state = SurfaceState::Ready;
        match result { HandoffResult::Submitted => Ok(()), HandoffResult::Rejected => Err(PresentError::QueueRejected) }
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
        Capability { version: 1, render_node: true, three_d: true, max_width: 4096, max_height: 2160, format_mask: XRGB8888 | ARGB8888 }
    }

    fn surface() -> SurfaceDescription {
        SurfaceDescription { session: 3, window: 41, window_owner: 7, device: 11, queue: 13, resource: 17, device_ready: true, surface_alive: true, present_supported: true, width: 1280, height: 720, format: SurfaceFormat::Xrgb8888 }
    }

    fn handoff() -> SurfaceHandoff { SurfaceHandoff { session: 3, window: 41, window_owner: 7, device: 11, queue: 13, resource: 17 } }

    #[test]
    fn present_requires_acquire_and_returns_to_ready() {
        let mut session = PresentSession::create(capability(), surface()).unwrap();
        assert_eq!(session.state(), SurfaceState::Ready);
        assert_eq!(session.present(HandoffResult::Submitted), Err(PresentError::InvalidState));
        session.acquire(handoff()).unwrap();
        assert_eq!(session.state(), SurfaceState::Acquired);
        session.present(HandoffResult::Submitted).unwrap();
        assert_eq!(session.state(), SurfaceState::Ready);
        session.acquire(handoff()).unwrap();
        session.present(HandoffResult::Submitted).unwrap();
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
    fn admission_rejects_missing_identity_and_unknown_format_bits() {
        assert!(matches!(PresentSession::create(capability(), SurfaceDescription { session: 0, ..surface() }), Err(PresentError::Unsupported)));
        assert!(matches!(PresentSession::create(capability(), SurfaceDescription { resource: 0, ..surface() }), Err(PresentError::Unsupported)));
        assert!(matches!(PresentSession::create(Capability { format_mask: KNOWN_FORMATS | 8, ..capability() }, surface()), Err(PresentError::Unsupported)));
    }

    #[test]
    fn loss_is_terminal_and_cannot_reacquire_or_present() {
        let mut session = PresentSession::create(capability(), surface()).unwrap();
        session.lose();
        assert_eq!(session.state(), SurfaceState::Lost);
        assert_eq!(session.acquire(handoff()), Err(PresentError::InvalidState));
        assert_eq!(session.present(HandoffResult::Submitted), Err(PresentError::InvalidState));
    }

    #[test]
    fn handoff_requires_the_canonical_window_and_queue_owners() {
        let mut session = PresentSession::create(capability(), surface()).unwrap();
        assert_eq!(session.acquire(SurfaceHandoff { queue: 99, ..handoff() }), Err(PresentError::NotOwned));
        assert_eq!(session.state(), SurfaceState::Ready);
        session.acquire(handoff()).unwrap();
        assert_eq!(session.present(HandoffResult::Rejected), Err(PresentError::QueueRejected));
        assert_eq!(session.state(), SurfaceState::Ready);
    }

    #[test]
    fn handoff_cannot_cross_a_present_session() {
        let mut session = PresentSession::create(capability(), surface()).unwrap();
        assert_eq!(session.acquire(SurfaceHandoff { session: 4, ..handoff() }), Err(PresentError::NotOwned));
        assert_eq!(session.state(), SurfaceState::Ready);
    }

    #[test]
    fn every_identity_is_checked_before_reservation() {
        let fields = [
            SurfaceHandoff { session: 0, ..handoff() },
            SurfaceHandoff { window: 0, ..handoff() },
            SurfaceHandoff { window_owner: 0, ..handoff() },
            SurfaceHandoff { device: 0, ..handoff() },
            SurfaceHandoff { queue: 0, ..handoff() },
            SurfaceHandoff { resource: 0, ..handoff() },
        ];
        for candidate in fields {
            let mut session = PresentSession::create(capability(), surface()).unwrap();
            assert_eq!(session.acquire(candidate), Err(PresentError::NotOwned));
            assert_eq!(session.state(), SurfaceState::Ready);
        }
    }
}
