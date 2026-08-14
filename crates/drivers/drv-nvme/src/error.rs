//! NVMe PCI error-recovery vote mapping.

use drv::{PciChannelState, PciErsResult};

/// Map each PCI channel state to NVMe's recovery vote. # C: O(1)
pub(crate) const fn detected_result(state: PciChannelState) -> PciErsResult {
    match state {
        PciChannelState::Normal => PciErsResult::CanRecover,
        PciChannelState::Frozen => PciErsResult::NeedReset,
        PciChannelState::PermanentFailure => PciErsResult::Disconnect,
    }
}

#[cfg(target_os = "oxide-kernel")]
pub(crate) static HANDLERS: drv::PciErrorHandlers = drv::PciErrorHandlers {
    error_detected: Some(super::nvme_error_detected),
    mmio_enabled: None,
    slot_reset: Some(super::nvme_slot_reset),
    resume: None,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pci_error_detection_votes_match_channel_recoverability() {
        assert_eq!(detected_result(PciChannelState::Normal), PciErsResult::CanRecover);
        assert_eq!(detected_result(PciChannelState::Frozen), PciErsResult::NeedReset);
        assert_eq!(detected_result(PciChannelState::PermanentFailure), PciErsResult::Disconnect);
    }
}
