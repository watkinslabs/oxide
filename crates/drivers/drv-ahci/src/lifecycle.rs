#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupStep {
    ReleaseController,
    DisablePciCommand,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerCleanupStep {
    MaskAndFreeIrq,
    SynchronizeIrq,
    ReleaseController,
}

const CONTROLLER_CLEANUP_STEPS: [ControllerCleanupStep; 3] = [
    ControllerCleanupStep::MaskAndFreeIrq,
    ControllerCleanupStep::SynchronizeIrq,
    ControllerCleanupStep::ReleaseController,
];

const REMOVE_CLEANUP_STEPS: [CleanupStep; 2] = [
    CleanupStep::ReleaseController,
    CleanupStep::DisablePciCommand,
];

const PROBE_FAILURE_CLEANUP_STEPS: [CleanupStep; 1] = [
    CleanupStep::DisablePciCommand,
];

/// AHCI-owned teardown order before PCI command restoration. # C: O(1)
pub(crate) fn controller_cleanup_steps() -> [ControllerCleanupStep; 3] {
    CONTROLLER_CLEANUP_STEPS
}

/// Run remove/shutdown cleanup in Linux teardown order: quiesce owned hardware
/// and drop BAR mappings before disabling PCI command decode.
/// # C: O(release + disable)
pub(crate) fn run_remove_cleanup<R, D>(mut release_controller: R, mut disable_pci_command: D)
where
    R: FnMut(),
    D: FnMut(),
{
    for step in REMOVE_CLEANUP_STEPS {
        match step {
            CleanupStep::ReleaseController => release_controller(),
            CleanupStep::DisablePciCommand => disable_pci_command(),
        }
    }
}

/// Run failed-probe cleanup after an attempted controller init has returned and
/// any owned BAR mapping passed to it has dropped through RAII.
/// # C: O(disable)
pub(crate) fn run_probe_failure_cleanup<D>(mut disable_pci_command: D)
where
    D: FnMut(),
{
    for step in PROBE_FAILURE_CLEANUP_STEPS {
        match step {
            CleanupStep::ReleaseController => {}
            CleanupStep::DisablePciCommand => disable_pci_command(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        controller_cleanup_steps, run_probe_failure_cleanup, run_remove_cleanup,
        ControllerCleanupStep,
    };

    #[test]
    fn irq_is_masked_and_synchronized_before_controller_release() {
        assert_eq!(
            controller_cleanup_steps(),
            [
                ControllerCleanupStep::MaskAndFreeIrq,
                ControllerCleanupStep::SynchronizeIrq,
                ControllerCleanupStep::ReleaseController,
            ],
        );
    }

    #[test]
    fn remove_cleanup_releases_controller_before_pci_command_disable() {
        let steps = core::cell::Cell::new(0u16);
        run_remove_cleanup(
            || { steps.set((steps.get() << 8) | b'R' as u16); },
            || { steps.set((steps.get() << 8) | b'D' as u16); },
        );
        assert_eq!(steps.get(), u16::from_be_bytes(*b"RD"));
    }

    #[test]
    fn probe_failure_cleanup_disables_pci_command() {
        let mut disabled = false;
        run_probe_failure_cleanup(|| { disabled = true; });
        assert!(disabled);
    }
}
