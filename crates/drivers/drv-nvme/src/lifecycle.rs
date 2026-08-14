#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupStep {
    ReleaseController,
    DisablePciCommand,
}

const REMOVE_CLEANUP_STEPS: [CleanupStep; 2] = [
    CleanupStep::ReleaseController,
    CleanupStep::DisablePciCommand,
];

const PROBE_FAILURE_CLEANUP_STEPS: [CleanupStep; 1] = [
    CleanupStep::DisablePciCommand,
];

/// A synchronous wait may recover only after its completion predicate remains
/// false at the deadline. Equality is expired so a clock read at the deadline
/// cannot leave a dead controller's request permanently owned.
/// # C: O(1)
pub(crate) const fn deadline_expired(completed: bool, now_ns: u64, deadline_ns: u64) -> bool {
    !completed && async_deadline_expired(now_ns, deadline_ns)
}

/// An in-flight asynchronous owner expires at its absolute deadline. # C: O(1)
pub(crate) const fn async_deadline_expired(now_ns: u64, deadline_ns: u64) -> bool {
    now_ns >= deadline_ns
}

/// The timeout worker sends one Admin Abort for a live I/O owner, then resets
/// only if that same owner survives its renewed deadline. `None` means the
/// CID completed while timeout work was being queued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AsyncTimeoutAction { Abort, Reset }

/// Select the bounded timeout action for one canonical CID owner. # C: O(1)
pub(crate) const fn async_timeout_action(
    now_ns: u64, deadline_ns: u64, abort_started: bool,
) -> Option<AsyncTimeoutAction> {
    if !async_deadline_expired(now_ns, deadline_ns) { return None; }
    if abort_started { Some(AsyncTimeoutAction::Reset) } else { Some(AsyncTimeoutAction::Abort) }
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

/// Release interrupt state before the BAR mapping holding its table is dropped.
/// # C: O(release + drop)
pub(crate) fn release_probe_irq_then_drop<M, R>(mut release_irq: R, mapping: M)
where
    R: FnMut(),
{
    release_irq();
    drop(mapping);
}

#[cfg(test)]
mod tests {
    use super::{AsyncTimeoutAction, async_deadline_expired, async_timeout_action, deadline_expired, release_probe_irq_then_drop, run_probe_failure_cleanup, run_remove_cleanup};

    #[test]
    fn deadline_recovery_waits_for_an_uncompleted_request() {
        assert!(!deadline_expired(true, 17, 16));
        assert!(!deadline_expired(false, 15, 16));
        assert!(deadline_expired(false, 16, 16));
        assert!(deadline_expired(false, 17, 16));
    }

    #[test]
    fn asynchronous_owner_expires_at_its_absolute_deadline() {
        assert!(!async_deadline_expired(15, 16));
        assert!(async_deadline_expired(16, 16));
        assert!(async_deadline_expired(17, 16));
    }

    #[test]
    fn timed_out_io_gets_one_abort_then_a_second_expiry_resets() {
        assert_eq!(async_timeout_action(15, 16, false), None);
        assert_eq!(async_timeout_action(16, 16, false), Some(AsyncTimeoutAction::Abort));
        assert_eq!(async_timeout_action(16, 16, true), Some(AsyncTimeoutAction::Reset));
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

    #[test]
    fn failed_probe_releases_irq_before_bar_drop() {
        struct Bar<'a>(&'a core::cell::Cell<u8>);
        impl Drop for Bar<'_> { fn drop(&mut self) { assert_eq!(self.0.get(), 1); self.0.set(2); } }
        let order = core::cell::Cell::new(0);
        release_probe_irq_then_drop(|| { order.set(1); }, Bar(&order));
        assert_eq!(order.get(), 2);
    }
}
