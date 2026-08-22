//! VMA admission for the expensive page-fault resolver.

use vmm::{Error, FaultKind};

/// Proof that the fault address belongs to a VMA after optional stack growth.
/// The downstream resolver requires this token, keeping page-table migration,
/// swap, and userfaultfd work behind the same gate Linux applies first.
pub(super) struct Admitted(());

/// Find the fault's VMA, giving a not-present fault one stack-growth attempt.
/// # C: O(log N_vmas)
pub(super) fn fault_vma<P, G>(fault: FaultKind, mut present: P, mut grow: G)
    -> Result<Admitted, Error>
where
    P: FnMut() -> bool,
    G: FnMut(),
{
    if present() {
        return Ok(Admitted(()));
    }
    if matches!(fault, FaultKind::NotPresent { .. }) {
        grow();
        if present() {
            return Ok(Admitted(()));
        }
    }
    Err(Error::Inval)
}

#[cfg(test)]
#[path = "admit/tests.rs"] mod tests;
