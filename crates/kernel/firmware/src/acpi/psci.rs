//! ACPI FADT PSCI conduit ownership.

use core::sync::atomic::{AtomicU8, Ordering};

use crate::psci::Conduit;

const NONE: u8 = 0;
const SMC: u8 = 1;
const HVC: u8 = 2;
const PSCI_COMPLIANT: u16 = 1;
const PSCI_USE_HVC: u16 = 1 << 1;

static CONDUIT: AtomicU8 = AtomicU8::new(NONE);

fn decode(flags: u16) -> Option<Conduit> {
    if flags & PSCI_COMPLIANT == 0 { return None; }
    Some(if flags & PSCI_USE_HVC != 0 { Conduit::Hvc } else { Conduit::Smc })
}

/// Publish the FADT-owned conduit before SMP initialization. # C: O(1)
pub(crate) fn publish(flags: u16) {
    let value = match decode(flags) { Some(Conduit::Smc) => SMC, Some(Conduit::Hvc) => HVC, None => NONE };
    CONDUIT.store(value, Ordering::Release);
}

/// Return the retained ACPI PSCI conduit. # C: O(1)
#[cfg(target_arch = "aarch64")]
pub(crate) fn conduit() -> Option<Conduit> {
    match CONDUIT.load(Ordering::Acquire) { SMC => Some(Conduit::Smc), HVC => Some(Conduit::Hvc), _ => None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compliance_admits_smc_or_hvc_and_hvc_alone_admits_nothing() {
        assert_eq!(decode(0), None);
        assert_eq!(decode(PSCI_USE_HVC), None);
        assert_eq!(decode(PSCI_COMPLIANT), Some(Conduit::Smc));
        assert_eq!(decode(PSCI_COMPLIANT | PSCI_USE_HVC), Some(Conduit::Hvc));
    }
}
