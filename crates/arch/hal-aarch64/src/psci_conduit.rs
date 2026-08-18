//! Boot-selected PSCI conduit state.

use core::sync::atomic::{AtomicU8, Ordering};

use crate::smccc::Conduit;

const NONE: u8 = 0;
const SMC: u8 = 1;
const HVC: u8 = 2;

static CONDUIT: AtomicU8 = AtomicU8::new(NONE);

/// Publish the firmware-selected conduit before any PSCI caller runs.
/// # C: O(1)
pub fn configure(conduit: Conduit) {
    let value = match conduit { Conduit::Smc => SMC, Conduit::Hvc => HVC };
    CONDUIT.store(value, Ordering::Release);
}

/// Return the selected conduit, or `None` before firmware has supplied one.
/// # C: O(1)
pub fn conduit() -> Option<Conduit> {
    match CONDUIT.load(Ordering::Acquire) {
        SMC => Some(Conduit::Smc),
        HVC => Some(Conduit::Hvc),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_round_trips_the_firmware_method() {
        configure(Conduit::Smc);
        assert_eq!(conduit(), Some(Conduit::Smc));
        configure(Conduit::Hvc);
        assert_eq!(conduit(), Some(Conduit::Hvc));
    }
}
