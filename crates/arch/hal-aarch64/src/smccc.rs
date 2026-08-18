//! ARM SMCCC v1.1 conduit calls.
//!
//! PSCI has a four-register wrapper with PSCI-specific status semantics. SCMI
//! uses the general SMCCC calling convention instead, where firmware may
//! clobber `x0..x17`; that ownership belongs here.

/// SMCCC conduit selected by the firmware transport binding.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Conduit { Smc, Hvc }

/// Registers returned from an SMCCC v1.1 call.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Result { pub registers: [u64; 8] }

impl Result {
    /// Value returned in `x0`. # C: O(1)
    pub const fn a0(self) -> u64 { self.registers[0] }
}

/// Call an SMCCC v1.1 service with arguments in `x0..x7`.
///
/// # Safety
/// The selected conduit and arguments must name a service the current
/// firmware permits at EL1. The caller must also satisfy that service's
/// serialization and shared-memory ordering rules.
/// # C: O(firmware round-trip)
pub unsafe fn call(conduit: Conduit, arguments: [u64; 8]) -> Result {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let mut x0 = arguments[0];
        let mut x1 = arguments[1];
        let mut x2 = arguments[2];
        let mut x3 = arguments[3];
        let mut x4 = arguments[4];
        let mut x5 = arguments[5];
        let mut x6 = arguments[6];
        let mut x7 = arguments[7];
        macro_rules! invoke {
            ($instruction:literal) => {
                core::arch::asm!(
                    $instruction,
                    inlateout("x0") x0, inlateout("x1") x1, inlateout("x2") x2,
                    inlateout("x3") x3, inlateout("x4") x4, inlateout("x5") x5,
                    inlateout("x6") x6, inlateout("x7") x7,
                    lateout("x8") _, lateout("x9") _, lateout("x10") _, lateout("x11") _,
                    lateout("x12") _, lateout("x13") _, lateout("x14") _, lateout("x15") _,
                    lateout("x16") _, lateout("x17") _, options(nostack),
                );
            };
        }
        // SAFETY: caller established that this firmware service and conduit
        // are valid. The explicit fixed-register operands model SMCCC's
        // inputs, returned x0..x7, and every x8..x17 clobber.
        unsafe {
            match conduit {
                Conduit::Smc => { invoke!(".inst 0xd4000003"); }
                Conduit::Hvc => { invoke!(".inst 0xd4000002"); }
            }
        }
        Result { registers: [x0, x1, x2, x3, x4, x5, x6, x7] }
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    {
        let _ = (conduit, arguments);
        Result { registers: [u64::MAX; 8] }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosted_call_reports_the_standard_not_supported_value() {
        // SAFETY: the hosted implementation makes no firmware call.
        let result = unsafe { call(Conduit::Smc, [0; 8]) };
        assert_eq!(result.a0(), u64::MAX);
    }
}
