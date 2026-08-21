//! Boot-source selection for the one architecture PSCI conduit.

/// Firmware-selected PSCI invocation instruction.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Conduit { Smc, Hvc }

#[cfg(any(target_arch = "aarch64", test))]
fn select(acpi_boot: bool, acpi: Option<Conduit>, dt: Option<Conduit>) -> Option<Conduit> {
    if acpi_boot { acpi } else { dt }
}

/// Install the conduit from the firmware source that owns this boot. # C: O(FDT)
#[cfg(target_arch = "aarch64")]
pub fn init(acpi_boot: bool) -> bool {
    let Some(conduit) = select(acpi_boot, crate::acpi::psci::conduit(), crate::fdt::psci::conduit()) else { return false; };
    let conduit = match conduit {
        Conduit::Smc => hal_aarch64::smccc::Conduit::Smc,
        Conduit::Hvc => hal_aarch64::smccc::Conduit::Hvc,
    };
    hal_aarch64::psci_conduit::configure(conduit);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acpi_boot_never_falls_back_to_or_accepts_the_dt_binding() {
        assert_eq!(select(true, Some(Conduit::Smc), Some(Conduit::Hvc)), Some(Conduit::Smc));
        assert_eq!(select(true, None, Some(Conduit::Hvc)), None);
        assert_eq!(select(false, Some(Conduit::Smc), Some(Conduit::Hvc)), Some(Conduit::Hvc));
    }
}
