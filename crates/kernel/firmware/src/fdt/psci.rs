//! PSCI conduit installation from the retained device tree.

/// Decode a PSCI method and hand it to the architecture-owned conduit slot.
/// Returns false when firmware supplied no complete PSCI node. # C: O(FDT)
pub fn configure_from<F>(tree: &[u8], configure: F) -> bool
where F: FnOnce(::fdt::PsciConduit) {
    let Some(conduit) = ::fdt::psci_conduit(tree) else { return false; };
    configure(conduit);
    true
}

/// Install the architecture's PSCI conduit before any PSCI operation may run.
/// # C: O(FDT)
#[cfg(target_arch = "aarch64")]
pub fn init() -> bool {
    let Some(tree) = super::blob() else { return false; };
    configure_from(tree, |conduit| {
        let conduit = match conduit {
            ::fdt::PsciConduit::Smc => hal_aarch64::smccc::Conduit::Smc,
            ::fdt::PsciConduit::Hvc => hal_aarch64::smccc::Conduit::Hvc,
        };
        hal_aarch64::psci_conduit::configure(conduit);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::fdt::fixture::Fdt;

    fn tree(method: &str) -> alloc::vec::Vec<u8> {
        let mut fdt = Fdt::new();
        fdt.begin("").begin("psci").prop_str("compatible", "arm,psci-0.2").prop_str("method", method).end().end();
        fdt.finish()
    }

    #[test]
    fn only_a_complete_psci_node_configures_the_architecture() {
        let mut got = None;
        assert!(configure_from(&tree("smc"), |conduit| got = Some(conduit)));
        assert_eq!(got, Some(::fdt::PsciConduit::Smc));
        assert!(!configure_from(&tree("bad"), |_| unreachable!()));
    }
}
