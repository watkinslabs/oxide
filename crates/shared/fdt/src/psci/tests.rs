use super::*;
use crate::fixture::Fdt;

fn tree(compatible: &[u8], method: &[u8]) -> alloc::vec::Vec<u8> {
    let mut fdt = Fdt::new();
    fdt.begin("").begin("psci").prop("compatible", compatible).prop("method", method).end().end();
    fdt.finish()
}

#[test]
fn a_compatible_psci_node_selects_its_exact_method() {
    assert_eq!(psci_conduit(&tree(b"arm,psci-1.0\0arm,psci-0.2\0arm,psci\0", b"hvc\0")), Some(PsciConduit::Hvc));
    assert_eq!(psci_conduit(&tree(b"arm,psci\0", b"smc\0")), Some(PsciConduit::Smc));
}

#[test]
fn a_non_psci_node_or_invalid_method_cannot_select_a_conduit() {
    assert_eq!(psci_conduit(&tree(b"vendor,psci-lookalike\0", b"hvc\0")), None);
    assert_eq!(psci_conduit(&tree(b"arm,psci-0.2\0", b"hvc\0smc\0")), None);
}
