use super::*;
use crate::fixture::Fdt;

fn cells(values: &[u32]) -> alloc::vec::Vec<u8> {
    let mut data = alloc::vec::Vec::new();
    for value in values { data.extend_from_slice(&value.to_be_bytes()); }
    data
}

fn complete_tree(transport: &str, power_domain_cpu: bool, broken_transport: bool, a2p: Option<u32>) -> Fdt {
    let mut fdt = Fdt::new();
    fdt.begin("").prop_u32("#address-cells", 2).prop_u32("#size-cells", 2)
        .begin("cpus").prop_u32("#address-cells", 1).prop_u32("#size-cells", 0)
        .begin("cpu@0").prop_str("device_type", "cpu").prop_u32("reg", 0).prop("clocks", &cells(&[50, 7])).end()
        .begin("cpu@1").prop_str("device_type", "cpu").prop_u32("reg", 1).prop("clocks", &cells(&[50, 7])).end();
    if power_domain_cpu {
        fdt.begin("cpu@2").prop_str("device_type", "cpu").prop_u32("reg", 2)
            .prop("power-domains", &cells(&[50, 9])).prop_str("power-domain-names", "perf").end();
    }
    if a2p.is_some() {
        fdt.begin("intc").prop_str("compatible", "arm,gic-v3").prop_u32("phandle", 90).prop_u32("#interrupt-cells", 3).end();
    }
    fdt.end().begin("firmware").begin("scmi").prop_str("compatible", transport).prop_u32("arm,smc-id", 0xc300_0001)
        .prop("shmem", &cells(&[60]));
    if let Some(kind) = a2p {
        fdt.prop_u32("interrupt-parent", 90).prop("interrupts", &cells(&[kind, 41, 4])).prop_str("interrupt-names", "a2p");
    }
    fdt.prop_u32("#address-cells", 1).prop_u32("#size-cells", 0)
        .begin("protocol@13").prop_u32("phandle", 50).prop_u32("reg", 0x13).prop_u32("#clock-cells", 1).prop_u32("#power-domain-cells", 1).end().end().end()
        .begin("soc").prop_u32("#address-cells", 2).prop_u32("#size-cells", 2).prop("ranges", &[])
        .begin("sram@50000000").prop("reg", &cells(&[0, 0x5000_0000, 0, 0x1000])).prop_u32("#address-cells", 1).prop_u32("#size-cells", 1)
        .prop("ranges", &cells(&[0, 0, 0x5000_0000, 0x1000]))
        .begin("shmem@100").prop_str("compatible", "arm,scmi-shmem").prop_u32("phandle", 60).prop("reg", &cells(&[0x100, 0x400])).end().end().end();
    if broken_transport {
        fdt.begin("broken-bus").prop_u32("#address-cells", 1).prop_u32("#size-cells", 1)
            .begin("shmem@0").prop_str("compatible", "arm,scmi-shmem").prop_u32("phandle", 70).prop("reg", &cells(&[0, 0x100])).end().end()
            .begin("firmware2").begin("scmi").prop_str("compatible", "arm,scmi-smc").prop_u32("arm,smc-id", 1).prop("shmem", &cells(&[70]))
            .prop_u32("#address-cells", 1).prop_u32("#size-cells", 0).begin("protocol@13").prop_u32("phandle", 71).prop_u32("reg", 0x13).prop_u32("#clock-cells", 1).end().end().end();
    }
    fdt.end();
    fdt
}

#[test]
fn smc_perf_clock_domains_resolve_through_nested_ranges() {
    let protocols = scmi_perf_protocols(&complete_tree("arm,scmi-smc", false, false, None).finish());
    assert_eq!(protocols, alloc::vec![ScmiPerfProtocol {
        protocol_phandle: 50, smc_id: 0xc300_0001, transport: ScmiSmcTransport::Direct, completion_irq: None,
        shmem: ScmiSharedMemory { base_pa: 0x5000_0100, size: 0x400 },
        cpu_domains: alloc::vec![ScmiCpuDomain { cpu_mpidr: 0, domain_id: 7 }, ScmiCpuDomain { cpu_mpidr: 1, domain_id: 7 }],
    }]);
}

#[test]
fn smc_param_uses_the_page_and_offset_transport_form() {
    let protocols = scmi_perf_protocols(&complete_tree("arm,scmi-smc-param", false, false, None).finish());
    assert_eq!(protocols[0].transport, ScmiSmcTransport::PageAndOffset);
}

#[test]
fn perf_power_domain_is_used_only_when_the_clock_selector_cannot_decode() {
    let mut fdt = complete_tree("arm,scmi-smc", true, false, None);
    let protocols = scmi_perf_protocols(&fdt.finish());
    assert_eq!(protocols[0].cpu_domains, alloc::vec![
        ScmiCpuDomain { cpu_mpidr: 0, domain_id: 7 }, ScmiCpuDomain { cpu_mpidr: 1, domain_id: 7 }, ScmiCpuDomain { cpu_mpidr: 2, domain_id: 9 },
    ]);
}

#[test]
fn a_shared_memory_bus_without_ranges_is_not_given_a_physical_address() {
    let mut fdt = complete_tree("arm,scmi-smc", false, true, None);
    let protocols = scmi_perf_protocols(&fdt.finish());
    assert_eq!(protocols.len(), 1, "the unrelated valid SCMI controller remains usable");
    assert_eq!(protocols[0].protocol_phandle, 50);
}

#[test]
fn a2p_completion_resolves_its_named_gic_interrupt() {
    let protocols = scmi_perf_protocols(&complete_tree("arm,scmi-smc", false, false, Some(0)).finish());
    assert_eq!(protocols[0].completion_irq, Some(ScmiCompletionIrq { intid: 73, level: true }));
}

#[test]
fn a2p_completion_keeps_a_named_gic_ppi() {
    let protocols = scmi_perf_protocols(&complete_tree("arm,scmi-smc", false, false, Some(1)).finish());
    assert_eq!(protocols[0].completion_irq, Some(ScmiCompletionIrq { intid: 57, level: true }));
}
