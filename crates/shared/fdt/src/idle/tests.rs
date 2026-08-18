use super::*;
use crate::fixture::Fdt;

fn states(values: &[u32]) -> alloc::vec::Vec<u8> {
    values.iter().flat_map(|value| value.to_be_bytes()).collect()
}

fn idle(fdt: &mut Fdt, name: &str, phandle: u32, state: u32, wakeup: Option<u32>) {
    fdt.begin(name).prop_u32("phandle", phandle).prop_str("compatible", "arm,idle-state")
        .prop_u32("arm,psci-suspend-param", state).prop_u32("min-residency-us", 100);
    if let Some(wakeup) = wakeup { fdt.prop_u32("wakeup-latency-us", wakeup); }
    else { fdt.prop_u32("entry-latency-us", 7).prop_u32("exit-latency-us", 11); }
    fdt.end();
}

#[test]
fn psci_cpu_ladders_keep_each_cpus_phandle_order_and_wakeup_contract() {
    let mut fdt = Fdt::new();
    fdt.begin("").begin("cpus").prop_u32("#address-cells", 1).prop_u32("#size-cells", 0)
        .begin("cpu@0").prop_u32("reg", 0).prop_str("enable-method", "psci")
        .prop("cpu-idle-states", &states(&[10])).end()
        .begin("cpu@1").prop_u32("reg", 1).prop_str("enable-method", "psci")
        .prop("cpu-idle-states", &states(&[20, 10])).end()
        .begin("idle-states").prop_str("entry-method", "psci");
    idle(&mut fdt, "cpu-sleep", 10, 0x0000_0001, None);
    idle(&mut fdt, "cpu-retention", 20, 0x0000_0002, Some(31));
    fdt.end().end().end();
    let tables = cpu_idle_tables(&fdt.finish());
    assert_eq!(tables.len(), 2);
    assert_eq!(tables[0].cpu_mpidr, 0);
    assert_eq!(tables[0].states[0].wakeup_latency_us, 18);
    assert_eq!(tables[1].cpu_mpidr, 1);
    assert_eq!(tables[1].states.iter().map(|state| state.psci_suspend_param).collect::<alloc::vec::Vec<_>>(), [2, 1]);
    assert_eq!(tables[1].states[0].wakeup_latency_us, 31);
}

#[test]
fn a_missing_or_malformed_referenced_state_refuses_only_that_cpu_ladder() {
    let mut fdt = Fdt::new();
    fdt.begin("").begin("cpus").prop_u32("#address-cells", 1)
        .begin("cpu@0").prop_u32("reg", 0).prop_str("enable-method", "psci")
        .prop("cpu-idle-states", &states(&[10])).end()
        .begin("cpu@1").prop_u32("reg", 1).prop_str("enable-method", "psci")
        .prop("cpu-idle-states", &states(&[10, 99])).end()
        .begin("idle-states");
    idle(&mut fdt, "cpu-sleep", 10, 1, Some(10));
    fdt.end().end().end();
    let tables = cpu_idle_tables(&fdt.finish());
    assert_eq!(tables.len(), 1);
    assert_eq!(tables[0].cpu_mpidr, 0);

    let mut fdt = Fdt::new();
    fdt.begin("").begin("cpus").prop_u32("#address-cells", 1)
        .begin("cpu@0").prop_u32("reg", 0).prop_str("enable-method", "psci")
        .prop("cpu-idle-states", &states(&[10])).end()
        .begin("idle-states").begin("bad").prop_u32("phandle", 10)
        .prop_str("compatible", "arm,idle-state").prop_u32("arm,psci-suspend-param", 1).end()
        .end().end().end();
    assert!(cpu_idle_tables(&fdt.finish()).is_empty());
}

#[test]
fn non_psci_or_disabled_cpus_never_publish_a_platform_ladder() {
    let mut fdt = Fdt::new();
    fdt.begin("").begin("cpus").prop_u32("#address-cells", 1)
        .begin("cpu@0").prop_u32("reg", 0).prop_str("enable-method", "spin-table")
        .prop("cpu-idle-states", &states(&[10])).end()
        .begin("cpu@1").prop_u32("reg", 1).prop_str("enable-method", "psci").prop_str("status", "disabled")
        .prop("cpu-idle-states", &states(&[10])).end().begin("idle-states");
    idle(&mut fdt, "cpu-sleep", 10, 1, Some(10));
    fdt.end().end().end();
    assert!(cpu_idle_tables(&fdt.finish()).is_empty());
}
