use super::*;
use alloc::vec::Vec;
use crate::fixture::Fdt;

fn voltage(target: u32, min: u32, max: u32) -> [u8; 12] {
    let mut data = [0u8; 12];
    data[..4].copy_from_slice(&target.to_be_bytes());
    data[4..8].copy_from_slice(&min.to_be_bytes());
    data[8..].copy_from_slice(&max.to_be_bytes());
    data
}

#[test]
fn cpu_opp_table_resolves_the_cpu_clock_and_regulator_owners() {
    let mut fdt = Fdt::new();
    fdt.begin("")
        .begin("cpus").prop_u32("#address-cells", 1).prop_u32("#size-cells", 0)
        .begin("cpu@0").prop_u32("reg", 0).prop_u32("operating-points-v2", 30)
        .prop_u32("clocks", 10).prop_u32("cpu-supply", 20).prop_u32("clock-latency", 700).end().end()
        .begin("cpu-clock").prop_u32("phandle", 10).prop_u32("#clock-cells", 0).end()
        .begin("cpu-regulator").prop_u32("phandle", 20).end()
        .begin("opp-table").prop_u32("phandle", 30).prop("opp-shared", &[])
        .begin("opp@2000000").prop("opp-hz", &2_000_000u64.to_be_bytes()).prop("opp-microvolt", &voltage(1_000_000, 950_000, 1_050_000)).prop("turbo-mode", &[]).end()
        .begin("opp@1000000").prop("opp-hz", &1_000_000u64.to_be_bytes()).prop("opp-microvolt", &900_000u32.to_be_bytes()).end()
        .begin("opp@3000000").prop("opp-hz", &3_000_000u64.to_be_bytes()).prop_str("status", "disabled").end()
        .end().end();
    let tables = cpu_opp_tables(&fdt.finish());
    assert_eq!(tables.len(), 1);
    assert_eq!(tables[0].cpu_mpidr, 0);
    assert_eq!(tables[0].table_phandle, 30);
    assert_eq!(tables[0].clocks, alloc::vec![ClockReference { provider: 10, arguments: alloc::vec![] }]);
    assert_eq!(tables[0].regulator_phandle, Some(20));
    assert!(tables[0].shared);
    assert_eq!(tables[0].transition_latency_ns, 700);
    assert_eq!(tables[0].points, alloc::vec![
        OperatingPoint { rates_hz: alloc::vec![1_000_000], voltage: Some(OppVoltage { target_uv: 900_000, min_uv: 900_000, max_uv: 900_000 }), turbo: false, ..OperatingPoint::default() },
        OperatingPoint { rates_hz: alloc::vec![2_000_000], voltage: Some(OppVoltage { target_uv: 1_000_000, min_uv: 950_000, max_uv: 1_050_000 }), turbo: true, ..OperatingPoint::default() },
    ]);
}

#[test]
fn unknown_clock_cell_layout_refuses_the_cpu_policy() {
    let mut fdt = Fdt::new();
    fdt.begin("").begin("cpus").prop_u32("#address-cells", 1)
        .begin("cpu@0").prop_u32("reg", 0).prop_u32("operating-points-v2", 3).prop_u32("clocks", 1).end().end()
        .begin("clock").prop_u32("phandle", 1).prop_u32("#clock-cells", 1).end()
        .begin("table").prop_u32("phandle", 3).begin("opp").prop("opp-hz", &1u64.to_be_bytes()).end().end().end();
    assert!(cpu_opp_tables(&fdt.finish()).is_empty());
}

#[test]
fn multi_clock_opp_uses_every_rate_and_every_clock_selector() {
    let mut fdt = Fdt::new();
    let mut clocks = Vec::new();
    clocks.extend_from_slice(&1u32.to_be_bytes());
    clocks.extend_from_slice(&2u32.to_be_bytes());
    clocks.extend_from_slice(&7u32.to_be_bytes());
    let mut rates = Vec::new();
    rates.extend_from_slice(&1_000_000u64.to_be_bytes());
    rates.extend_from_slice(&400_000_000u64.to_be_bytes());
    fdt.begin("").begin("cpus").prop_u32("#address-cells", 1)
        .begin("cpu@0").prop_u32("reg", 0).prop_u32("operating-points-v2", 3).prop("clocks", &clocks).end().end()
        .begin("cpu-clock").prop_u32("phandle", 1).prop_u32("#clock-cells", 0).end()
        .begin("bus-clock").prop_u32("phandle", 2).prop_u32("#clock-cells", 1).end()
        .begin("table").prop_u32("phandle", 3).begin("opp").prop("opp-hz", &rates).end().end().end();
    let tables = cpu_opp_tables(&fdt.finish());
    assert_eq!(tables.len(), 1);
    assert_eq!(tables[0].clocks, alloc::vec![
        ClockReference { provider: 1, arguments: alloc::vec![] },
        ClockReference { provider: 2, arguments: alloc::vec![7] },
    ]);
    assert_eq!(tables[0].points[0].rates_hz, [1_000_000, 400_000_000]);
}

#[test]
fn a_rate_vector_with_the_wrong_clock_count_refuses_the_cpu_policy() {
    let mut fdt = Fdt::new();
    fdt.begin("").begin("cpus").prop_u32("#address-cells", 1)
        .begin("cpu@0").prop_u32("reg", 0).prop_u32("operating-points-v2", 3).prop_u32("clocks", 1).end().end()
        .begin("clock").prop_u32("phandle", 1).prop_u32("#clock-cells", 0).end()
        .begin("table").prop_u32("phandle", 3).begin("opp").prop("opp-hz", &[0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2]).end().end().end();
    assert!(cpu_opp_tables(&fdt.finish()).is_empty());
}

#[test]
fn constrained_opps_keep_hardware_current_dependency_level_and_suspend_data() {
    let mut masks = Vec::new();
    masks.extend_from_slice(&1u32.to_be_bytes());
    masks.extend_from_slice(&4u32.to_be_bytes());
    let mut required = Vec::new();
    required.extend_from_slice(&41u32.to_be_bytes());
    let mut fdt = Fdt::new();
    fdt.begin("").begin("cpus").prop_u32("#address-cells", 1)
        .begin("cpu@0").prop_u32("reg", 0).prop_u32("operating-points-v2", 3).prop_u32("clocks", 1).end().end()
        .begin("clock").prop_u32("phandle", 1).prop_u32("#clock-cells", 0).end()
        .begin("cpu-table").prop_u32("phandle", 3)
        .begin("opp@1").prop_u32("phandle", 31).prop("opp-hz", &1_000_000u64.to_be_bytes())
        .prop_u32("opp-microamp", 70_000).prop_u32("opp-level", 5).prop("opp-supported-hw", &masks)
        .prop("required-opps", &required).prop("opp-suspend", &[]).end()
        .begin("opp@2").prop("opp-hz", &2_000_000u64.to_be_bytes()).prop("opp-suspend", &[]).end().end()
        .begin("memory-table").prop_u32("phandle", 4)
        .begin("opp@2").prop_u32("phandle", 41).prop_u32("opp-level", 9).prop_u32("opp-supported-hw", 8).end().end()
        .end();
    let tables = cpu_opp_tables(&fdt.finish());
    assert_eq!(tables.len(), 1);
    let point = &tables[0].points[0];
    assert_eq!(point.current_ua, Some(70_000));
    assert_eq!(point.level, Some(5));
    assert_eq!(point.supported_hw, Some(alloc::vec![1, 4]));
    assert!(point.suspend);
    assert_eq!(point.required_opps, alloc::vec![RequiredOpp {
        table_phandle: 4, performance_state: 9, supported_hw: Some(alloc::vec![8]),
    }]);
    assert_eq!(tables[0].suspend_index(), Some(1));
}

#[test]
fn malformed_constraints_and_unknown_required_targets_refuse_the_cpu_policy() {
    for property in ["opp-supported-hw", "required-opps", "opp-microamp", "opp-level"] {
        let mut fdt = Fdt::new();
        fdt.begin("").begin("cpus").prop_u32("#address-cells", 1)
            .begin("cpu@0").prop_u32("reg", 0).prop_u32("operating-points-v2", 3).prop_u32("clocks", 1).end().end()
            .begin("clock").prop_u32("phandle", 1).prop_u32("#clock-cells", 0).end()
            .begin("table").prop_u32("phandle", 3).begin("opp").prop("opp-hz", &1u64.to_be_bytes())
            .prop(property, &[]).end().end().end();
        assert!(cpu_opp_tables(&fdt.finish()).is_empty(), "{property}");
    }
    let mut missing = Fdt::new();
    missing.begin("").begin("cpus").prop_u32("#address-cells", 1)
        .begin("cpu@0").prop_u32("reg", 0).prop_u32("operating-points-v2", 3).prop_u32("clocks", 1).end().end()
        .begin("clock").prop_u32("phandle", 1).prop_u32("#clock-cells", 0).end()
        .begin("table").prop_u32("phandle", 3).begin("opp").prop("opp-hz", &1u64.to_be_bytes())
        .prop_u32("required-opps", 99).end().end().end();
    assert!(cpu_opp_tables(&missing.finish()).is_empty());
}
