use super::*;
use crate::acpi::cpufreq::decode::PctSpace;

fn states() -> Vec<Pstate> {
    alloc::vec![
        Pstate { index: 0, frequency_khz: 3_000_000, transition_latency_ns: 1_000, control: 30, status: 30 },
        Pstate { index: 1, frequency_khz: 2_000_000, transition_latency_ns: 2_000, control: 20, status: 20 },
    ]
}

fn description(cpu: usize, psd: Option<Psd>, limit: Option<u32>) -> CpuDescription {
    let register = PctRegister { space: PctSpace::SystemIo, width_bits: 16, address: 0x1234 };
    CpuDescription { cpu, states: states(), control: register, status: register, platform_limit: limit, psd }
}

#[test]
fn psd_forms_one_shared_policy_and_applies_the_tightest_ppc_cap() {
    let psd = Psd { domain: 7, processors: 2, coordination: Coordination::SoftwareAll };
    let domains = domains(alloc::vec![description(1, Some(psd), None), description(3, Some(psd), Some(1))]);
    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].cpus, alloc::vec![1, 3]);
    assert_eq!(domains[0].platform_max_khz, 2_000_000);
}

#[test]
fn incomplete_psd_group_is_not_published_as_a_partial_policy() {
    let psd = Psd { domain: 7, processors: 2, coordination: Coordination::SoftwareAll };
    assert!(domains(alloc::vec![description(1, Some(psd), None)]).is_empty());
}

#[test]
fn an_unshared_cpu_uses_software_any_coordination() {
    let domains = domains(alloc::vec![description(2, None, None)]);
    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].coordination, Coordination::SoftwareAny);
}

#[test]
fn only_software_any_coordination_is_admitted_for_fast_switching() {
    assert!(fast_switch_admitted(Coordination::SoftwareAny));
    assert!(!fast_switch_admitted(Coordination::SoftwareAll));
    assert!(!fast_switch_admitted(Coordination::HardwareAll));
}
