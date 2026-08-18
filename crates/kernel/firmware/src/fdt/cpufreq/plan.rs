//! Pure admission and grouping for CPU OPP tables.

extern crate alloc;

use alloc::vec::Vec;

/// One logical CPU and the firmware table it resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Candidate { pub cpu: usize, pub table: ::fdt::CpuOppTable }

/// One policy-shaped OPP domain ready for its real hardware owners.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainPlan { pub cpus: Vec<usize>, pub table: ::fdt::CpuOppTable }

/// Highest ordinary OPP used to establish the boot policy state. # C: O(points)
pub fn initial_index(table: &::fdt::CpuOppTable) -> Option<usize> {
    table.points.iter().rposition(|point| !point.turbo)
}

/// Group only tables firmware explicitly marks shared. Every member of a
/// shared table must name identical rate, voltage, clock and regulator data;
/// an inconsistent group is rejected rather than publishing a partial domain.
/// # C: O(cpus² × points)
pub fn domains(mut candidates: Vec<Candidate>) -> Vec<DomainPlan> {
    let mut out = Vec::new();
    while let Some(first) = candidates.pop() {
        let mut group = alloc::vec![first];
        if group[0].table.shared {
            let table = group[0].table.table_phandle;
            let mut index = 0usize;
            while index < candidates.len() {
                if candidates[index].table.shared && candidates[index].table.table_phandle == table {
                    group.push(candidates.swap_remove(index));
                } else { index += 1; }
            }
        }
        let first = &group[0].table;
        if group.iter().any(|candidate| !same_table(first, &candidate.table)) { continue; }
        let mut cpus: Vec<usize> = group.iter().map(|candidate| candidate.cpu).collect();
        cpus.sort_unstable();
        if cpus.windows(2).any(|pair| pair[0] == pair[1]) { continue; }
        out.push(DomainPlan { cpus, table: first.clone() });
    }
    out
}

fn same_table(left: &::fdt::CpuOppTable, right: &::fdt::CpuOppTable) -> bool {
    left.table_phandle == right.table_phandle && left.clocks == right.clocks
        && left.regulator_phandle == right.regulator_phandle && left.shared == right.shared
        && left.transition_latency_ns == right.transition_latency_ns && left.points == right.points
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(cpu_mpidr: u64, shared: bool) -> ::fdt::CpuOppTable {
        ::fdt::CpuOppTable {
            cpu_mpidr, table_phandle: 1, clocks: alloc::vec![::fdt::ClockReference { provider: 2, arguments: alloc::vec![3] }],
            regulator_phandle: Some(4), shared, transition_latency_ns: 9,
            points: alloc::vec![::fdt::OperatingPoint { rates_hz: alloc::vec![1_000_000], voltage: None, turbo: false }],
        }
    }

    #[test]
    fn only_an_explicitly_shared_table_forms_one_policy() {
        let plans = domains(alloc::vec![
            Candidate { cpu: 1, table: table(1, true) }, Candidate { cpu: 0, table: table(0, true) },
        ]);
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].cpus, [0, 1]);
        let plans = domains(alloc::vec![
            Candidate { cpu: 1, table: table(1, false) }, Candidate { cpu: 0, table: table(0, false) },
        ]);
        assert_eq!(plans.len(), 2);
        assert!(plans.iter().all(|plan| plan.cpus.len() == 1));
    }

    #[test]
    fn a_shared_table_with_disagreeing_clock_specs_is_not_published() {
        let mut second = table(1, true);
        second.clocks[0].arguments = alloc::vec![4];
        assert!(domains(alloc::vec![Candidate { cpu: 0, table: table(0, true) }, Candidate { cpu: 1, table: second }]).is_empty());
    }

    #[test]
    fn a_turbo_opp_does_not_become_the_initial_boost_disabled_rate() {
        let mut table = table(0, false);
        table.points.push(::fdt::OperatingPoint { rates_hz: alloc::vec![2_000_000], voltage: None, turbo: true });
        assert_eq!(initial_index(&table), Some(0));
        table.points[0].turbo = true;
        assert_eq!(initial_index(&table), None);
    }
}
