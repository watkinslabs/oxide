//! Device-tree PSCI CPU-idle provider.

extern crate alloc;

use alloc::vec::Vec;

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
use alloc::sync::Arc;

use cpuidle::{Entry, IdleState};

/// Build a state-table slot for every logical CPU. Every enabled CPU must have
/// one complete firmware ladder; disabled topology entries retain only their
/// architected WFI state and can never enter the scheduler's idle loop.
/// # C: O(N_cpus * N_tables)
#[cfg_attr(not(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel"))), allow(dead_code))]
fn tables_for_topology(tables: Vec<::fdt::CpuIdleTable>, topology: &[(u64, bool)])
    -> Option<Vec<Vec<::fdt::CpuIdleState>>>
{
    if tables.is_empty() || topology.is_empty() { return None; }
    let mut out: Vec<Vec<::fdt::CpuIdleState>> = (0..topology.len()).map(|_| Vec::new()).collect();
    for (logical, (hardware, enabled)) in topology.iter().enumerate() {
        if !enabled { continue; }
        let mut matching = tables.iter().filter(|table| table.cpu_mpidr == *hardware);
        let table = matching.next()?;
        if matching.next().is_some() || table.states.is_empty() { return None; }
        out[logical] = table.states.clone();
    }
    if tables.iter().any(|table| !topology.iter().any(|(hardware, _)| *hardware == table.cpu_mpidr)) {
        return None;
    }
    Some(out)
}

#[cfg_attr(not(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel"))), allow(dead_code))]
fn wfi() -> IdleState {
    IdleState::from_us("WFI", "ARM WFI", 1, 1, Entry::PlatformSuspend { param: 0 })
}

#[cfg_attr(not(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel"))), allow(dead_code))]
fn state_table(states: Vec<::fdt::CpuIdleState>) -> Option<Vec<IdleState>> {
    let mut table = alloc::vec![wfi()];
    for state in states {
        #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
        if !hal_aarch64::psci::cpu_suspend_state_valid(state.psci_suspend_param) { return None; }
        let mut idle = IdleState::from_us(&state.name, &state.description, u64::from(state.wakeup_latency_us),
                                          u64::from(state.target_residency_us),
                                          Entry::PlatformSuspend { param: state.psci_suspend_param });
        if state.local_timer_stop { idle.flags |= cpuidle::uapi::FLAG_TIMER_STOP; }
        table.push(idle);
    }
    Some(table)
}

/// Register every usable PSCI DT ladder, replacing the generic WFI fallback
/// only after the full topology has one unambiguous table. # C: O(FDT²)
pub fn init() -> usize {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        if !cpuidle::idle::generic::is_generic() { return 0; }
        let Some(blob) = super::blob() else { return 0; };
        let raw = ::fdt::cpu_idle_tables(blob);
        if raw.is_empty() { return 0; }
        // SAFETY: firmware initialization owns the PSCI probe on the boot CPU
        // before any platform idle state is registered or can be entered.
        if matches!(unsafe { hal_aarch64::psci::probe_cpu_suspend() },
                    hal_aarch64::psci::CpuSuspendFormat::Unsupported) { return 0; }
        let count = cpu::count() as usize;
        let mut topology = Vec::with_capacity(count);
        for logical in 0..count {
            let Some((hardware, flags)) = cpu::get(logical) else { return 0; };
            let enabled = flags & (cpu::FLAG_ENABLED | cpu::FLAG_ONLINE_CAPABLE) != 0;
            topology.push((hardware, enabled));
        }
        let Some(raw_tables) = tables_for_topology(raw, &topology) else { return 0; };
        let tables = raw_tables.into_iter().map(state_table).collect::<Option<Vec<_>>>();
        let Some(tables) = tables else { return 0; };
        if tables.iter().all(|table| table.len() == 1) { return 0; }
        // The generic table has no provider-owned state and no reader may have
        // entered idle during boot discovery; all validation above completed
        // before it is withdrawn, so a failed replacement never loses WFI.
        if !cpuidle::driver::unregister() { return 0; }
        if cpuidle::register_per_cpu("psci_idle", tables, Arc::new(PsciIdle)).is_ok() {
            return topology.iter().filter(|(_, enabled)| *enabled).count();
        }
    }
    0
}

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
struct PsciIdle;

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
impl cpuidle::IdleOps for PsciIdle {
    /// # C: O(sleep)
    fn enter(&self, _cpu: usize, index: usize, state: &IdleState) -> vfs::KResult<usize> {
        match state.entry {
            Entry::Halt => {
                hal_aarch64::safe_halt();
                Ok(index)
            }
            Entry::PlatformSuspend { param } => {
                // SAFETY: cpuidle invokes this from the IRQ-off idle path; the
                // state parser and PSCI probe validated the parameter before
                // this driver was published.
                unsafe { hal_aarch64::cpu_suspend::cpu_suspend(param) }
                    .map(|_| index).map_err(|_| vfs::VfsError::Eio)
            }
            _ => Err(vfs::VfsError::Einval),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(param: u32) -> ::fdt::CpuIdleState {
        ::fdt::CpuIdleState {
            name: alloc::string::String::from("cpu-sleep"), description: alloc::string::String::from("sleep"),
            wakeup_latency_us: 10, target_residency_us: 100, local_timer_stop: false,
            psci_suspend_param: param,
        }
    }

    #[test]
    fn every_enabled_cpu_requires_exactly_one_firmware_ladder() {
        let tables = alloc::vec![
            ::fdt::CpuIdleTable { cpu_mpidr: 3, states: alloc::vec![state(1)] },
            ::fdt::CpuIdleTable { cpu_mpidr: 9, states: alloc::vec![state(2)] },
        ];
        let plans = tables_for_topology(tables, &[(3, true), (7, false), (9, true)]).expect("tables");
        assert_eq!(plans.iter().map(Vec::len).collect::<Vec<_>>(), [1, 0, 1]);
        assert!(tables_for_topology(alloc::vec![::fdt::CpuIdleTable { cpu_mpidr: 3, states: alloc::vec![state(1)] }],
                                    &[(3, true), (9, true)]).is_none());
    }

    #[test]
    fn a_dt_ladder_adds_wfi_before_the_firmware_states() {
        let table = state_table(alloc::vec![state(1)]).expect("table");
        assert_eq!(table.len(), 2);
        assert_eq!(table[0].entry, Entry::PlatformSuspend { param: 0 });
        assert_eq!(table[1].entry, Entry::PlatformSuspend { param: 1 });
    }
}
