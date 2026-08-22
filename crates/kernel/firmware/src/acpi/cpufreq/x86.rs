//! x86 ACPI P-state discovery and transition programming.

use alloc::sync::Arc;
use alloc::vec::Vec;
use hal::CpuOps;
use vfs::{KResult, VfsError};

use super::command::{Command, CommandKind};
use super::decode::{Coordination, PctSpace, decode_pct, decode_ppc, decode_psd, decode_pss,
                    frequency_for_msr_status, frequency_for_status, max_latency};
use super::policy::{CpuDescription, PolicyDomain, domains, fast_switch_admitted};
use crate::acpi::aml_eval;

/// One registered ACPI performance domain, keyed by its policy allocation.
struct Domain { policy: Arc<cpufreq::Policy>, states: Vec<super::decode::Pstate>, kind: CommandKind,
                control: super::decode::PctRegister, coordination: Coordination }

/// ACPI P-state driver state. It is immutable after registration: the remote
/// call path receives an encoded command and never reaches this collection.
struct Driver { domains: Vec<Domain> }

impl Driver {
    fn domain(&self, policy: &cpufreq::Policy) -> Option<&Domain> {
        self.domains.iter().find(|domain| core::ptr::eq(Arc::as_ptr(&domain.policy), policy))
    }

    fn command(&self, policy: &cpufreq::Policy, index: usize) -> KResult<(Coordination, Command)> {
        let domain = self.domain(policy).ok_or(VfsError::Enodev)?;
        let pss_index = policy.table.entries.get(index).ok_or(VfsError::Einval)?.driver_data;
        let state = domain.states.iter().find(|state| state.index == pss_index).ok_or(VfsError::Einval)?;
        Ok((domain.coordination, Command {
            kind: domain.kind, port: domain.control.address as u16, width_bits: domain.control.width_bits,
            control: state.control,
        }))
    }
}

impl cpufreq::CpufreqOps for Driver {
    fn target_index(&self, policy: &cpufreq::Policy, index: usize) -> KResult<()> {
        let (coordination, command) = self.command(policy, index)?;
        program(policy, coordination, command)
    }

    fn get(&self, cpu: usize) -> Option<u32> {
        let domain = self.domains.iter().find(|domain| domain.policy.related_cpus.contains(&cpu))?;
        match domain.kind {
            CommandKind::SystemIo => {
                let status = u32::try_from(hal_x86_64::io::operation_region_access(
                    domain.control.address, u64::from(domain.control.width_bits), None)?).ok()?;
                frequency_for_status(&domain.states, status)
            }
            CommandKind::IntelMsr => frequency_for_msr_status(&domain.states,
                hal_x86_64::cpufreq::read_pstate(hal_x86_64::cpufreq::PstateBackend::Intel)?),
            CommandKind::AmdMsr => frequency_for_msr_status(&domain.states,
                hal_x86_64::cpufreq::read_pstate(hal_x86_64::cpufreq::PstateBackend::Amd)?),
        }
    }

    fn fast_switch_possible(&self, policy: &cpufreq::Policy) -> bool {
        self.domain(policy).is_some_and(|domain| fast_switch_admitted(domain.coordination))
    }

    fn fast_switch(&self, policy: &cpufreq::Policy, index: usize) -> KResult<()> {
        let (coordination, command) = self.command(policy, index)?;
        if !fast_switch_admitted(coordination) { return Err(VfsError::Ebusy); }
        if execute(command) { Ok(()) } else { Err(VfsError::Eio) }
    }
}

/// Build and register every complete x86 ACPI performance policy. # C: O(AML²)
pub(super) fn init() -> usize {
    let mut registered = Vec::new();
    for domain in domains(descriptions()) {
        let Some(kind) = command_kind(domain.control.space) else { continue; };
        let Some(policy) = make_policy(&domain) else { continue; };
        let Some(state) = domain.states.iter().find(|state| state.frequency_khz == domain.platform_max_khz) else { continue; };
        let command = Command { kind, port: domain.control.address as u16, width_bits: domain.control.width_bits,
                                control: state.control };
        if program(&policy, domain.coordination, command).is_err() { continue; }
        registered.push(Domain { policy, states: domain.states, kind, control: domain.control,
                                 coordination: domain.coordination });
    }
    if registered.is_empty() { return 0; }
    let driver = Arc::new(Driver { domains: registered });
    if cpufreq::register_driver("acpi-cpufreq", driver.clone()).is_err() { return 0; }
    let mut count = 0usize;
    for domain in driver.domains.iter() {
        if cpufreq::register_policy(Arc::clone(&domain.policy)).is_ok() { count += 1; }
    }
    count
}

/// Execute a transition command on the CPU draining the call-function queue.
/// # C: O(1)
pub(super) fn service_remote(raw: u64) {
    if let Some(command) = Command::decode(raw) { let _ = execute(command); }
}

/// Read all usable processor performance descriptions from firmware.
/// # C: O(AML²)
fn descriptions() -> Vec<CpuDescription> {
    let mut out = Vec::new();
    for scope in aml_eval::processor_scopes() {
        let Some(cpu) = cpu::logical_id_for_acpi_uid(scope.uid).map(|cpu| cpu as usize) else { continue; };
        let Some(pss_rows) = aml_eval::eval_package_rows(&scope.path, "_PSS") else { continue; };
        let Ok(states) = decode_pss(&pss_rows) else { continue; };
        let Some(pct_buffers) = aml_eval::eval_package_buffers(&scope.path, "_PCT") else { continue; };
        let Ok((control, status)) = decode_pct(&pct_buffers) else { continue; };
        let platform_limit = if aml_eval::has_method(&scope.path, "_PPC") {
            let Some(value) = aml_eval::eval_integer(&scope.path, "_PPC") else { continue; };
            let Some(limit) = decode_ppc(Some(value), pss_rows.len()) else { continue; };
            Some(limit)
        } else { None };
        let psd = if aml_eval::has_method(&scope.path, "_PSD") {
            let Some(rows) = aml_eval::eval_package_rows(&scope.path, "_PSD") else { continue; };
            let Ok(psd) = decode_psd(&rows) else { continue; };
            Some(psd)
        } else { None };
        out.push(CpuDescription { cpu, states, control, status, platform_limit, psd });
    }
    out
}

/// Build one generic policy around a validated firmware performance domain.
/// # C: O(states)
fn make_policy(domain: &PolicyDomain) -> Option<Arc<cpufreq::Policy>> {
    let entries = domain.states.iter().map(|state| cpufreq::FreqEntry::new(state.frequency_khz, state.index)).collect();
    let table = cpufreq::FreqTable::new(entries).ok()?;
    let policy = cpufreq::Policy::new(domain.cpus.clone(), table, max_latency(&domain.states), domain.platform_max_khz,
                                      cpufreq::governor::default_governor().name)?;
    policy.set_request(cpufreq::LimitSource::Platform,
                       cpufreq::Request { min: None, max: Some(domain.platform_max_khz) });
    Some(policy)
}

/// Hardware action available for a PCT address space. # C: O(1)
fn command_kind(space: PctSpace) -> Option<CommandKind> {
    match space {
        PctSpace::SystemIo => Some(CommandKind::SystemIo),
        PctSpace::FixedHardware => match hal_x86_64::cpufreq::pstate_backend()? {
            hal_x86_64::cpufreq::PstateBackend::Intel => Some(CommandKind::IntelMsr),
            hal_x86_64::cpufreq::PstateBackend::Amd => Some(CommandKind::AmdMsr),
        },
    }
}

/// Program a command on every CPU coordinating this policy. # C: O(cpus + IPI)
fn program(policy: &cpufreq::Policy, coordination: Coordination, command: Command) -> KResult<()> {
    let current = hal_x86_64::X86CpuOps::current_cpu() as usize;
    let mut mask = [0u64; hal::MAX_CPUS.div_ceil(u64::BITS as usize)];
    let selected: &[usize] = match coordination {
        Coordination::SoftwareAny => policy.cpus.get(..1).unwrap_or(&[]),
        Coordination::SoftwareAll | Coordination::HardwareAll => &policy.cpus,
    };
    let mut remote = false;
    let mut local = false;
    for cpu in selected {
        if *cpu >= hal::MAX_CPUS { return Err(VfsError::Einval); }
        mask[*cpu / u64::BITS as usize] |= 1u64 << (*cpu % u64::BITS as usize);
        if *cpu == current { local = true; } else { remote = true; }
    }
    if remote && !hal::smp_call::available() { return Err(VfsError::Ebusy); }
    if local && !execute(command) { return Err(VfsError::Eio); }
    if remote { hal::smp_call::call_function_many(&mask, hal::smp_call::CallKind::CpuFreq, command.encode(), true); }
    Ok(())
}

/// Execute one already-validated control write locally. # C: O(1)
fn execute(command: Command) -> bool {
    match command.kind {
        CommandKind::SystemIo => hal_x86_64::io::operation_region_access(u64::from(command.port),
            u64::from(command.width_bits), Some(u64::from(command.control))).is_some(),
        CommandKind::IntelMsr => hal_x86_64::cpufreq::write_pstate(hal_x86_64::cpufreq::PstateBackend::Intel,
                                                                    command.control),
        CommandKind::AmdMsr => hal_x86_64::cpufreq::write_pstate(hal_x86_64::cpufreq::PstateBackend::Amd,
                                                                  command.control),
    }
}
