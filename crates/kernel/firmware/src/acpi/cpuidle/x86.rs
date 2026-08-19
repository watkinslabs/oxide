//! x86 ACPI C-state discovery and entry.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use cpuidle::{Entry, IdleOps, IdleState};
use vfs::{KResult, VfsError};

use super::decode::{CstState, decode_cst, with_c1_fallback};
use crate::acpi::aml_eval;
use crate::acpi::fadt::{self, CstateRegisters, FADT_WBINVD, Gas, SPACE_SYSTEM_IO};

const BUS_MASTER_STATUS: u64 = 1 << 4;
const BUS_MASTER_RELOAD: u64 = 1 << 1;
const ARBITRATION_DISABLE: u64 = 1;
const INTEL_VENDOR: [u8; 12] = *b"GenuineIntel";

/// One fixed I/O register after port width and range validation.
#[derive(Copy, Clone)]
struct IoRegister { port: u16, width: u8 }

/// The fixed-register actions needed around every C3 entry.
#[derive(Copy, Clone)]
struct C3Config {
    check_bus_master: bool,
    status_a: Option<IoRegister>,
    status_b: Option<IoRegister>,
    arbitration: Option<IoRegister>,
    cache_flush: bool,
    enabled_cpus: usize,
}

/// Immutable C-state plan paired with the cpuidle state table.
struct Driver {
    tables: Vec<Vec<CstState>>,
    c3: Option<C3Config>,
    intel: bool,
    timer_wait: Option<IoRegister>,
}

static C3_RESIDENTS: AtomicUsize = AtomicUsize::new(0);

impl IdleOps for Driver {
    /// # C: O(sleep)
    fn enter(&self, cpu: usize, index: usize, state: &IdleState) -> KResult<usize> {
        let plan = self.tables.get(cpu).and_then(|table| table.get(index)).ok_or(VfsError::Einval)?;
        if plan.cstate != 3 { return self.enter_one(state).map(|()| index); }
        let Some(c3) = self.c3 else { return Err(VfsError::Einval); };
        let skip_status = self.intel && plan.skip_bus_master_status;
        if c3.check_bus_master && !skip_status && c3.bus_master_active() {
            let safe = self.tables[cpu].iter().rposition(|state| matches!(state.cstate, 1 | 2))
                .ok_or(VfsError::Ebusy)?;
            self.enter_one(&self.tables[cpu][safe].state)?;
            return Ok(safe);
        }
        let arbitration = c3.enter_arbitration();
        if c3.cache_flush { hal_x86_64::writeback_invalidate_cache(); }
        let result = self.enter_one(state).map(|()| index);
        if arbitration { c3.leave_arbitration(); }
        result
    }
}

impl Driver {
    /// Carry out the firmware-described operation itself. # C: O(sleep)
    fn enter_one(&self, state: &IdleState) -> KResult<()> {
        match state.entry {
            Entry::Halt => hal_x86_64::safe_halt(),
            Entry::Mwait { hint } => hal_x86_64::acpi_mwait(hint),
            Entry::SystemIo { port, width } => {
                hal_x86_64::io::operation_region_access(port, u64::from(width), None)
                    .ok_or(VfsError::Eio)?;
                if let Some(timer) = self.timer_wait {
                    hal_x86_64::io::operation_region_access(u64::from(timer.port), u64::from(timer.width), None)
                        .ok_or(VfsError::Eio)?;
                }
            }
            _ => return Err(VfsError::Einval),
        }
        Ok(())
    }
}

impl C3Config {
    /// Check and clear a latched bus-master indication. An inaccessible fixed
    /// register is treated as activity, so C3 is never entered on uncertainty.
    /// # C: O(1)
    fn bus_master_active(&self) -> bool {
        let a = self.status_a.is_some_and(status_active);
        let b = self.status_b.is_some_and(status_active);
        a || b
    }

    /// Disable arbitration only while every enabled CPU is resident in C3.
    /// # C: O(1)
    fn enter_arbitration(&self) -> bool {
        let Some(register) = self.arbitration else { return false; };
        if C3_RESIDENTS.fetch_add(1, Ordering::AcqRel) + 1 != self.enabled_cpus { return true; }
        if set_bit(register, ARBITRATION_DISABLE) { true }
        else {
            C3_RESIDENTS.fetch_sub(1, Ordering::AcqRel);
            false
        }
    }

    /// Restore arbitration before this CPU resumes normal execution. # C: O(1)
    fn leave_arbitration(&self) {
        let Some(register) = self.arbitration else { return; };
        let _ = set_bit_value(register, ARBITRATION_DISABLE, false);
        C3_RESIDENTS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Build and register every complete ACPI C-state ladder. # C: O(AML²)
pub(super) fn init() -> usize {
    if !cpuidle::idle::generic::is_generic() { return 0; }
    let intel = hal_x86_64::cpuid_vendor() == INTEL_VENDOR;
    let count = cpu::count() as usize;
    let Some(mut tables) = firmware_tables(count) else { return 0; };
    let has_c3 = tables.iter().flatten().any(|state| state.cstate == 3);
    let c3 = if has_c3 {
        fadt::cstate_registers_published().and_then(|registers| c3_config(registers, intel))
    } else { None };
    if has_c3 && c3.is_none() {
        for table in &mut tables { table.retain(|state| state.cstate != 3); }
    }
    let idle_tables: Vec<Vec<IdleState>> = tables.iter().map(|table| table.iter()
        .map(|state| state.state.clone()).collect()).collect();
    if idle_tables.iter().all(|table| table.len() == 1 && table[0].entry == Entry::Halt) { return 0; }
    let timer_wait = if intel && !hal_x86_64::hypervisor_present() {
        fadt::cstate_registers_published().and_then(|registers| io_register(registers.pm_timer, Some(32)))
    } else { None };
    if !cpuidle::driver::unregister() { return 0; }
    let driver = Arc::new(Driver { tables, c3, intel, timer_wait });
    match cpuidle::register_per_cpu("acpi_idle", idle_tables, driver) {
        Ok(_) => count_enabled(),
        Err(_) => 0,
    }
}

/// Join every enabled CPU UID to exactly one usable `_CST` package. # C: O(AML²)
fn firmware_tables(count: usize) -> Option<Vec<Vec<CstState>>> {
    if count == 0 { return None; }
    let mut tables: Vec<Option<Vec<CstState>>> = (0..count).map(|_| None).collect();
    for scope in aml_eval::processor_scopes() {
        let cpu = cpu::logical_id_for_acpi_uid(scope.uid)? as usize;
        if cpu >= count || tables[cpu].is_some() { return None; }
        let (_, flags) = cpu::get(cpu)?;
        if flags & (cpu::FLAG_ENABLED | cpu::FLAG_ONLINE_CAPABLE) == 0 { continue; }
        let package = aml_eval::eval_cst(&scope.path)?;
        let states = decode_cst(&package, hal_x86_64::acpi_mwait_supported).ok()?;
        if states.is_empty() { return None; }
        tables[cpu] = Some(with_c1_fallback(states));
    }
    let mut complete = Vec::with_capacity(count);
    for cpu in 0..count {
        let (_, flags) = cpu::get(cpu)?;
        if flags & (cpu::FLAG_ENABLED | cpu::FLAG_ONLINE_CAPABLE) != 0 {
            complete.push(tables[cpu].take()?);
        } else {
            complete.push(with_c1_fallback(Vec::new()));
        }
    }
    Some(complete)
}

/// Configure C3's hardware-defined coherency guard before registration.
/// # C: O(1)
fn c3_config(registers: CstateRegisters, intel: bool) -> Option<C3Config> {
    let enabled_cpus = count_enabled().max(1);
    let check_bus_master = enabled_cpus == 1 || intel;
    if !check_bus_master && registers.flags & FADT_WBINVD == 0 { return None; }
    let status_a = if check_bus_master { Some(status_register(registers.pm1a_event, registers.pm1_event_len)?) }
                   else { None };
    let status_b = if check_bus_master && registers.pm1b_event.address != 0 {
        Some(status_register(registers.pm1b_event, registers.pm1_event_len)?)
    } else { None };
    // PM2 control owns both bus-master reload and arbitration disable.  C3
    // remains usable when firmware omits it: bus-master status is still
    // checked, while arbitration is left unchanged.  When it is present,
    // leave bus-master reload enabled for all subsequent C3 entries.
    let arbitration = if registers.pm2_control_len == 0 { None } else {
        let register = io_register(registers.pm2_control, Some(8))?;
        if !set_bit(register, BUS_MASTER_RELOAD) { return None; }
        Some(register)
    };
    Some(C3Config { check_bus_master, status_a, status_b, arbitration, cache_flush: !check_bus_master, enabled_cpus })
}

/// PM1 event status is the first half of the block and carries a 16-bit word.
/// # C: O(1)
fn status_register(gas: Gas, event_len: u8) -> Option<IoRegister> {
    if event_len / 2 < 2 { return None; }
    io_register(gas, Some(16))
}

/// Normalize a FADT I/O GAS to a register this architecture can access.
/// # C: O(1)
fn io_register(gas: Gas, required_width: Option<u8>) -> Option<IoRegister> {
    if gas.space_id != SPACE_SYSTEM_IO || gas.address == 0 { return None; }
    let port = u16::try_from(gas.address).ok()?;
    let declared = match gas.access_width {
        0 => gas.bit_width,
        1 => 8,
        2 => 16,
        3 => 32,
        _ => return None,
    };
    let width = required_width.unwrap_or(declared);
    if !matches!(width, 8 | 16 | 32) || (gas.access_width != 0 && declared != width) { return None; }
    let bytes = u32::from(width / 8);
    (u32::from(port).checked_add(bytes)? <= u32::from(u16::MAX) + 1).then_some(IoRegister { port, width })
}

/// Read-and-clear one PM1 bus-master status bit. # C: O(1)
fn status_active(register: IoRegister) -> bool {
    let Some(value) = hal_x86_64::io::operation_region_access(u64::from(register.port), u64::from(register.width), None) else {
        return true;
    };
    if value & BUS_MASTER_STATUS == 0 { return false; }
    let _ = hal_x86_64::io::operation_region_access(u64::from(register.port), u64::from(register.width), Some(BUS_MASTER_STATUS));
    true
}

/// Set one preserved control-register bit. # C: O(1)
fn set_bit(register: IoRegister, bit: u64) -> bool { set_bit_value(register, bit, true) }

/// Update one control bit without disturbing firmware-owned bits. # C: O(1)
fn set_bit_value(register: IoRegister, bit: u64, value: bool) -> bool {
    let Some(old) = hal_x86_64::io::operation_region_access(u64::from(register.port), u64::from(register.width), None) else {
        return false;
    };
    let next = if value { old | bit } else { old & !bit };
    hal_x86_64::io::operation_region_access(u64::from(register.port), u64::from(register.width), Some(next)).is_some()
}

/// CPUs that can actually run the scheduler's idle loop. # C: O(cpus)
fn count_enabled() -> usize { cpu::enabled_count() as usize }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_register_rejects_mismatched_and_overflowing_gas() {
        let good = Gas { space_id: SPACE_SYSTEM_IO, bit_width: 16, bit_offset: 0, access_width: 2, address: 0x404 };
        assert_eq!(io_register(good, Some(16)).map(|register| (register.port, register.width)), Some((0x404, 16)));
        assert!(io_register(Gas { address: u64::from(u16::MAX), ..good }, Some(16)).is_none());
        assert!(io_register(Gas { access_width: 1, ..good }, Some(16)).is_none());
    }

    #[test]
    fn c3_without_a_bus_check_requires_cache_writeback_authorization() {
        let registers = CstateRegisters { flags: 0, ..CstateRegisters::default() };
        assert!(c3_config(registers, false).is_none());
    }

    #[test]
    fn cst_c3_keeps_bus_master_status_check_without_pm2_arbitration() {
        let event = Gas { space_id: SPACE_SYSTEM_IO, bit_width: 32, bit_offset: 0, access_width: 0, address: 0x400 };
        let registers = CstateRegisters { pm1a_event: event, pm1_event_len: 4, ..CstateRegisters::default() };
        let c3 = c3_config(registers, true).expect("CST C3 without PM2 control");
        assert!(c3.check_bus_master);
        assert!(c3.arbitration.is_none());
    }
}
