// The platform enter: hand the machine to firmware, and come back.
//
// `32a§5` step 15 runs this with interrupts disabled, one CPU online and
// every device already suspended. Two shapes, because the two states differ
// in what survives:
//
//   standby (S1) — CPU context is retained, so the register write returns
//                  here when the platform wakes, and all that is left is to
//                  confirm the wake actually happened.
//   mem (S3)     — CPU context is lost. The resume address goes into the
//                  FACS waking vector, the processor context into the arch
//                  record, and control into the low-level sleep path, which
//                  the resume trampoline lands back on.
//
// The register write itself happens inside the low-level path so that the
// captured resume point is the instruction after it, not before: an S3 that
// re-runs the write on resume would sleep again forever.

use core::cell::UnsafeCell;

use firmware::acpi::{PowerOffAction, SleepState as AcpiState, sleep_action, wake_status_registers};
use hal_x86_64::suspend::{SavedCpuState, restore_processor_state, save_processor_state,
    suspend_lowlevel};

use crate::decide::{Error, KResult};
use crate::suspend::state::SuspendState;
use super::io;
use super::plan::{SleepPlan, legacy_plan, reduced_plan};

/// Non-zero result the sleep callback reports when a register refused the
/// write, so nothing entered a sleep and the caller unwinds.
const WRITE_REFUSED: u64 = 1;

/// The record the resume lands on and the plan the callback issues.
///
/// Not a lock: the resume arrives with no stack of its own and no per-CPU
/// state, so nothing on that path can take one, and a lock held across a
/// sleep is a lock whose owner the resume cannot identify. The single-writer
/// discipline comes from the sequence instead — `32a§2.6` runs the platform
/// enter with interrupts disabled and one CPU online, and `run` admits one
/// transition at a time.
struct SleepCell {
    saved: UnsafeCell<SavedCpuState>,
    plan: UnsafeCell<Option<SleepPlan>>,
}

// SAFETY: both cells are touched only from the platform enter, which runs
// with interrupts disabled on the one CPU still online, and only one suspend
// transition exists at a time.
unsafe impl Sync for SleepCell {}

static CELL: SleepCell = SleepCell {
    saved: UnsafeCell::new(SavedCpuState::new()),
    plan: UnsafeCell::new(None),
};

/// Issue the pending plan. Called from the low-level sleep path, which is
/// where the machine stops being ours.
extern "C" fn issue_sleep_writes() -> u64 {
    // SAFETY: the plan was stored by `enter` on this CPU with interrupts disabled, and nothing else writes the cell.
    let Some(plan) = (unsafe { *CELL.plan.get() }) else { return WRITE_REFUSED; };
    if io::execute(&plan) != plan.len() { return WRITE_REFUSED; }
    0
}

/// Turn a firmware-authorised action into the ordered write list.
fn build_plan(action: PowerOffAction) -> Option<SleepPlan> {
    match action {
        PowerOffAction::Legacy { pm1a_control, pm1b_control, sleep_type_a, sleep_type_b } => {
            let base = io::read_gas16(pm1a_control)?;
            let (status_a, status_b) = match wake_status_registers() {
                Some((a, b)) => (Some(a), b),
                None => (None, None),
            };
            Some(legacy_plan(pm1a_control, pm1b_control, status_a, status_b, base, sleep_type_a, sleep_type_b))
        }
        PowerOffAction::Reduced { sleep_control, sleep_status, sleep_type } =>
            Some(reduced_plan(sleep_control, sleep_status, sleep_type)),
    }
}

/// Which ACPI state a sleep-state label enters.
fn acpi_state(state: SuspendState) -> Option<AcpiState> {
    match state {
        SuspendState::Standby => Some(AcpiState::S1),
        SuspendState::Mem => Some(AcpiState::S3),
        _ => None,
    }
}

/// `32a§5` step 15.
/// # C: O(1)
/// # Ctx: IRQ-off, single-CPU, devices suspended
pub fn enter(state: SuspendState) -> KResult<()> {
    let acpi = acpi_state(state).ok_or(Error::Inval)?;
    let action = sleep_action(acpi).ok_or(Error::Inval)?;
    let plan = build_plan(action).ok_or(Error::Io)?;
    if !firmware::acpi::events::arm_wakeup_gpes() { return Err(Error::Io); }
    // SAFETY: single-CPU, interrupts disabled, one transition at a time.
    unsafe { *CELL.plan.get() = Some(plan); }
    if acpi == AcpiState::S3 { return enter_deep(); }
    enter_shallow()
}

/// S1: the write returns here, and the wake status confirms the platform
/// actually made the transition rather than ignoring the write.
fn enter_shallow() -> KResult<()> {
    if issue_sleep_writes() != 0 { return Err(Error::Io); }
    match wake_status_registers() {
        Some(((status, _), _)) => { io::wait_wake_status(status); Ok(()) }
        None => Ok(()),
    }
}

/// S3: publish the resume address, save what firmware will not preserve,
/// and hand the machine over. Returns when the resume has restored it.
fn enter_deep() -> KResult<()> {
    let pa = super::resume_vector().ok_or(Error::Inval)?;
    let vector32 = u32::try_from(pa).map_err(|_| Error::Inval)?;
    // The 64-bit vector is deliberately zero: firmware resumes the real-mode
    // stub through the 32-bit one, and a machine that takes the 64-bit
    // vector instead lands in protected mode the stub never expects.
    if !io::publish_waking_vector(vector32, 0) { return Err(Error::Io); }
    // SAFETY: single-CPU, interrupts disabled; the record outlives the sleep
    // because it is a static, and nothing else touches it.
    let saved = unsafe { &mut *CELL.saved.get() };
    // SAFETY: CPL=0, interrupts disabled, one CPU online — the contract both
    // the save and the low-level transfer state.
    let result = unsafe {
        save_processor_state(saved);
        let r = suspend_lowlevel(saved, issue_sleep_writes);
        restore_processor_state(saved);
        r
    };
    if result != 0 { return Err(Error::Io); }
    Ok(())
}
