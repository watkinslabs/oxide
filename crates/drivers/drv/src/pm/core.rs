// The machine's device PM core: the phase lists bound to the real device
// registry, and the no-argument entry points `32a§5` steps 5-11 call.
//
// The lists are per-transition working state seeded from `model::devices()` at
// step 5 and returned to it at step 5's undo, so the registry stays the single
// source of truth for which devices exist; nothing here is a second registry.

use alloc::string::String;
use alloc::sync::Arc;
use sync::{Spinlock, TaskList as DriverListClass};

use crate::KResult;
use crate::model::{bound_driver, devices, Device};
use super::lists::{PmLists, PmPhase, PmTarget};
use super::ops::{pm_op_at, PmTransition};

impl PmTarget for Arc<Device> {
    /// # C: O(1)
    fn pm_name(&self) -> &str { &self.addr }

    /// Dispatch to the bound driver's table; an unbound device, a driver with
    /// no table, or a table with no member for this phase all succeed with
    /// nothing done — the reference's "no callback is not an error".
    /// # C: driver-defined
    fn pm_run(&self, phase: PmPhase, t: PmTransition) -> KResult<()> {
        let Some(drv) = bound_driver(self) else { return Ok(()) };
        let Some(ops) = drv.pm() else { return Ok(()) };
        match phase {
            PmPhase::Prepare => match ops.prepare { Some(f) => f(self), None => Ok(()) },
            PmPhase::Complete => { if let Some(f) = ops.complete { f(self); } Ok(()) }
            PmPhase::Depth(depth, dir) => match pm_op_at(ops, depth, t, dir) {
                Some(f) => f(self),
                None => Ok(()),
            },
        }
    }
}

/// The machine's phase lists.
static DPM: Spinlock<Option<PmLists<Arc<Device>>>, DriverListClass> = Spinlock::new(None);
/// The transition in flight, so the no-argument entry points agree on which
/// members of a driver's table they select. Mirrors the reference's single
/// transition word rather than threading it through the backend signature.
static TRANSITION: Spinlock<PmTransition, DriverListClass> = Spinlock::new(PmTransition::Suspend);

fn with<R>(f: impl FnOnce(&mut PmLists<Arc<Device>>) -> R) -> R {
    let mut g = DPM.lock();
    f(g.get_or_insert_with(PmLists::new))
}

/// Select the transition the next device phase walks belong to. Called before
/// step 5. # C: O(1)
pub fn dpm_set_transition(t: PmTransition) { *TRANSITION.lock() = t; }

/// The transition currently selected. # C: O(1)
pub fn dpm_transition() -> PmTransition { *TRANSITION.lock() }

/// Step 5: seed the lists from the registry and run `prepare` in registration
/// order. # C: O(N_devices)
pub fn dpm_prepare() -> KResult<()> {
    let t = dpm_transition();
    with(|l| {
        if !l.is_idle() { l.reset(); }
        l.seed(devices());
        l.prepare(t)
    })
}

/// Step 6: `suspend`, reverse registration order. # C: O(N_devices)
pub fn dpm_suspend() -> KResult<()> { let t = dpm_transition(); with(|l| l.suspend(t)) }

/// Step 8: `suspend_late`, reverse. Resumes its own partial state on failure.
/// # C: O(N_devices)
pub fn dpm_suspend_late() -> KResult<()> { let t = dpm_transition(); with(|l| l.suspend_late(t)) }

/// Step 10: `suspend_noirq`, reverse. Resumes its own partial state on failure.
/// # C: O(N_devices)
/// # Ctx: IRQ-off
pub fn dpm_suspend_noirq() -> KResult<()> { let t = dpm_transition(); with(|l| l.suspend_noirq(t)) }

/// Undo of step 10. # C: O(N_devices)
/// # Ctx: IRQ-off
pub fn dpm_resume_noirq() { let t = dpm_transition(); with(|l| l.resume_noirq(t)) }

/// Undo of step 8. # C: O(N_devices)
pub fn dpm_resume_early() { let t = dpm_transition(); with(|l| l.resume_early(t)) }

/// Undo of step 6. # C: O(N_devices)
pub fn dpm_resume() { let t = dpm_transition(); with(|l| l.resume(t)) }

/// Undo of step 5: `complete` in reverse, leaving the lists idle.
/// # C: O(N_devices)
pub fn dpm_complete() {
    let t = dpm_transition();
    with(|l| { l.complete(t); l.list.clear(); });
}

/// Bus address of the device whose callback refused most recently, for the
/// suspend statistics record (`32a§11`). # C: O(n)
pub fn dpm_failed_device() -> Option<String> {
    use alloc::string::ToString;
    with(|l| l.failed_device().map(|s| s.to_string()))
}
