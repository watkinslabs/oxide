// Device power-management callback table and the phase/transition selectors
// (`32a§5` steps 5-11, `35`).
//
// A table of optional function pointers rather than a trait: a driver supplies
// only the hooks it has, the table is `&'static`, and `07§5` keeps `dyn` off
// this seam. Three sleep transitions share one table, and each transition
// picks a different member at each of the three phase depths — that selection
// is the whole of this module, and it is where a hand-written driver-side
// `match` goes wrong.

use crate::KResult;
use crate::model::Device;

/// A callback that can refuse. Every member but `complete` has this shape.
pub type PmFn = fn(&Device) -> KResult<()>;
/// The one callback that cannot refuse: the transition has already ended.
pub type PmVoidFn = fn(&Device);

/// One driver's sleep callbacks.
///
/// Runtime PM (`runtime_suspend`, `runtime_resume`, `runtime_idle`) is a
/// separate mechanism with its own reference-counted state machine and is not
/// part of this table yet; it is deliberately absent rather than stubbed.
pub struct DevPmOps {
    /// Registration order, before anything is suspended. May refuse.
    pub prepare: Option<PmFn>,
    /// Reverse of `prepare`. Runs whether or not the transition succeeded.
    pub complete: Option<PmVoidFn>,

    // Depth 1: the ordinary phase, interrupts on.
    pub suspend: Option<PmFn>,
    pub resume: Option<PmFn>,
    pub freeze: Option<PmFn>,
    pub thaw: Option<PmFn>,
    pub poweroff: Option<PmFn>,
    pub restore: Option<PmFn>,

    // Depth 2: after the ordinary phase, interrupts still on.
    pub suspend_late: Option<PmFn>,
    pub resume_early: Option<PmFn>,
    pub freeze_late: Option<PmFn>,
    pub thaw_early: Option<PmFn>,
    pub poweroff_late: Option<PmFn>,
    pub restore_early: Option<PmFn>,

    // Depth 3: device interrupts already masked.
    pub suspend_noirq: Option<PmFn>,
    pub resume_noirq: Option<PmFn>,
    pub freeze_noirq: Option<PmFn>,
    pub thaw_noirq: Option<PmFn>,
    pub poweroff_noirq: Option<PmFn>,
    pub restore_noirq: Option<PmFn>,
}

impl DevPmOps {
    /// A table with no callbacks, the base every driver's table starts from.
    /// # C: O(1)
    pub const fn none() -> Self {
        DevPmOps {
            prepare: None, complete: None,
            suspend: None, resume: None, freeze: None, thaw: None,
            poweroff: None, restore: None,
            suspend_late: None, resume_early: None, freeze_late: None,
            thaw_early: None, poweroff_late: None, restore_early: None,
            suspend_noirq: None, resume_noirq: None, freeze_noirq: None,
            thaw_noirq: None, poweroff_noirq: None, restore_noirq: None,
        }
    }
}

/// Which sleep transition is running. Each names a different pair of members
/// at every phase depth.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PmTransition {
    /// System sleep (`32a§3`): `suspend`/`resume`.
    Suspend,
    /// Hibernation snapshot: `freeze`/`thaw`.
    Freeze,
    /// Hibernation power-down and image restore: `poweroff`/`restore`.
    Hibernate,
}

/// Which half of a transition a walk belongs to.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PmDir { Down, Up }

/// Phase depth a walk operates at.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PmDepth { Normal, LateEarly, Noirq }

/// The depth-1 callback for `t` in direction `d`. # C: O(1)
pub fn pm_op(ops: &DevPmOps, t: PmTransition, d: PmDir) -> Option<PmFn> {
    match (t, d) {
        (PmTransition::Suspend,   PmDir::Down) => ops.suspend,
        (PmTransition::Suspend,   PmDir::Up)   => ops.resume,
        (PmTransition::Freeze,    PmDir::Down) => ops.freeze,
        (PmTransition::Freeze,    PmDir::Up)   => ops.thaw,
        (PmTransition::Hibernate, PmDir::Down) => ops.poweroff,
        (PmTransition::Hibernate, PmDir::Up)   => ops.restore,
    }
}

/// The depth-2 callback for `t` in direction `d`. # C: O(1)
pub fn pm_late_early_op(ops: &DevPmOps, t: PmTransition, d: PmDir) -> Option<PmFn> {
    match (t, d) {
        (PmTransition::Suspend,   PmDir::Down) => ops.suspend_late,
        (PmTransition::Suspend,   PmDir::Up)   => ops.resume_early,
        (PmTransition::Freeze,    PmDir::Down) => ops.freeze_late,
        (PmTransition::Freeze,    PmDir::Up)   => ops.thaw_early,
        (PmTransition::Hibernate, PmDir::Down) => ops.poweroff_late,
        (PmTransition::Hibernate, PmDir::Up)   => ops.restore_early,
    }
}

/// The depth-3 callback for `t` in direction `d`. # C: O(1)
pub fn pm_noirq_op(ops: &DevPmOps, t: PmTransition, d: PmDir) -> Option<PmFn> {
    match (t, d) {
        (PmTransition::Suspend,   PmDir::Down) => ops.suspend_noirq,
        (PmTransition::Suspend,   PmDir::Up)   => ops.resume_noirq,
        (PmTransition::Freeze,    PmDir::Down) => ops.freeze_noirq,
        (PmTransition::Freeze,    PmDir::Up)   => ops.thaw_noirq,
        (PmTransition::Hibernate, PmDir::Down) => ops.poweroff_noirq,
        (PmTransition::Hibernate, PmDir::Up)   => ops.restore_noirq,
    }
}

/// The callback at `depth` for `t` in direction `d`. # C: O(1)
pub fn pm_op_at(ops: &DevPmOps, depth: PmDepth, t: PmTransition, d: PmDir) -> Option<PmFn> {
    match depth {
        PmDepth::Normal    => pm_op(ops, t, d),
        PmDepth::LateEarly => pm_late_early_op(ops, t, d),
        PmDepth::Noirq     => pm_noirq_op(ops, t, d),
    }
}
