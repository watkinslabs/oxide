// Device power management (`32a§5` steps 5-11, `35`).
//
// Module manifest:
// - `ops`:   the `DevPmOps` callback table and the transition/depth selectors.
// - `lists`: the four phase lists and the ordering + partial-failure contract,
//            generic over the target so the walk is exercised hosted.
// - `core`:  those lists bound to the real device registry, and the
//            no-argument entry points the suspend sequence calls.

pub mod ops;
pub mod lists;
pub mod core;

pub use ops::{
    pm_late_early_op, pm_noirq_op, pm_op, pm_op_at,
    DevPmOps, PmDepth, PmDir, PmFn, PmTransition, PmVoidFn,
};
pub use lists::{PmEntry, PmLists, PmPhase, PmTarget};
pub use core::{
    dpm_complete, dpm_failed_device, dpm_prepare, dpm_resume, dpm_resume_early,
    dpm_resume_noirq, dpm_set_transition, dpm_suspend, dpm_suspend_late,
    dpm_suspend_noirq, dpm_transition,
};

#[cfg(test)]
#[path = "pm/tests/walk.rs"]
mod tests_walk;
#[cfg(test)]
#[path = "pm/tests/selectors.rs"]
mod tests_selectors;
