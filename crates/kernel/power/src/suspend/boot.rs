// One place that assembles the machine's suspend wiring, per `32a`.
//
// `kmain` calls [`init`] once after the scheduler and the driver model exist.
// Keeping the assembly here rather than spelled out in the boot sequence means
// the hook set and the backend that consumes it cannot drift apart: adding a
// hook to `wire::SuspendHooks` and forgetting to fill it in is a change in one
// file, visible in one diff.

use crate::decide::KResult;
use super::wire::{self, SuspendHooks};

/// Filesystem sync before the freeze (`32a§5` step 0).
fn sync_filesystems() -> KResult<()> { Ok(()) }

/// Install the scheduler-side and device-side halves of the sequence, and the
/// suspend-to-idle blocking primitives.
///
/// Device-model hooks arrive separately through [`set_device_hooks`], because
/// the driver core initialises after the scheduler.
/// # C: O(1)
/// # Ctx: boot path, single-CPU
pub fn init() {
    super::s2idle_wait::init();
    wire::set_hooks(SuspendHooks {
        sync_filesystems: Some(sync_filesystems),
        freeze_processes: Some(super::freezer_walk::freeze_processes),
        freeze_kernel_threads: Some(super::freezer_walk::freeze_kernel_threads),
        thaw_processes: Some(super::freezer_walk::thaw_processes),
        ..wire::hooks()
    });
    super::sysfs_api::init_mem_sleep_default();
}

/// Install the device-model half of the sequence (`32a§5` steps 4-6, 8, 10).
/// `kmain` calls this after the driver core exists; a machine that never calls
/// it still suspends, with no device participating.
/// # C: O(1)
pub fn set_device_hooks(h: DeviceHooks) {
    wire::set_hooks(SuspendHooks {
        console_suspend: h.console_suspend,
        console_resume: h.console_resume,
        dpm_prepare: h.dpm_prepare,
        dpm_suspend: h.dpm_suspend,
        dpm_suspend_late: h.dpm_suspend_late,
        dpm_suspend_noirq: h.dpm_suspend_noirq,
        dpm_resume_noirq: h.dpm_resume_noirq,
        dpm_resume_early: h.dpm_resume_early,
        dpm_resume: h.dpm_resume,
        dpm_complete: h.dpm_complete,
        ..wire::hooks()
    });
}

/// The device-model and console half of the hook set.
#[derive(Copy, Clone, Default)]
pub struct DeviceHooks {
    pub console_suspend: Option<fn()>,
    pub console_resume: Option<fn()>,
    pub dpm_prepare: Option<fn() -> KResult<()>>,
    pub dpm_suspend: Option<fn() -> KResult<()>>,
    pub dpm_suspend_late: Option<fn() -> KResult<()>>,
    pub dpm_suspend_noirq: Option<fn() -> KResult<()>>,
    pub dpm_resume_noirq: Option<fn()>,
    pub dpm_resume_early: Option<fn()>,
    pub dpm_resume: Option<fn()>,
    pub dpm_complete: Option<fn()>,
}

/// Install the CPU-offlining half (`32a§5` step 12). Separate because it comes
/// from the interrupt-controller layer, which initialises earlier than the
/// driver core and later than the scheduler.
/// # C: O(1)
pub fn set_cpu_hooks(off: fn() -> KResult<()>, on: fn()) {
    wire::set_hooks(SuspendHooks {
        disable_secondary_cpus: Some(off),
        enable_secondary_cpus: Some(on),
        ..wire::hooks()
    });
}

/// Install the filesystem-sync hook (`32a§5` step 0). # C: O(1)
pub fn set_sync_hook(f: fn() -> KResult<()>) {
    wire::set_hooks(SuspendHooks { sync_filesystems: Some(f), ..wire::hooks() });
}

#[cfg(test)]
#[path = "boot/tests.rs"]
mod tests;
