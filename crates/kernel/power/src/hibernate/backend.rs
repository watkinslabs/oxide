//! Generic owners called by the hibernation write transaction.

use core::convert::Infallible;
use crate::decide::KResult;

/// Which side returned through the saved architecture continuation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Side { Original, Restored }

/// Device callback message selected during unwind.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ResumeKind { Thaw, Restore }

/// Post-image behavior selected by `/sys/power/disk`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FinishMode { PowerDown, Suspend, TestResume }

/// Subsystem boundary for one write-side hibernation transaction.
///
/// A callback returning an error must undo any partial work it performed.
/// The orchestrator installs the matching reverse action only after success.
pub trait Backend {
    fn lease_acquire(&mut self) -> KResult<()>;
    fn lease_release(&mut self);
    fn console_prepare(&mut self) -> KResult<()>;
    fn console_restore(&mut self);
    fn notify_prepare(&mut self) -> KResult<()>;
    fn notify_post(&mut self);
    fn sync_filesystems(&mut self) -> KResult<()>;
    fn filesystems_freeze(&mut self) -> KResult<()>;
    fn filesystems_thaw(&mut self);
    fn users_freeze(&mut self) -> KResult<()>;
    fn users_thaw(&mut self);
    fn helpers_disable(&mut self) -> KResult<()>;
    fn helpers_enable(&mut self);
    fn hotplug_lock(&mut self) -> KResult<()>;
    fn hotplug_unlock(&mut self);
    fn kernel_threads_freeze(&mut self) -> KResult<()>;
    fn kernel_threads_thaw(&mut self);
    fn snapshot_prepare(&mut self) -> KResult<()>;
    fn snapshot_release(&mut self);
    fn devices_prepare(&mut self) -> KResult<()>;
    fn devices_freeze(&mut self) -> KResult<()>;
    fn devices_late(&mut self) -> KResult<()>;
    fn devices_noirq(&mut self) -> KResult<()>;
    fn devices_resume_noirq(&mut self, kind: ResumeKind);
    fn devices_resume_early(&mut self, kind: ResumeKind);
    fn devices_resume(&mut self, kind: ResumeKind);
    fn devices_complete(&mut self, kind: ResumeKind);
    fn cpus_off(&mut self) -> KResult<()>;
    fn cpus_on(&mut self) -> KResult<()>;
    fn irqs_off(&mut self) -> u64;
    fn irqs_on(&mut self, state: u64);
    fn syscore_suspend(&mut self) -> KResult<()>;
    fn syscore_resume(&mut self);
    fn arch_snapshot_and_copy(&mut self) -> KResult<Side>;
    fn serialize_image(&mut self) -> KResult<()>;
    fn commit_marker(&mut self) -> KResult<()>;
    fn unmark_image(&mut self) -> KResult<()>;
    fn finish_mode(&self) -> FinishMode;
    fn suspend_with_image(&mut self) -> KResult<()>;
    fn prepare_test_resume(&mut self) -> KResult<()>;
    fn enter_test_resume(&mut self) -> KResult<Infallible>;
    fn devices_poweroff(&mut self) -> KResult<()>;
    /// Terminal power transition. A normal return is impossible.
    fn terminal(&mut self, claim: &crate::transition::Claim) -> KResult<Infallible>;
    /// Stop when a committed image cannot be unmarked safely.
    fn halt_with_live_image(&mut self) -> !;
}
