//! Task-owned x86 synchronous fault-frame handoff.

#[cfg(target_arch = "x86_64")]
use core::sync::atomic::Ordering;

use crate::Task;

/// Preserve the outgoing task's fault frame before another task runs here.
#[cfg(target_arch = "x86_64")]
pub(super) fn save_outgoing(task: &Task) {
    let (frame, rsp, rip) = hal_x86_64::capture_current_fault_frame();
    task.fault_frame.store(frame, Ordering::Release);
    task.fault_rsp.store(rsp, Ordering::Release);
    task.fault_rip.store(rip, Ordering::Release);
}

/// Restore the incoming task's frame immediately before its saved context resumes.
#[cfg(target_arch = "x86_64")]
pub(super) fn restore_incoming(task: &Task) {
    hal_x86_64::restore_current_fault_frame(
        task.fault_frame.load(Ordering::Acquire),
        task.fault_rsp.load(Ordering::Acquire),
        task.fault_rip.load(Ordering::Acquire),
    );
}

#[cfg(not(target_arch = "x86_64"))]
pub(super) fn save_outgoing(_task: &Task) {}

#[cfg(not(target_arch = "x86_64"))]
pub(super) fn restore_incoming(_task: &Task) {}
