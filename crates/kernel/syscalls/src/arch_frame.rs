#![cfg(target_os = "oxide-kernel")]

/// Current task's live AArch64 SVC frame. The task-owned pointer survives a
/// blocking syscall's context switches; the per-CPU slot is only a pre-dispatch
/// fallback. # C: O(1)
#[cfg(target_arch = "aarch64")]
pub fn current_svc_frame() -> *mut hal_aarch64::SvcFrame {
    use core::sync::atomic::Ordering;

    sched::current()
        .map(|task| task.svc_frame.load(Ordering::Acquire))
        .filter(|frame| *frame != 0)
        .map(|frame| frame as *mut hal_aarch64::SvcFrame)
        .unwrap_or_else(hal_aarch64::current_svc_frame)
}
