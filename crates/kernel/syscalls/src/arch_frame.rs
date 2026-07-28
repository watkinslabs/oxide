#![cfg(target_os = "oxide-kernel")]

pub use ::fs::sig_dispatch::UserRegs;

/// The live entry frame of the syscall currently dispatching — Linux's `regs`
/// argument, threaded from `entry_SYSCALL_64` / `el0_svc` all the way to
/// `arch_do_signal_or_restart`. ONE accessor for both arches so no caller has
/// to know which per-CPU slot or stack offset holds it.
///
/// aarch64 prefers the TASK-owned pointer: it survives a blocking syscall's
/// context switches, where the per-CPU slot is only a pre-dispatch fallback
/// another task can overwrite (F206).
/// # C: O(1)
pub fn current_user_regs() -> *mut UserRegs {
    #[cfg(target_arch = "aarch64")]
    {
        use core::sync::atomic::Ordering;
        sched::current()
            .map(|task| task.svc_frame.load(Ordering::Acquire))
            .filter(|frame| *frame != 0)
            .map(|frame| frame as *mut UserRegs)
            .unwrap_or_else(hal_aarch64::current_svc_frame)
    }
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::current_pt_regs() }
}

/// Alias kept for the aarch64 diagnostics that speak of the SVC frame
/// specifically. # C: O(1)
#[cfg(target_arch = "aarch64")]
pub fn current_svc_frame() -> *mut hal_aarch64::SvcFrame { current_user_regs() }
