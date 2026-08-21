//! Scheduler-owned FP/SIMD synchronization for a hibernation snapshot.
//!
//! Oxide saves and restores FP/SIMD eagerly at every task switch. Therefore
//! the running task is the only task whose canonical `Task::fpu_state` may
//! lag the CPU registers. This module closes that one gap before memory is
//! copied; it does not create a hibernation-specific register image or a
//! second CPU-owner state machine.

use crate::preempt::PreemptGuard;

/// Invoke `save` exactly once when a current-task save area exists.
/// # C: O(1)
fn save_present(state: Option<*mut u8>, save: impl FnOnce(*mut u8)) -> bool {
    let Some(state) = state else { return false; };
    save(state);
    true
}

/// Invoke `restore` exactly once from the canonical current-task area.
/// Kept separate from the architecture primitive so the positive control can
/// prove stale hardware is overwritten without relying on a context switch.
/// # C: O(1)
fn restore_present(state: Option<*const u8>, restore: impl FnOnce(*const u8)) -> bool {
    let Some(state) = state else { return false; };
    restore(state);
    true
}

/// Synchronize the running task's live FP/SIMD registers into its canonical
/// `Task::fpu_state` before a hibernation snapshot.
///
/// Returns `false` only before the live runqueue has installed a current task.
/// Unlike Linux's lazy-FPU path, there is no CPU owner tag to invalidate:
/// Oxide switches FP/SIMD eagerly, so retaining the live register contents
/// after this save is intentional and a later context switch may save them
/// again.
///
/// # C: O(architectural FP/SIMD save-area size)
/// # Ctx: task context; may nest under an existing preempt-disabled section
pub fn flush_current_fpu_for_hibernate() -> bool {
    let _preempt = PreemptGuard::new();
    let Some(task) = crate::live::current() else { return false; };
    task.debug_check_fpu_state("hibernate-save-current");

    // SAFETY: preemption is disabled, so `task` stays current on this CPU and
    // is the single mutator of its UnsafeCell-backed save area. ArchFpuBuf
    // guarantees the 64-byte alignment required by XSAVE (and therefore by
    // the weaker FXSAVE/AArch64 requirements). Kernel interrupt handlers do
    // not use task FP/SIMD state.
    let state = unsafe { (*task.fpu_state.get()).as_mut_ptr() };
    // SAFETY: the closure receives the same exclusively owned aligned task
    // save area while preemption remains disabled on this processor.
    save_present(Some(state), |state| unsafe {
        #[cfg(target_arch = "x86_64")]
        hal_x86_64::fpu_save(state.cast::<hal_x86_64::FpuStateX86_64>());
        #[cfg(target_arch = "aarch64")]
        hal_aarch64::fpu_save(state.cast::<hal_aarch64::FpuStateAArch64>());
    })
}

/// Reload the restored current task's FP/SIMD state after a cold image jump.
///
/// The restore kernel used the same physical CPU and left its own register
/// contents live. The image restored `Task::fpu_state`, but no task switch is
/// required before the hibernating task may eventually return to userspace,
/// so this reload is part of the cold continuation rather than deferred to
/// scheduling. Linux has the same ordering through x86 `kernel_fpu_end()` and
/// arm64's resume/foreign-FPSIMD repair.
///
/// # C: O(architectural FP/SIMD save-area size)
/// # Ctx: cold-resume task context, IRQ-off, one CPU
pub fn restore_current_fpu_after_hibernate() -> bool {
    let _preempt = PreemptGuard::new();
    let Some(task) = crate::live::current() else { return false; };
    task.debug_check_fpu_state("hibernate-restore-current");

    // SAFETY: the restored task is current and preemption remains disabled;
    // the canonical buffer was part of the admitted image and is 64-aligned.
    let state = unsafe { (*task.fpu_state.get()).as_ptr() };
    // SAFETY: the closure reads the admitted canonical task buffer while the
    // restored task remains current and cannot migrate.
    restore_present(Some(state), |state| unsafe {
        #[cfg(target_arch = "x86_64")]
        hal_x86_64::fpu_restore(state.cast::<hal_x86_64::FpuStateX86_64>());
        #[cfg(target_arch = "aarch64")]
        hal_aarch64::fpu_restore(state.cast::<hal_aarch64::FpuStateAArch64>());
    })
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    #[test]
    fn absent_current_task_never_runs_arch_save() {
        let called = Cell::new(false);
        assert!(!super::save_present(None, |_| called.set(true)));
        assert!(!called.get());
    }

    #[test]
    fn canonical_pointer_is_forwarded_once() {
        let mut byte = 0u8;
        let expected = core::ptr::addr_of_mut!(byte);
        let calls = Cell::new(0);
        assert!(super::save_present(Some(expected), |actual| {
            assert_eq!(actual, expected);
            calls.set(calls.get() + 1);
        }));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn cold_restore_replaces_stale_hardware_without_a_context_switch() {
        let canonical = 0x5au8;
        let mut hardware = 0xc3u8; // stand-in for the restore kernel's state
        let calls = Cell::new(0);
        assert!(super::restore_present(Some(&canonical), |state| {
            // SAFETY: `state` points at `canonical` for this synchronous call.
            hardware = unsafe { *state };
            calls.set(calls.get() + 1);
        }));
        assert_eq!(hardware, canonical);
        assert_eq!(calls.get(), 1, "reload must not wait for a task switch");
    }
}
