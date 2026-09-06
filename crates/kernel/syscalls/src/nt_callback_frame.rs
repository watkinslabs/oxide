//! Capture and restore of the interrupted user state around a user-mode
//! callback. The callback runs on the same thread with its own ABI; on return
//! the whole entry frame and the callee-saved FP set come back from the
//! continuation, the way the reference's callback frame restores them, so a
//! Unix-ABI native callback cannot leak clobbered registers into PE code.
#![cfg(target_os = "oxide-kernel")]
use crate::arch_frame::UserRegs;
use crate::nt_callback_fp_layout as layout;
use sched::nt_callback::{Completion, Frame, Preserved, REGISTER_WORDS};
use sched::Task;

const _: () = assert!(core::mem::size_of::<UserRegs>() <= REGISTER_WORDS * 8);

/// Snapshot the live entry frame and the callee-saved FP set. # C: O(FPU image)
pub(crate) fn capture(regs: &UserRegs, task: &Task, completion: Completion) -> Frame {
    let mut preserved = Preserved::EMPTY;
    // SAFETY: UserRegs is a plain repr(C) register image no larger than the
    // destination (asserted above); both pointers are valid for the copy.
    unsafe { core::ptr::copy_nonoverlapping((regs as *const UserRegs).cast::<u8>(), preserved.regs.as_mut_ptr().cast::<u8>(), core::mem::size_of::<UserRegs>()); }
    with_fpu_image(task, |image| { extract(image, &mut preserved.fp); false });
    #[cfg(target_arch = "x86_64")]
    let (rip, rsp) = (regs.rip, regs.rsp);
    #[cfg(target_arch = "aarch64")]
    let (rip, rsp) = (regs.elr_el1, regs.sp_el0);
    Frame { rip, rsp, completion, preserved }
}

/// Put the captured entry frame and FP set back; the caller then writes the
/// callback's result register. # C: O(FPU image)
pub(crate) fn restore(regs: &mut UserRegs, task: &Task, saved: &Frame) {
    // SAFETY: the continuation was captured from a UserRegs of this size on
    // this task; the frame is the live entry frame this dispatch owns.
    unsafe { core::ptr::copy_nonoverlapping(saved.preserved.regs.as_ptr().cast::<u8>(), (regs as *mut UserRegs).cast::<u8>(), core::mem::size_of::<UserRegs>()); }
    with_fpu_image(task, |image| patch(image, &saved.preserved.fp));
}

fn extract(image: &[u8], out: &mut [u8; sched::nt_callback::FP_BYTES]) -> bool {
    #[cfg(target_arch = "x86_64")] { layout::x86_extract(image, out) }
    #[cfg(target_arch = "aarch64")] { layout::arm_extract(image, out) }
}

fn patch(image: &mut [u8], saved: &[u8; sched::nt_callback::FP_BYTES]) -> bool {
    #[cfg(target_arch = "x86_64")] { layout::x86_patch(image, saved, hal_x86_64::xsave_active()) }
    #[cfg(target_arch = "aarch64")] { layout::arm_patch(image, saved) }
}

/// Save the live FPU registers into the task's own area, hand the image to
/// `f`, and reload the registers when `f` changed it. The running task owns
/// the FPU registers and its save area on this CPU for the whole dispatch.
/// # C: O(FPU image)
fn with_fpu_image(task: &Task, f: impl FnOnce(&mut [u8]) -> bool) {
    let _guard = sched::preempt::PreemptGuard::new();
    // SAFETY: this dispatch runs on the task's own kernel stack, the task is
    // the sole mutator of its fpu_state slot and holds the live FPU registers
    // while preemption is off; the area is ARCH_FPU_SIZE bytes, 64-aligned.
    unsafe {
        let buf = (*task.security.fpu_state.get()).as_mut_ptr();
        #[cfg(target_arch = "x86_64")]
        hal_x86_64::fpu_save(buf.cast::<hal_x86_64::FpuStateX86_64>());
        #[cfg(target_arch = "aarch64")]
        hal_aarch64::fpu_save(buf.cast::<hal_aarch64::FpuStateAArch64>());
        let image = core::slice::from_raw_parts_mut(buf, sched::ARCH_FPU_SIZE);
        if f(image) {
            #[cfg(target_arch = "x86_64")]
            hal_x86_64::fpu_restore(buf.cast::<hal_x86_64::FpuStateX86_64>());
            #[cfg(target_arch = "aarch64")]
            hal_aarch64::fpu_restore(buf.cast::<hal_aarch64::FpuStateAArch64>());
        }
    }
}
