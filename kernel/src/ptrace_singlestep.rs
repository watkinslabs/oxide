// PTRACE_SINGLESTEP arch glue.
//
// Two halves bridged here:
//
//   1. The kernel-to-user resume path arms the per-arch single-step
//      bit in the saved RFLAGS / SPSR slot when the current task has
//      `Task.singlestep` set. On x86_64 the syscall return asm calls
//      `oxide_x86_arm_singlestep` between dispatch return and the
//      final pops; on aarch64 the eret-trampoline runs the parallel
//      hook (lands in a follow-up).
//
//   2. The user-trap path posts SIGTRAP to the current task and
//      clears RFLAGS.TF / MDSCR_EL1.SS so the user instruction
//      retired exactly once. On x86_64 this rides hal_x86_64's
//      `UserTrapHook` (vec==1 #DB from CPL=3).
//
// Per `13§5` (singlestep AtomicU32 lives on Task) + `27§*` (signals).

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;

/// SIGTRAP per `27§3` Linux ABI table — signal number 5; sigpending
/// bitmask uses 0-indexed bit (sig - 1).
const SIGTRAP: u32 = 5;
/// RFLAGS.TF (Trap Flag) — single-step on x86.
#[cfg(target_arch = "x86_64")]
const RFLAGS_TF: u64 = 0x100;

/// Asm-callable hook from `oxide_syscall_entry`'s sysretq prologue.
/// Reads `Task.singlestep` and ORs RFLAGS.TF into `*rflags_ptr` if
/// set. Called with rax (syscall retval) preserved by the asm.
///
/// # SAFETY: caller is the syscall return asm; `rflags_ptr` points
/// at the user-RFLAGS quadword on the per-task syscall stack tail
/// (live until `pop r11`).
/// # C: O(1)
/// # Ctx: kernel-mode tail of syscall, IRQs off
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn oxide_x86_arm_singlestep(rflags_ptr: *mut u64) {
    let cur = match crate::sched::current() { Some(c) => c, None => return };
    if cur.singlestep.load(Ordering::Acquire) == 0 { return; }
    // SAFETY: per fn contract; `rflags_ptr` is a live aligned u64 on
    // the kernel stack we own at this asm point.
    unsafe { *rflags_ptr |= RFLAGS_TF; }
}

/// `UserTrapHook` impl — vec==1 (#DB) from CPL=3 means the user
/// instruction retired exactly once after PTRACE_SINGLESTEP armed
/// TF. Clear TF, post SIGTRAP, reset Task.singlestep so the next
/// resume goes back to normal-speed execution.
///
/// Returns `true` so the asm `iretq`s back to user with the cleared
/// frame. The pending SIGTRAP is delivered on the next syscall
/// boundary (or on next user-trap if user is wedged).
#[cfg(target_arch = "x86_64")]
fn x86_user_trap_hook(frame: &mut hal_x86_64::FaultFrame) -> bool {
    if frame.vector != 1 { return false; }
    frame.rflags &= !RFLAGS_TF;
    if let Some(cur) = crate::sched::current() {
        cur.sigpending.fetch_or(1u64 << (SIGTRAP - 1), Ordering::Release);
        cur.singlestep.store(0, Ordering::Release);
    }
    true
}

/// Install the per-arch user-trap hook so #DB / Software-Step traps
/// from user mode route to SIGTRAP delivery instead of the silent
/// fault halt.
///
/// # SAFETY: caller is the boot path; runs single-CPU pre-init.
/// # C: O(1)
pub unsafe fn install() {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: hook is a 'static fn; pre-init single-CPU swap.
    unsafe { hal_x86_64::install_user_trap_hook(x86_user_trap_hook); }
    // aarch64 follow-up adds the matching hook on the eret path.
}
