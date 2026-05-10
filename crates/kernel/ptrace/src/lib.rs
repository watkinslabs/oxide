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






#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use core::sync::atomic::Ordering;

/// SIGTRAP per `27§3` Linux ABI table — signal number 5; sigpending
/// bitmask uses 0-indexed bit (sig - 1).
const SIGTRAP: u32 = 5;
/// RFLAGS.TF (Trap Flag) — single-step on x86.
#[cfg(target_arch = "x86_64")]
const RFLAGS_TF: u64 = 0x100;
/// SPSR_EL1.SS — software-step on aarch64. Bit 21.
#[cfg(target_arch = "aarch64")]
const SPSR_SS: u64 = 1 << 21;
/// SVC frame layout slot offsets per `oxide_lower_el_sync_handler`'s
/// 288-byte frame (see `vbar.rs` save block).
#[cfg(target_arch = "aarch64")]
const FRAME_X0_OFF:   usize = 0x00;
#[cfg(target_arch = "aarch64")]
const FRAME_SPSR_OFF: usize = 0xb8;

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
    let cur = match sched::current() { Some(c) => c, None => return };
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
    if let Some(cur) = sched::current() {
        cur.sigpending.fetch_or(1u64 << (SIGTRAP - 1), Ordering::Release);
        cur.singlestep.store(0, Ordering::Release);
    }
    true
}

/// Asm-callable hook from `oxide_lower_sync_restore` — arms
/// SPSR.SS + MDSCR_EL1.SS in the saved frame so the next user
/// instruction triggers a Software-Step exception.
///
/// # SAFETY: caller is the SVC/softstep return asm; `frame_ptr`
/// points at a 288 B SVC frame on the kernel stack.
/// # C: O(1)
/// # Ctx: kernel-mode tail of sync handler, IRQs masked
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn oxide_arm_arm_singlestep(frame_ptr: *mut u8) {
    let cur = match sched::current() { Some(c) => c, None => return };
    if cur.singlestep.load(Ordering::Acquire) == 0 { return; }
    // SAFETY: per fn contract; the SPSR slot is an aligned u64 within the 288 B frame we own.
    unsafe {
        let spsr_ptr = frame_ptr.add(FRAME_SPSR_OFF) as *mut u64;
        *spsr_ptr |= SPSR_SS;
    }
    // Set MDSCR_EL1.SS (bit 0) so the CPU treats SPSR.SS as
    // single-step rather than ignoring it. Stays set across the
    // step; cleared by the software-step handler.
    // SAFETY: MDSCR_EL1 is privileged; legal at EL1; RMW on a sysreg.
    unsafe {
        core::arch::asm!(
            "mrs  x9,  mdscr_el1",
            "orr  x9,  x9, #1",
            "msr  mdscr_el1, x9",
            out("x9") _,
            options(nostack, preserves_flags),
        );
    }
}

/// Asm-callable hook from `oxide_softstep_save_block` — handles a
/// Software-Step exception from user mode. Clears SPSR.SS in the
/// saved frame, clears MDSCR_EL1.SS kernel-side, posts SIGTRAP, and
/// clears Task.singlestep. Returns the original user x0 so the
/// shared restore block can store it to the retval slot — making
/// the post-restore `ldr x0, [sp, #0xc8]` a no-op for this path.
///
/// # SAFETY: caller is the softstep asm; `frame_ptr` points at a
/// fully-saved 288 B SVC frame.
/// # C: O(1)
/// # Ctx: synchronous exception, IRQs masked
#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub unsafe extern "C" fn oxide_arm_software_step_handler(frame_ptr: *mut u8) -> u64 {
    // SAFETY: per fn contract; frame is on our stack with valid SPSR + x0 slots.
    let (orig_x0, spsr_ptr) = unsafe {
        let x0_ptr   = frame_ptr.add(FRAME_X0_OFF)   as *const u64;
        let spsr_ptr = frame_ptr.add(FRAME_SPSR_OFF) as *mut u64;
        (core::ptr::read_volatile(x0_ptr), spsr_ptr)
    };
    // Clear SPSR.SS so the next instruction doesn't single-step.
    // SAFETY: spsr_ptr is the SPSR slot in the saved 288 B SVC frame; aligned u64; we own it for the duration of this hook.
    unsafe { *spsr_ptr &= !SPSR_SS; }
    // Clear MDSCR_EL1.SS so the CPU stops generating step exceptions
    // until the next PTRACE_SINGLESTEP arms it again.
    // SAFETY: MDSCR_EL1 is a privileged debug sysreg; legal RMW at EL1; single-CPU UP at this synchronous-trap context.
    unsafe {
        core::arch::asm!(
            "mrs  x9,  mdscr_el1",
            "bic  x9,  x9, #1",
            "msr  mdscr_el1, x9",
            out("x9") _,
            options(nostack, preserves_flags),
        );
    }
    if let Some(cur) = sched::current() {
        cur.sigpending.fetch_or(1u64 << (SIGTRAP - 1), Ordering::Release);
        cur.singlestep.store(0, Ordering::Release);
    }
    orig_x0
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
