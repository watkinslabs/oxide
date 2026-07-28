// Registry for the ONE return-to-user work loop.
//
// The loop body needs signal dequeue + delivery, which live in the `syscalls`
// work-fn crate; the IRQ and exception return paths live in `arch-irq` and the
// HAL crates. `syscalls` already depends on `arch-irq`, so the call cannot go
// the other way as a direct dependency — it goes through the fn pointer
// installed here at boot, the same shape as `preempt::set_schedule_hook` and
// `arch_irq::set_tick_poll_hook`.
//
// There is exactly ONE registered function. Every return path (syscall tail,
// IRQ exit, exception exit, both arches) reaches the same body; nothing
// open-codes a second copy of the loop.

use core::sync::atomic::{AtomicPtr, Ordering};

/// The arch entry paths' view of the interrupted register frame:
/// `*mut hal_x86_64::PtRegs` on x86_64, `*mut hal_aarch64::SvcFrame` on
/// aarch64. Type-erased because this crate sits below both HALs; the executor
/// casts it back under `#[cfg(target_arch)]` and is the only place that does.
pub type ExitToUserFn = unsafe extern "C" fn(regs: *mut u8);

static HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the return-to-user work loop. Boot path, before the first `sti` /
/// `msr daifclr` that can take an interrupt from user mode.
/// # SAFETY: `f` must remain valid for the kernel's lifetime and must accept
/// this arch's entry frame pointer.
/// # C: O(1)
pub unsafe fn set_hook(f: ExitToUserFn) { HOOK.store(f as *mut (), Ordering::Release); }

/// Whether a work loop is installed yet. Early boot (before the first user
/// task exists) has none, and an IRQ taken then has no user frame to service.
/// # C: O(1)
pub fn installed() -> bool { !HOOK.load(Ordering::Acquire).is_null() }

/// Run the work loop for a return that is about to reach user mode.
///
/// Called from the arch IRQ/exception exit with interrupts MASKED and the
/// hardirq accounting already dropped (`preempt::irq_exit`), matching Linux's
/// `irqentry_exit_to_user_mode`, which is documented "invoked with interrupts
/// disabled and fully valid regs" and returns with interrupts disabled so the
/// caller's `iretq`/`eret` is atomic against a newly posted signal.
///
/// # SAFETY: `regs` is the live entry frame for this return, owned by the
/// calling entry path for the whole call, and is this arch's frame type.
/// # C: O(1) plus the work the loop services
/// # Ctx: return-to-user, IRQs masked, not hardirq
pub unsafe fn run(regs: *mut u8) {
    let raw = HOOK.load(Ordering::Acquire);
    if raw.is_null() { return; }
    // SAFETY: `set_hook` round-trips an `ExitToUserFn` through the same
    // pointer type; a non-null slot therefore always holds that ABI.
    let f: ExitToUserFn = unsafe { core::mem::transmute(raw) };
    // SAFETY: caller's contract — `regs` is the live entry frame for this
    // arch, and the loop runs on the interrupted task's own kernel stack.
    unsafe { f(regs); }
}
