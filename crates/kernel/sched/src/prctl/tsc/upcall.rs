// aarch64 counter-read-trap upcalls.
//
// The EL0 sysreg-trap emulator lives in the HAL, below the scheduler, so it
// cannot read `Task::tsc_sigsegv` itself. These two symbols are the whole
// interface: "may this task read the counter?" and "deliver the signal it
// gets instead". Keeping the POLICY here rather than shadowing the flag into
// a per-CPU word in the HAL means there is one source of truth for the mode.

use core::sync::atomic::Ordering;

/// Non-zero when the current task armed `PR_TSC_SIGSEGV`.
///
/// A trap with no current task (early boot, kthread) answers "allowed": the
/// kernel's own counter reads never trap, and refusing here would turn a
/// bring-up read into a signal delivery with nobody to receive it.
///
/// # SAFETY: called from the EL0 sysreg-trap handler with IRQs masked; reads
/// one atomic on the current task and takes no locks.
/// # C: O(1)
/// # Ctx: synchronous exception, IRQs masked
#[no_mangle]
pub unsafe extern "C" fn oxide_arm_counter_read_denied() -> u64 {
    match crate::live::current() {
        Some(cur) => cur.tsc_sigsegv.load(Ordering::Acquire) as u64,
        None => 0,
    }
}

/// Linux `cntvct_read_handler`'s `force_sig(SIGSEGV)` arm.
///
/// `force_sig` carries no `_sigfault` payload, so the delivered `si_code` is
/// `SI_KERNEL` and `si_addr` is zero — the same shape the x86_64 `#GP` from a
/// trapped `rdtsc` produces, which is what makes the option behave alike on
/// both arches. The faulting instruction is deliberately NOT skipped: a
/// handler that returns re-executes it and traps again, exactly as Linux
/// leaves it.
///
/// # SAFETY: `frame_ptr` is the live 288 B lower-EL sync frame on the current
/// task's kernel stack, supplied by the trap handler.
/// # C: O(1)
/// # Ctx: synchronous exception, IRQs masked
#[no_mangle]
pub unsafe extern "C" fn oxide_arm_counter_read_sigsegv(frame_ptr: *mut u8) -> u64 {
    // The per-task `svc_frame` slot still names the last SYSCALL's frame, so
    // the signal-frame builder would rewrite the wrong one without this.
    hal_aarch64::set_current_svc_frame(frame_ptr as u64);
    let Some(cur) = crate::live::current() else { return 0 };
    cur.svc_frame.store(frame_ptr as u64, Ordering::Release);
    // SAFETY: `frame_ptr` is the 288 B lower-EL sync frame; user x0 sits at offset 0.
    let saved_x0 = unsafe { core::ptr::read_volatile(frame_ptr as *const u64) };
    crate::live::force_sig_fault(crate::signum::Signum::Sigsegv, hal::fault_class::SI_KERNEL, 0, 0);
    saved_x0
}
