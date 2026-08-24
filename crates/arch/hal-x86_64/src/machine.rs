use hal::MachineOps;

/// x86_64 owner of the irreversible machine instructions.
pub struct X86MachineOps;

impl MachineOps for X86MachineOps {
    unsafe fn mask_local_irqs() {
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        {
            // SAFETY: terminal transition never restores the caller's state.
            unsafe { core::arch::asm!("cli", options(nomem, nostack, preserves_flags)); }
        }
    }

    unsafe fn halt() -> ! {
        loop {
            crate::cpu::halt();
            #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
            core::hint::spin_loop();
        }
    }

    unsafe fn restart(reset: unsafe fn() -> !) -> ! {
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        {
            // SAFETY: the caller owns the terminal transition and supplies
            // the validated kernel reset ladder.
            unsafe { reset() }
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
        {
            let _ = reset;
            // SAFETY: hosted builds have no machine reset endpoint.
            unsafe { Self::halt() }
        }
    }

    unsafe fn power_off(power_off: fn()) -> ! {
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        {
            power_off();
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
        {
            let _ = power_off;
        }
        // SAFETY: a returning firmware power-off call has failed to stop the
        // machine, so the only safe terminal state is a halted CPU.
        unsafe { Self::halt() }
    }
}
