use hal::MachineOps;

/// aarch64 owner of the irreversible machine instructions and PSCI calls.
pub struct ArmMachineOps;

impl MachineOps for ArmMachineOps {
    unsafe fn mask_local_irqs() {
        #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
        {
            // SAFETY: terminal transition never restores the caller's state.
            unsafe { core::arch::asm!("msr daifset, #2", options(nomem, nostack, preserves_flags)); }
        }
    }

    unsafe fn halt() -> ! {
        loop {
            crate::halt();
            #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
            core::hint::spin_loop();
        }
    }

    unsafe fn restart(reset: unsafe fn() -> !) -> ! {
        #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
        {
            let _ = reset;
            // SAFETY: firmware selected the PSCI conduit during early boot.
            let _ = unsafe { crate::psci::conduit_call(crate::psci::PSCI_SYSTEM_RESET, 0, 0, 0) };
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
        {
            let _ = reset;
        }
        // SAFETY: a returning PSCI reset call did not stop the machine.
        unsafe { Self::halt() }
    }

    unsafe fn power_off(power_off: fn()) -> ! {
        #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
        {
            let _ = power_off;
            // SAFETY: firmware selected the PSCI conduit during early boot.
            let _ = unsafe { crate::psci::conduit_call(crate::psci::PSCI_SYSTEM_OFF, 0, 0, 0) };
            klog::announce("PSCI SYSTEM_OFF returned");
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
        {
            let _ = power_off;
        }
        // SAFETY: a returning power-off endpoint has failed to stop the
        // machine, so the only safe terminal state is a halted CPU.
        unsafe { Self::halt() }
    }
}
