#[cfg(feature = "debug-boot")]
use crate::pl011::{Pl011, PL011_VIRT_BASE};
#[cfg(feature = "debug-boot")]
use klog::Uart;
#[cfg(feature = "debug-boot")]
use sync::{Spinlock, Tty as UartClass};
// Sole caller is `boot_emit`, which is `debug-boot`-gated; without that gate the
// semihosting sink is never installed.
#[cfg(all(target_os = "oxide-kernel", feature = "debug-boot"))]
mod semihost {
    /// ARM semihosting putc per ARMv8 semihosting spec §5.5
    /// (SYS_WRITEC = 0x03). QEMU `-semihosting-config target=native`
    /// intercepts the `hlt #0xf000` opcode at EL1, reads x0 = op,
    /// x1 = pointer to char, and emits the char to stdout.
    /// # SAFETY: privileged opcode legal at EL1 with semihosting
    /// enabled; `byte` lives across the call via stack-local `b`.
    /// # C: O(1) host-syscall trap
    pub unsafe fn putc(byte: u8) {
        let b: u32 = byte as u32;
        let p = &b as *const u32 as u64;
        // SAFETY: `hlt #0xf000` is the ARMv8 semihosting opcode;
        // QEMU intercepts it at EL1 when -semihosting-config is on.
        // x0 = SYS_WRITEC op id, x1 points to a u32 holding the byte.
        unsafe {
            core::arch::asm!(
                "hlt #0xf000",
                in("x0") 0x03_u64,    // SYS_WRITEC
                in("x1") p,
                lateout("x0") _,
                options(nostack, preserves_flags),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Boot-time klog sink. The self-bootstrap trampoline maps an HHDM
// device block over phys 0, so the PL011 at `0x0900_0000` is reachable
// at `ARM_SELFBOOT_HHDM + 0x0900_0000`; `boot_emit_pl011` drives it.
// ARM semihosting putc (`boot_emit`) remains as a paging-agnostic
// fallback sink for environments where the device block is absent.
// ---------------------------------------------------------------------------

#[cfg(feature = "debug-boot")]
static BOOT_UART: Spinlock<Pl011, UartClass>
    = Spinlock::new(Pl011::new(PL011_VIRT_BASE));

/// klog `LogSink` adapter via semihosting. Each byte triggers a
/// `hlt #0xf000` at EL1; QEMU intercepts and emits the byte to its
/// stdout — same channel `-serial stdio` lands on.
/// # C: O(len)
#[cfg(feature = "debug-boot")]
pub(crate) fn boot_emit(bytes: &[u8]) {
    #[cfg(target_os = "oxide-kernel")]
    {
        for &b in bytes {
            // SAFETY: privileged opcode legal at EL1 with semihosting
            // enabled by QEMU `-semihosting-config target=native`.
            unsafe { semihost::putc(b); }
        }
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    { let _ = bytes; }
}

/// Alternative klog sink via PL011 MMIO over the trampoline-installed
/// HHDM device block. Uses `lock_irqsave` per `06§3.1` for symmetry
/// with the x86 path: any IRQ-context klog (timer, fault, panic) needs
/// the IRQ-off window to avoid deadlock against a kernel-mode holder.
/// # C: O(bytes)
#[cfg(feature = "debug-boot")]
pub(crate) fn boot_emit_pl011(bytes: &[u8]) {
    let mut g = BOOT_UART.lock_irqsave::<hal_aarch64::ArmIrqGate>();
    g.write_bytes(bytes);
}

/// klog clock thunk — surfaces `ArmTimerOps::monotonic_ns` as the
/// `klog::ClockFn` after `set_cntfrq_khz` calibration.
/// # C: O(1)
pub(crate) fn now_ns_aarch64() -> u64 {
    use hal::TimerOps;
    hal_aarch64::ArmTimerOps::monotonic_ns().0
}

/// Boot-time CPU identification log. Reads MIDR_EL1 and the MMU
/// control registers the boot trampoline programmed before handoff.
/// # C: O(1)
#[cfg(feature = "debug-boot")]
pub(crate) fn log_cpu_info() {
    let m = hal_aarch64::midr_el1();
    klog::write_raw(b"[INFO]  midr_el1=");
    klog::write_hex_u64(m);
    klog::write_raw(b"\n[INFO]  mmu sctlr_el1=");
    klog::write_hex_u64(hal_aarch64::read_sctlr_el1());
    klog::write_raw(b" tcr_el1=");
    klog::write_hex_u64(hal_aarch64::read_tcr_el1());
    klog::write_raw(b" mair_el1=");
    klog::write_hex_u64(hal_aarch64::read_mair_el1());
    klog::write_raw(b"\n[INFO]  mmu ttbr0_el1=");
    klog::write_hex_u64(hal_aarch64::read_ttbr0_el1());
    klog::write_raw(b" ttbr1_el1=");
    klog::write_hex_u64(hal_aarch64::read_ttbr1_el1());
    klog::write_raw(b"\n");
}
