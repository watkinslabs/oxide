// x86 mechanism for each reset rung. The ORDER lives in the parent module
// and is host-tested there; this file only performs the writes, and every
// one of them is a privileged port or physical-memory access that cannot
// run outside the kernel target.

use firmware::acpi::ResetAction;

use super::{KBD_COMMAND_PORT, KBD_PULSE_ATTEMPTS, KBD_PULSE_RESET, KBD_STATUS_INPUT_FULL,
    RESET_CONTROL_PORT, RESET_SETTLE_US, FIRMWARE_SETTLE_US, ResetRung, ladder,
    reset_control_writes};

/// Legacy PCI configuration address/data ports. The reference restricts a
/// FADT PCI reset register to bus 0, which is exactly the range this
/// mechanism can reach, so no ECAM mapping is required.
const PCI_CONFIG_ADDRESS: u16 = 0x0cf8;
const PCI_CONFIG_DATA: u16 = 0x0cfc;
const PCI_CONFIG_ENABLE: u32 = 0x8000_0000;

/// # SAFETY: writes one byte to an x86 I/O port; the caller is the terminal reset path and has already quiesced drivers.
unsafe fn outb(port: u16, value: u8) {
    // SAFETY: `out` on a caller-chosen port is legal at CPL=0; the reset path owns the machine at this point.
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags)); }
}

/// # SAFETY: reads one byte from an x86 I/O port; side effects are the port's own and the caller owns the machine.
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: `in` on a caller-chosen port is legal at CPL=0; the reset path owns the machine at this point.
    unsafe { core::arch::asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags)); }
    value
}

/// # SAFETY: writes one 32-bit word to an x86 I/O port.
unsafe fn outl(port: u16, value: u32) {
    // SAFETY: `out` on a caller-chosen port is legal at CPL=0; the reset path owns the machine at this point.
    unsafe { core::arch::asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags)); }
}

/// Spin for approximately `us` microseconds off the monotonic clock. The
/// reset path runs with drivers already shut down, so a sleeping wait has
/// nothing left to schedule against.
fn settle_us(us: u64) {
    use hal::TimerOps;
    let deadline = hal_x86_64::X86TimerOps::monotonic_ns().0.saturating_add(us.saturating_mul(1_000));
    while hal_x86_64::X86TimerOps::monotonic_ns().0 < deadline { core::hint::spin_loop(); }
}

/// Perform the write the FADT authorised.
/// # SAFETY: irreversible by intent; only reached from the terminal reset path.
unsafe fn firmware_reset(a: ResetAction) {
    match a {
        // SAFETY: the port and value are the ones firmware published as its reset register.
        ResetAction::PortIo { port, value } => unsafe { outb(port, value) },
        ResetAction::Mmio { pa, value } => {
            // SAFETY: the reset register's page is device memory firmware published; mapping it is the only way to reach the register.
            let va = unsafe { mmio_map::map_pages(pa & !0xfff, 1) };
            if va == 0 { return; }
            // SAFETY: `va` maps the frame containing `pa`; the byte offset stays inside that frame.
            unsafe { core::ptr::write_volatile((va + (pa & 0xfff)) as *mut u8, value) };
        }
        ResetAction::PciConfig { device, function, offset, value } => {
            // Bus 0 only, per the register's own constraint.
            let addr = PCI_CONFIG_ENABLE
                | ((device as u32 & 0x1f) << 11)
                | ((function as u32 & 0x7) << 8)
                | (offset as u32 & 0xfc);
            // SAFETY: the legacy configuration ports address bus 0 config space, which is where this register is required to live.
            unsafe {
                outl(PCI_CONFIG_ADDRESS, addr);
                outb(PCI_CONFIG_DATA + (offset & 0x3), value);
            }
        }
    }
}

/// Pulse the keyboard controller's CPU-reset line.
/// # SAFETY: irreversible by intent; only reached from the terminal reset path.
unsafe fn keyboard_controller_reset() {
    let mut i = 0u32;
    while i < KBD_PULSE_ATTEMPTS {
        // Drain the controller's input buffer so the command is not dropped.
        let mut spins = 0u32;
        // SAFETY: reading the controller's status port has no side effect beyond the read itself.
        while unsafe { inb(KBD_COMMAND_PORT) } & KBD_STATUS_INPUT_FULL != 0 && spins < 100_000 {
            spins += 1;
            core::hint::spin_loop();
        }
        settle_us(RESET_SETTLE_US);
        // SAFETY: 0xfe on the command port pulses the reset line; this is the rung's whole purpose.
        unsafe { outb(KBD_COMMAND_PORT, KBD_PULSE_RESET) };
        settle_us(RESET_SETTLE_US);
        i += 1;
    }
}

/// Request a reset through the chipset reset-control port.
/// # SAFETY: irreversible by intent; only reached from the terminal reset path.
unsafe fn reset_control() {
    // SAFETY: the reset-control port read-back carries chipset bits that must survive the write.
    let current = unsafe { inb(RESET_CONTROL_PORT) };
    let (request, fire) = reset_control_writes(current);
    // SAFETY: the paired writes are the documented request-then-reset sequence for this port.
    unsafe {
        outb(RESET_CONTROL_PORT, request);
        settle_us(RESET_SETTLE_US);
        outb(RESET_CONTROL_PORT, fire);
    }
    settle_us(RESET_SETTLE_US);
}

/// Triple fault: load a zero-limit interrupt descriptor table and take an
/// interrupt, so the fault cascade reaches the reset no rung below can decline.
/// # SAFETY: clobbers the IDT and never returns.
unsafe fn triple_fault() -> ! {
    // SAFETY: a zero-limit IDT makes the following breakpoint fault, then double-fault, then reset. Irreversible on purpose.
    unsafe {
        core::arch::asm!(
            "sub rsp, 16",
            "mov word ptr [rsp], 0",
            "mov qword ptr [rsp+2], 0",
            "lidt [rsp]",
            "int3",
            options(noreturn, nostack)
        );
    }
}

/// Walk the ladder. Each rung runs only because the machine is still
/// executing after the one before it.
/// # SAFETY: irreversible; the caller has validated the reboot request and shut the drivers down.
/// # C: O(1)
pub unsafe fn run_ladder() -> ! {
    let firmware = firmware::reset_action();
    for rung in ladder(firmware.is_some()) {
        match rung {
            ResetRung::Firmware => {
                if let Some(a) = firmware {
                    klog::write_raw(b"reset: firmware register\n");
                    // SAFETY: performs the write firmware published as its reset register.
                    unsafe { firmware_reset(a) };
                    settle_us(FIRMWARE_SETTLE_US);
                }
            }
            ResetRung::KeyboardController => {
                klog::write_raw(b"reset: keyboard controller\n");
                // SAFETY: pulses the legacy controller's reset line; no other state is touched.
                unsafe { keyboard_controller_reset() };
            }
            ResetRung::ResetControl => {
                klog::write_raw(b"reset: reset control port\n");
                // SAFETY: performs the chipset's documented request-then-reset port sequence.
                unsafe { reset_control() };
            }
            // SAFETY: terminal rung; the fault cascade resets the machine and never returns.
            ResetRung::TripleFault => unsafe { triple_fault() },
        }
    }
    // SAFETY: unreachable — the ladder always ends in the triple-fault rung, which diverges.
    unsafe { triple_fault() }
}
