// Bounded CPL=0 port-I/O primitives against the i8042 at 0x60/0x64. Every spin
// here carries a budget so a dead or absent controller cannot wedge boot.

use super::regs::*;

/// # SAFETY: privileged port I/O legal at CPL=0; no memory effect.
#[inline]
pub(super) unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    // SAFETY: `in` at CPL=0 reads one byte from an x86 I/O port; the i8042 ports have no DMA/memory side effect on the caller's state.
    unsafe { core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack, preserves_flags)); }
    v
}

/// # SAFETY: privileged port I/O legal at CPL=0; no memory effect.
#[inline]
pub(super) unsafe fn outb(port: u16, v: u8) {
    // SAFETY: `out` at CPL=0 writes one byte to an x86 I/O port; the i8042 ports have no DMA/memory side effect on the caller's state.
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags)); }
}

/// Spin until the input buffer is clear, so a controller/device write
/// won't be dropped. Bounded so a dead controller can't wedge boot.
/// # SAFETY: status-port read at CPL=0; single-CPU boot context.
pub(super) unsafe fn wait_writable() {
    let mut n = 0u32;
    // SAFETY: reading the i8042 status register (0x64) at CPL=0 has no side effect.
    while n < WAIT_WRITABLE_SPINS && unsafe { inb(CMD) } & STS_INPUT_FULL != 0 {
        n += 1;
    }
}

/// Read one byte from the output buffer once it's full, bounded.
/// Returns None if no byte arrives in the spin budget.
/// # SAFETY: status + data port reads at CPL=0; single-CPU boot context.
pub(super) unsafe fn read_blocking() -> Option<u8> {
    let mut n = 0u32;
    loop {
        // SAFETY: reading the i8042 status register (0x64) at CPL=0 has no side effect.
        if unsafe { inb(CMD) } & STS_OUTPUT_FULL != 0 {
            // SAFETY: STS_OUTPUT_FULL set ⇒ the data port (0x60) holds a byte to read at CPL=0.
            return Some(unsafe { inb(DATA) });
        }
        n += 1;
        if n >= READ_BLOCKING_SPINS {
            return None;
        }
    }
}

/// Write a controller command to port 0x64. # SAFETY: as `wait_writable`.
pub(super) unsafe fn write_cmd(c: u8) {
    // SAFETY: drain-then-write — wait_writable + the command write are CPL=0 port I/O to the i8042.
    unsafe {
        wait_writable();
        outb(CMD, c);
    }
}

/// Write a byte to the keyboard device (data port 0x60).
/// # SAFETY: as `wait_writable`.
pub(super) unsafe fn write_data(b: u8) {
    // SAFETY: drain-then-write — wait_writable + the data write are CPL=0 port I/O to the i8042.
    unsafe {
        wait_writable();
        outb(DATA, b);
    }
}

/// Drain and discard any pending output bytes (flush stale state left
/// by firmware before we take ownership). Bounded.
/// # SAFETY: status + data reads at CPL=0; single-CPU boot context.
pub(super) unsafe fn flush_output() {
    let mut n = 0u32;
    // SAFETY: reading status (0x64) + data (0x60) at CPL=0 to drain stale bytes has no side effect beyond clearing the buffer.
    while n < FLUSH_MAX_BYTES && unsafe { inb(CMD) } & STS_OUTPUT_FULL != 0 {
        // SAFETY: output-buffer-full ⇒ a byte is present at the data port; discard it.
        let _ = unsafe { inb(DATA) };
        n += 1;
    }
}

/// Send a keyboard-device command and wait for the 0xFA ACK.
/// Returns true on ACK. # SAFETY: as `Ps2KbdDriver::probe`.
pub(super) unsafe fn kbd_cmd(b: u8) -> bool {
    // SAFETY: CPL=0 data-port write then a bounded ACK read; single-CPU boot.
    unsafe {
        write_data(b);
        matches!(read_blocking(), Some(KBD_ACK))
    }
}
