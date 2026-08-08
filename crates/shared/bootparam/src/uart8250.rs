// 8250/16550 register model for the boot console.
//
// One definition of the register file, shared by both arches: the same UART
// is reached through port I/O on one and through MMIO on the other, and the
// only difference is the accessor. A per-arch copy of this sequence would be
// two definitions of "how is a 16550 programmed", which is exactly the split
// the project keeps paying for.

use crate::access::Access;

/// Register indices, before the io-type stride is applied.
pub mod reg {
    pub const THR: u32 = 0;
    pub const DLL: u32 = 0;
    pub const IER: u32 = 1;
    pub const DLM: u32 = 1;
    pub const FCR: u32 = 2;
    pub const LCR: u32 = 3;
    pub const MCR: u32 = 4;
    pub const LSR: u32 = 5;
}

/// LSR bit: transmit holding register empty.
pub const LSR_THRE: u8 = 1 << 5;
/// LSR bit: transmitter empty (shift register drained too).
pub const LSR_TEMT: u8 = 1 << 6;
/// LCR: 8 data bits.
const LCR_WLEN8: u8 = 0x03;
/// LCR: divisor latch access.
const LCR_DLAB: u8 = 0x80;
/// MCR: data-terminal-ready + request-to-send.
const MCR_DTR_RTS: u8 = 0x03;
/// IER bit retained across the interrupt mask (UART unit enable on the
/// implementations that define it).
const IER_UUE: u8 = 0x40;
/// Reference clock the divisor is derived from: 16x the 115200 base rate.
const UARTCLK: u32 = 115_200 * 16;

/// Program the port for `baud`, 8N1, no FIFO, interrupts masked. Mirrors the
/// minimal bring-up a boot console needs — it must work on a port the
/// firmware left in any state, and must not depend on anything the kernel has
/// not initialised yet.
/// # C: O(1)
pub fn init(a: &Access, baud: u32) {
    a.write(reg::LCR, LCR_WLEN8);
    let ier = a.read(reg::IER);
    a.write(reg::IER, ier & IER_UUE);
    a.write(reg::FCR, 0);
    a.write(reg::MCR, MCR_DTR_RTS);
    if baud != 0 {
        let divisor = (UARTCLK + 8 * baud) / (16 * baud);
        let lcr = a.read(reg::LCR);
        a.write(reg::LCR, lcr | LCR_DLAB);
        a.write(reg::DLL, (divisor & 0xff) as u8);
        a.write(reg::DLM, ((divisor >> 8) & 0xff) as u8);
        a.write(reg::LCR, lcr & !LCR_DLAB);
    }
}

/// Divisor this driver programs for `baud`. Exposed so the arithmetic is
/// checkable without a UART. # C: O(1)
pub fn divisor_for(baud: u32) -> u32 { if baud == 0 { 0 } else { (UARTCLK + 8 * baud) / (16 * baud) } }

/// Write one byte, waiting for the transmitter to drain afterwards. The wait
/// is bounded: a boot console that spins forever on a back-pressured emulated
/// UART converts a diagnosable hang into an undiagnosable one.
/// # C: O(spin up to the cap)
pub fn putc(a: &Access, b: u8) {
    a.write(reg::THR, b);
    let mut spins: u32 = 0;
    while a.read(reg::LSR) & (LSR_THRE | LSR_TEMT) != (LSR_THRE | LSR_TEMT) {
        spins += 1;
        if spins >= crate::SPIN_CAP { return; }
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn divisor_matches_the_standard_rates() {
        assert_eq!(divisor_for(115_200), 1);
        assert_eq!(divisor_for(57_600), 2);
        assert_eq!(divisor_for(38_400), 3);
        assert_eq!(divisor_for(9_600), 12);
        assert_eq!(divisor_for(0), 0, "no baud requested leaves the divisor alone");
    }

    #[test]
    fn init_programs_the_documented_register_sequence() {
        let _g = crate::access::recorder::serial();
        let a = Access::recording();
        init(&a, 115_200);
        // 8N1, mask interrupts, no FIFO, DTR+RTS, then the divisor behind DLAB.
        assert_eq!(a.recorded(), &[
            (reg::LCR, LCR_WLEN8),
            (reg::IER, 0),  // interrupts masked
            (reg::FCR, 0),
            (reg::MCR, MCR_DTR_RTS),
            (reg::LCR, LCR_WLEN8 | LCR_DLAB),
            (reg::DLL, 1),
            (reg::DLM, 0),
            (reg::LCR, LCR_WLEN8),
        ]);
    }

    #[test]
    fn a_byte_goes_to_the_transmit_register() {
        let _g = crate::access::recorder::serial();
        let a = Access::recording();
        putc(&a, b'A');
        assert_eq!(a.recorded(), &[(reg::THR, b'A')]);
    }
}
