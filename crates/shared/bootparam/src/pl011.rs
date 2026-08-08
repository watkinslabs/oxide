// PrimeCell PL011 boot-console writer.
//
// The port is used as firmware left it: a boot console exists to report what
// happened before the kernel configured anything, so re-programming the baud
// divisors here would be the boot console changing the very state it is meant
// to observe. Only the transmit path is driven.

use crate::access::Access;

mod reg {
    /// Data register.
    pub const DR: usize = 0x00;
    /// Flag register.
    pub const FR: usize = 0x18;
}

/// FR: transmit FIFO full.
const FR_TXFF: u32 = 1 << 5;
/// FR: transmitter busy.
const FR_BUSY: u32 = 1 << 3;

/// Write one byte, waiting for FIFO room first and for the shift register to
/// drain afterwards. Both waits are bounded so a stalled consumer cannot turn
/// the boot console into the hang it is diagnosing.
/// # C: O(spin up to the cap)
pub fn putc(a: &Access, b: u8) {
    let mut spins: u32 = 0;
    while a.read32(reg::FR) & FR_TXFF != 0 {
        spins += 1;
        if spins >= crate::SPIN_CAP { return; }
        core::hint::spin_loop();
    }
    a.write32(reg::DR, b as u32);
    spins = 0;
    while a.read32(reg::FR) & FR_BUSY != 0 {
        spins += 1;
        if spins >= crate::SPIN_CAP { return; }
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_byte_goes_to_the_data_register_and_nothing_else() {
        let _g = crate::access::recorder::serial();
        let a = Access::recording();
        putc(&a, b'Z');
        assert_eq!(a.recorded(), &[(reg::DR as u32, b'Z')], "the boot console must not reprogram the port");
    }
}
