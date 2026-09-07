//! Reflected CRC-32 over the ISO-HDLC polynomial, the checksum the NT RTL's
//! accumulation export computes. The caller's residue is the running value in
//! its final, complemented form: it is inverted on entry and again on exit, so
//! a residue of zero over a byte run yields that run's plain CRC-32 and
//! feeding a second run the first run's answer continues one checksum.

/// Reflected generator for the ISO-HDLC CRC-32.
const REFLECTED_POLYNOMIAL: u32 = 0xedb8_8320;
/// Value the residue is exclusive-ORed with on entry and on exit.
const RESIDUE_MASK: u32 = 0xffff_ffff;

/// Fold one byte into the internal (uncomplemented) residue.
/// # C: O(1)
const fn step(residue: u32, byte: u8) -> u32 {
    let mut value = residue ^ byte as u32;
    let mut bit = 0;
    while bit < 8 {
        value = if value & 1 != 0 { (value >> 1) ^ REFLECTED_POLYNOMIAL } else { value >> 1 };
        bit += 1;
    }
    value
}

/// Continue `residue` over `data`, in the caller-visible complemented form.
/// # C: O(N_bytes)
pub fn accumulate(residue: u32, data: &[u8]) -> u32 {
    let mut value = residue ^ RESIDUE_MASK;
    for byte in data { value = step(value, *byte); }
    value ^ RESIDUE_MASK
}
