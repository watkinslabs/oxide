//! Frame check sequence.
//!
//! An 8-bit CRC over the frame header, computed least-significant-bit first,
//! with the generator polynomial x^8 + x^2 + x + 1. The table is generated from
//! the polynomial rather than transcribed, so the polynomial is the thing that
//! can be checked.
//!
//! Coverage differs by frame type and getting it wrong is not loud: a UIH frame
//! covers the address and control bytes only, every other type covers the
//! length byte as well. A receiver that folds the length byte into a UIH frame's
//! check rejects every data frame the peer sends.

/// Generator polynomial, in the normal (most-significant-bit-first) form.
pub const FCS_POLY: u8 = 0x07;
/// The same polynomial reflected, which is the form a least-significant-bit
/// first CRC shifts with.
pub const FCS_POLY_REFLECTED: u8 = 0xe0;
/// The residue a correct frame's check byte folds to.
pub const FCS_GOOD: u8 = 0xcf;
/// The check byte is the ones-complement of the CRC against this value.
pub const FCS_COMPLEMENT: u8 = 0xff;

/// Per-byte CRC table, generated from `FCS_POLY_REFLECTED`. # C: O(1)
const fn build_table() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut c = i as u8;
        let mut bit = 0;
        while bit < 8 {
            c = if c & 0x01 != 0 { (c >> 1) ^ FCS_POLY_REFLECTED } else { c >> 1 };
            bit += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

/// The generated table.
pub static FCS_TABLE: [u8; 256] = build_table();

/// CRC over the address and control bytes. # C: O(1)
pub fn crc2(addr: u8, ctrl: u8) -> u8 {
    FCS_TABLE[(FCS_TABLE[(FCS_COMPLEMENT ^ addr) as usize] ^ ctrl) as usize]
}

/// Check byte of a UIH frame, which covers the address and control bytes.
/// # C: O(1)
pub fn fcs_uih(addr: u8, ctrl: u8) -> u8 { FCS_COMPLEMENT.wrapping_sub(crc2(addr, ctrl)) }

/// Check byte of every non-UIH frame, which additionally covers the length
/// byte. # C: O(1)
pub fn fcs_cmd(addr: u8, ctrl: u8, len: u8) -> u8 {
    FCS_COMPLEMENT.wrapping_sub(FCS_TABLE[(crc2(addr, ctrl) ^ len) as usize])
}

/// Whether a received frame's check byte is correct for its type. `is_uih`
/// selects the coverage. # C: O(1)
pub fn check(addr: u8, ctrl: u8, len: u8, is_uih: bool, fcs: u8) -> bool {
    let mut f = crc2(addr, ctrl);
    if !is_uih { f = FCS_TABLE[(f ^ len) as usize]; }
    FCS_TABLE[(f ^ fcs) as usize] == FCS_GOOD
}
