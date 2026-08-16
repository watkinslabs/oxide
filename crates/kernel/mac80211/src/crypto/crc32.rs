// The integrity check value the two stream ciphers append.
//
// This is the ordinary reflected polynomial, computed bit by bit rather than
// from a table: the frames it runs over are short, and a 1 KiB table in a
// kernel image to save a few cycles on a cipher nothing should still be using
// is the wrong trade.

/// Reflected form of the polynomial.
const POLY: u32 = 0xedb8_8320;

/// Running value over `data`, continuing from `crc`. # C: O(len)
pub fn update(crc: u32, data: &[u8]) -> u32 {
    let mut crc = crc;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ POLY } else { crc >> 1 };
        }
    }
    crc
}

/// The check value a frame carries: the running value over the whole
/// payload, inverted at both ends. # C: O(len)
pub fn icv(data: &[u8]) -> u32 { !update(!0, data) }

/// The four bytes as they appear on the air, least significant first.
/// # C: O(len)
pub fn icv_bytes(data: &[u8]) -> [u8; 4] { icv(data).to_le_bytes() }
