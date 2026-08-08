// Primitive field formatters shared by `status_render`. Numeric shapes come
// from Linux's `seq_put_decimal_ull`, `seq_put_hex_ll(.., 16)` (`render_cap_t`
// / `render_sigset_t`) and its `%*pb` / `%*pbl` bitmap forms.

use alloc::vec::Vec;

/// Bits per `%*pb` chunk (Linux `CHUNKSZ`). # C: O(1)
const CHUNKSZ: u32 = 32;

/// # C: O(b.len())
pub(crate) fn push(v: &mut Vec<u8>, b: &[u8]) { v.extend_from_slice(b); }

/// # C: O(log10 n)
pub(crate) fn push_dec(v: &mut Vec<u8>, mut n: u64) {
    if n == 0 { v.push(b'0'); return; }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    while i > 0 { i -= 1; v.push(buf[i]); }
}

/// # C: O(max(min_width, log8 n))
pub(super) fn push_octal(v: &mut Vec<u8>, mut n: u64, min_width: usize) {
    let mut buf = [0u8; 24];
    let mut i = 0;
    if n == 0 { buf[0] = b'0'; i = 1; }
    while n > 0 { buf[i] = b'0' + (n & 7) as u8; n >>= 3; i += 1; }
    while i < min_width { buf[i] = b'0'; i += 1; }
    while i > 0 { i -= 1; v.push(buf[i]); }
}

/// Lowercase hex zero-padded to `width` digits. # C: O(width)
fn push_hex(v: &mut Vec<u8>, n: u64, width: usize) {
    for shift in (0..width).rev() {
        let nib = ((n >> (shift * 4)) & 0xf) as u8;
        v.push(if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) });
    }
}

/// The 16-digit form `render_cap_t` / `render_sigset_t` use. # C: O(1)
pub(super) fn push_hex16(v: &mut Vec<u8>, n: u64) { push_hex(v, n, 16) }

/// Linux `%*pb` (`bitmap_string`): 32-bit chunks in hex, most-significant
/// first, comma-separated. Every chunk is 8 digits except the most significant
/// one, which is only as wide as the bit count needs — so a 1-CPU machine
/// prints `1`, not `00000001`. # C: O(nbits/4)
pub(super) fn push_cpumask(v: &mut Vec<u8>, mask: u64, nbits: u32) {
    if nbits == 0 { return; }
    let top_bits = match nbits % CHUNKSZ { 0 => CHUNKSZ, r => r };
    let chunks = nbits.div_ceil(CHUNKSZ);
    for c in (0..chunks).rev() {
        if c + 1 != chunks { v.push(b','); }
        let shift = c * CHUNKSZ;
        let width = if c + 1 == chunks { top_bits } else { CHUNKSZ };
        let chunk_mask = if width == 64 { u64::MAX } else { (1u64 << width) - 1 };
        let val = (mask >> shift) & chunk_mask;
        push_hex(v, val, width.div_ceil(4) as usize);
    }
}

/// Linux `%*pbl` (`bitmap_list_string`): ascending set-bit ranges, `a-b` for
/// runs of 2+ and a bare index otherwise, comma-separated. # C: O(nbits)
pub(super) fn push_cpulist(v: &mut Vec<u8>, mask: u64, nbits: u32) {
    let mut first = true;
    let mut i = 0u32;
    while i < nbits {
        if mask >> i & 1 == 0 { i += 1; continue; }
        let start = i;
        while i + 1 < nbits && mask >> (i + 1) & 1 == 1 { i += 1; }
        if !first { v.push(b','); }
        first = false;
        push_dec(v, start as u64);
        if i > start { v.push(b'-'); push_dec(v, i as u64); }
        i += 1;
    }
}
