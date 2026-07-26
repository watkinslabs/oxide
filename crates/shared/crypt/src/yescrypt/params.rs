// $y$ setting-string parameter codec: the variable-length base64 integer
// encoding (`encode64_uint32`/`decode64_uint32` in alg-yescrypt-common.c) for
// flavor/N_log2/r/p/t/g/NROM_log2, plus the yescrypt_params_t flag bits.
// Distinct from `b64::encode64`/`decode64` (fixed 3-bytes-to-4-chars salt
// codec) despite sharing the same itoa64 alphabet.
use super::b64::{atoi64, ITOA64};

pub const YESCRYPT_WORM: u32 = 1;
pub const YESCRYPT_RW: u32 = 0x002;
pub const YESCRYPT_ROUNDS_6: u32 = 0x004;
pub const YESCRYPT_GATHER_4: u32 = 0x010;
pub const YESCRYPT_SIMPLE_2: u32 = 0x020;
pub const YESCRYPT_SBOX_12K: u32 = 0x080;
const YESCRYPT_RW_FLAVOR_MASK: u32 = 0x3fc;
/// The one pwxform flavor libxcrypt's own optimized implementation supports
/// (all other RW flavor bit combinations are `#error` upstream — see
/// pwxform.rs module doc).
pub const YESCRYPT_RW_DEFAULTS: u32 = YESCRYPT_RW | YESCRYPT_ROUNDS_6 | YESCRYPT_GATHER_4 | YESCRYPT_SIMPLE_2 | YESCRYPT_SBOX_12K;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YescryptParams {
    pub flags: u32,
    pub n: u64,
    pub r: u32,
    pub p: u32,
    pub t: u32,
    pub g: u32,
    pub nrom: u64,
}

/// Is `flags` a combination this KDF can actually compute? Classic scrypt
/// (0), WORM (bit0 only), or exactly YESCRYPT_RW_DEFAULTS.
/// # C: O(1)
pub fn flags_supported(flags: u32) -> bool {
    flags == 0 || flags == YESCRYPT_WORM || flags == YESCRYPT_RW_DEFAULTS
}

struct Cursor<'a> { buf: &'a [u8], pos: usize }

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<u8> { self.buf.get(self.pos).copied() }

    fn next_c64(&mut self) -> Option<u8> {
        let c = atoi64(*self.buf.get(self.pos)?)?;
        self.pos += 1;
        Some(c)
    }

    /// decode64_uint32: variable-length base64 integer with a growing digit
    /// range per extra character (alg-yescrypt-common.c decode64_uint32).
    /// # C: O(1)
    fn decode_uint32(&mut self, min: u32) -> Option<u32> {
        let mut start: u32 = 0;
        let mut end: u32 = 47;
        let mut chars: u32 = 1;
        let mut bits: u32 = 0;
        let c = self.next_c64()? as u32;
        let mut dst = min;
        // Widen [start,end] until the single already-read char `c` fits —
        // matches the reference re-testing the SAME c each pass (no new
        // chars read here; extra chars are read below, one per widening).
        while c > end {
            dst = dst.checked_add((end + 1 - start) << bits)?;
            start = end + 1;
            end = start + (62 - end) / 2;
            chars += 1;
            bits += 6;
        }
        dst = dst.checked_add((c - start) << bits)?;
        while chars > 1 {
            chars -= 1;
            let c2 = self.next_c64()? as u32;
            bits -= 6;
            dst = dst.checked_add(c2 << bits)?;
        }
        Some(dst)
    }

    fn expect(&mut self, b: u8) -> Option<()> {
        if self.peek() == Some(b) { self.pos += 1; Some(()) } else { None }
    }
}

/// Parse the field portion of a `$y$<fields>$<salt...>` setting (the bytes
/// immediately after `"$y$"`). Returns (params, bytes consumed including the
/// trailing '$'). NROM (ROM) hashes are parsed but rejected (`nrom != 0`) —
/// we have no ROM support, matching yescrypt_kdf's own `shared==NULL` path.
/// # C: O(1)
pub fn parse_fields(src: &[u8]) -> Option<(YescryptParams, usize)> {
    let mut cur = Cursor { buf: src, pos: 0 };
    let flavor = cur.decode_uint32(0)?;
    let flags = if flavor < YESCRYPT_RW {
        flavor
    } else if flavor <= YESCRYPT_RW + (YESCRYPT_RW_FLAVOR_MASK >> 2) {
        YESCRYPT_RW + ((flavor - YESCRYPT_RW) << 2)
    } else {
        return None;
    };

    let n_log2 = cur.decode_uint32(1)?;
    if n_log2 > 63 { return None; }
    let n = 1u64 << n_log2;

    let r = cur.decode_uint32(1)?;

    let mut p: u32 = 1;
    let mut t: u32 = 0;
    let mut g: u32 = 0;
    let mut nrom: u64 = 0;
    if cur.peek() != Some(b'$') {
        let have = cur.decode_uint32(1)?;
        if have & 1 != 0 { p = cur.decode_uint32(2)?; }
        if have & 2 != 0 { t = cur.decode_uint32(1)?; }
        if have & 4 != 0 { g = cur.decode_uint32(1)?; }
        if have & 8 != 0 {
            let nrom_log2 = cur.decode_uint32(1)?;
            if nrom_log2 > 63 { return None; }
            nrom = 1u64 << nrom_log2;
        }
    }
    cur.expect(b'$')?;

    Some((YescryptParams { flags, n, r, p, t, g, nrom }, cur.pos))
}

fn encode_uint32(out: &mut alloc::vec::Vec<u8>, src: u32, min: u32) -> Option<()> {
    if src < min { return None; }
    let mut src = src - min;
    let mut start: u32 = 0;
    let mut end: u32 = 47;
    let mut chars: u32 = 1;
    let mut bits: u32 = 0;
    loop {
        let count = (end + 1 - start) << bits;
        if src < count { break; }
        if start >= 63 { return None; }
        start = end + 1;
        end = start + (62 - end) / 2;
        src -= count;
        chars += 1;
        bits += 6;
    }
    out.push(ITOA64[(start + (src >> bits)) as usize]);
    while chars > 1 {
        chars -= 1;
        bits -= 6;
        out.push(ITOA64[((src >> bits) & 0x3f) as usize]);
    }
    Some(())
}

/// Encode `params`' field portion (no salt), for `crypt_gensalt`. Mirrors
/// `yescrypt_encode_params_r` (alg-yescrypt-common.c): only ever emits the
/// one supported RW flavor, or classic (flags=0).
/// # C: O(1)
pub fn encode_fields(params: &YescryptParams) -> Option<alloc::vec::Vec<u8>> {
    if !flags_supported(params.flags) || params.g != 0 || params.nrom != 0 { return None; }
    let flavor = if params.flags < YESCRYPT_RW { params.flags } else { YESCRYPT_RW + (params.flags >> 2) };
    let n_log2 = {
        let mut k = 0u32;
        while (1u64 << k) < params.n { k += 1; }
        if 1u64 << k != params.n || k == 0 { return None; }
        k
    };
    if (params.r as u64) * (params.p as u64) >= (1u64 << 30) { return None; }

    let mut out = alloc::vec::Vec::new();
    encode_uint32(&mut out, flavor, 0)?;
    encode_uint32(&mut out, n_log2, 1)?;
    encode_uint32(&mut out, params.r, 1)?;
    let have = if params.p != 1 { 1u32 } else { 0 } | if params.t != 0 { 2 } else { 0 };
    if have != 0 {
        encode_uint32(&mut out, have, 1)?;
        if params.p != 1 { encode_uint32(&mut out, params.p, 2)?; }
        if params.t != 0 { encode_uint32(&mut out, params.t, 1)?; }
    }
    out.push(b'$');
    Some(out)
}

extern crate alloc;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn roundtrip_uint32(v: u32, min: u32) {
        let mut buf = Vec::new();
        encode_uint32(&mut buf, v, min).unwrap();
        let mut cur = Cursor { buf: &buf, pos: 0 };
        assert_eq!(cur.decode_uint32(min).unwrap(), v, "v={v} min={min}");
        assert_eq!(cur.pos, buf.len());
    }

    #[test]
    fn uint32_roundtrip_spread() {
        // Field values in practice (N_log2/NROM_log2<=63, r/p/t/g small);
        // the encoding's own max representable value (~17.3M, min=0) is
        // enforced by `encode_uint32` returning None beyond it (checked
        // separately, not a real-world field-size gap).
        for &v in &[0u32, 1, 2, 11, 12, 47, 48, 49, 100, 1000, 100_000, 0xFFFF, 0xFFFFF] {
            roundtrip_uint32(v, 0);
        }
        for &v in &[1u32, 2, 5, 12, 63] { roundtrip_uint32(v, 1); }
        for &v in &[2u32, 3, 12, 63] { roundtrip_uint32(v, 2); }
    }

    #[test]
    fn encode_uint32_rejects_out_of_range() {
        let mut buf = Vec::new();
        // Beyond the scheme's max representable value (min=0): fails cleanly
        // rather than silently truncating.
        assert!(encode_uint32(&mut buf, u32::MAX / 2, 0).is_none());
    }

    #[test]
    fn parse_known_j9t_prefix() {
        // "$y$j9T$..." -> field bytes after "$y$" are "j9T$"
        let (p, consumed) = parse_fields(b"j9T$salthere").unwrap();
        assert_eq!(p.flags, YESCRYPT_RW_DEFAULTS);
        assert_eq!(p.n, 4096);
        assert_eq!(p.r, 32);
        assert_eq!(p.p, 1);
        assert_eq!(p.t, 0);
        assert_eq!(p.g, 0);
        assert_eq!(p.nrom, 0);
        assert_eq!(consumed, 4); // "j9T$"
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_fields(b"!!!").is_none());
        assert!(parse_fields(b"j9T").is_none()); // missing trailing '$'
    }
}
