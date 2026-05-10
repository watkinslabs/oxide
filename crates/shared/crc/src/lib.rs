// CRC primitives. CRC32 (IEEE 802.3 / Ethernet / zlib reflected) +
// CRC32C (Castagnoli, RFC 3720 / iSCSI / SCTP / ext4 metadata_csum).
// Both compute via per-byte table lookup. Tables are static const
// so the kernel can call into this from any context (no heap, no
// external state).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

/// CRC32C polynomial (Castagnoli, reflected): 0x82F63B78.
pub const CRC32C_POLY: u32 = 0x82F63B78;

/// CRC32 (Ethernet/zlib) reflected polynomial: 0xEDB88320.
pub const CRC32_POLY: u32 = 0xEDB88320;

const fn build_table(poly: u32) -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i: u32 = 0;
    while i < 256 {
        let mut c = i;
        let mut j = 0;
        while j < 8 {
            c = if (c & 1) != 0 { (c >> 1) ^ poly } else { c >> 1 };
            j += 1;
        }
        t[i as usize] = c;
        i += 1;
    }
    t
}

static CRC32C_TBL: [u32; 256] = build_table(CRC32C_POLY);
static CRC32_TBL:  [u32; 256] = build_table(CRC32_POLY);

/// CRC32C of `bytes` continuing from `seed`. Pass `0xFFFF_FFFF`
/// as seed for a fresh CRC; XOR the final result with `0xFFFF_FFFF`
/// to get the standard "reflected" form (RFC 3720 / SCTP / ext4).
/// # C: O(N)
pub fn crc32c_update(seed: u32, bytes: &[u8]) -> u32 {
    let mut c = seed;
    for &b in bytes {
        c = CRC32C_TBL[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    c
}

/// One-shot CRC32C with the standard 0xFFFF_FFFF seed + finalize.
/// # C: O(N)
pub fn crc32c(bytes: &[u8]) -> u32 {
    crc32c_update(0xFFFF_FFFF, bytes) ^ 0xFFFF_FFFF
}

/// CRC32 (zlib/Ethernet) — same shape, different table.
/// # C: O(N)
pub fn crc32_update(seed: u32, bytes: &[u8]) -> u32 {
    let mut c = seed;
    for &b in bytes {
        c = CRC32_TBL[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    c
}

/// # C: O(1)
pub fn crc32(bytes: &[u8]) -> u32 {
    crc32_update(0xFFFF_FFFF, bytes) ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3720 §B.4 known test vectors for CRC32C.
    #[test]
    fn crc32c_known_vectors() {
        assert_eq!(crc32c(b""), 0x0000_0000);
        // "123456789" ASCII → 0xE3069283 (Castagnoli reference).
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn crc32_known_vector() {
        // "123456789" ASCII → 0xCBF43926 (zlib/Ethernet).
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn streaming_matches_oneshot() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let oneshot = crc32c(data);
        let mut s: u32 = 0xFFFF_FFFF;
        for chunk in data.chunks(7) { s = crc32c_update(s, chunk); }
        assert_eq!(s ^ 0xFFFF_FFFF, oneshot);
    }

    #[test]
    fn empty_returns_zero() {
        assert_eq!(crc32c(b""), 0);
        assert_eq!(crc32(b""),  0);
    }
}
