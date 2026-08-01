/// Register Linux CRC helper symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("crc32",       crc32       as *const () as usize),
        ("crc32_le",    crc32_le    as *const () as usize),
        ("crc32_be",    crc32_be    as *const () as usize),
        ("crc32c",      crc32c      as *const () as usize),
        ("__crc32c_le", __crc32c_le as *const () as usize),
        ("crc_t10dif_arch", crc_t10dif_arch as *const () as usize),
        ("crc_t10dif_generic", crc_t10dif_generic as *const () as usize),
    ] { export(name, addr, false); }
}

extern "C" fn crc32(seed: u32, data: *const u8, len: usize) -> u32 {
    crc32_le(seed, data, len)
}

extern "C" fn crc32_le(seed: u32, data: *const u8, len: usize) -> u32 {
    bytes(data, len).map(|b| crc::crc32_update(seed, b)).unwrap_or(seed)
}

extern "C" fn crc32c(seed: u32, data: *const u8, len: usize) -> u32 {
    __crc32c_le(seed, data, len)
}

extern "C" fn __crc32c_le(seed: u32, data: *const u8, len: usize) -> u32 {
    bytes(data, len).map(|b| crc::crc32c_update(seed, b)).unwrap_or(seed)
}

extern "C" fn crc32_be(seed: u32, data: *const u8, len: usize) -> u32 {
    bytes(data, len).map(|b| crc32_be_update(seed, b)).unwrap_or(seed)
}

extern "C" fn crc_t10dif_arch(seed: u16, data: *const u8, len: usize) -> u16 {
    crc_t10dif_generic(seed, data, len)
}

extern "C" fn crc_t10dif_generic(seed: u16, data: *const u8, len: usize) -> u16 {
    bytes(data, len).map(|b| crc_t10dif_update(seed, b)).unwrap_or(seed)
}

fn bytes<'a>(data: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 { return Some(&[]); }
    if data.is_null() { return None; }
    // SAFETY: caller supplies a readable kernel buffer of len bytes.
    Some(unsafe { core::slice::from_raw_parts(data, len) })
}

fn crc32_be_update(seed: u32, data: &[u8]) -> u32 {
    let mut crc = seed;
    for &byte in data {
        crc ^= (byte as u32) << CRC_BE_SHIFT;
        for _ in 0..CRC_BE_BITS {
            crc = if (crc & CRC_BE_TOP_BIT) != 0 {
                (crc << 1) ^ CRC32_BE_POLY
            } else {
                crc << 1
            };
        }
    }
    crc
}

const CRC_BE_SHIFT: u32 = 24;
const CRC_BE_BITS: usize = 8;
const CRC_BE_TOP_BIT: u32 = 0x8000_0000;
const CRC32_BE_POLY: u32 = 0x04C1_1DB7;
const CRC_T10DIF_TOP_BIT: u16 = 0x8000;
const CRC_T10DIF_POLY: u16 = 0x8BB7;

fn crc_t10dif_update(seed: u16, data: &[u8]) -> u16 {
    let mut crc = seed;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if (crc & CRC_T10DIF_TOP_BIT) != 0 {
                (crc << 1) ^ CRC_T10DIF_POLY
            } else {
                crc << 1
            };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    const CRC_FINAL_XOR: u32 = u32::MAX;
    const VECTOR: &[u8] = b"123456789";
    const CRC32_STANDARD: u32 = 0xCBF4_3926;
    const CRC32C_STANDARD: u32 = 0xE306_9283;
    const CRC32_BE_STANDARD: u32 = 0xFC89_1918;
    const CRC_T10DIF_STANDARD: u16 = 0xD0DB;

    #[test]
    fn crc32_le_matches_shared_crc() {
        let _modules = crate::test_serial::claim();
        let raw = crc32_le(CRC_FINAL_XOR, VECTOR.as_ptr(), VECTOR.len());
        assert_eq!(raw ^ CRC_FINAL_XOR, CRC32_STANDARD);
    }

    #[test]
    fn crc32c_matches_shared_crc() {
        let _modules = crate::test_serial::claim();
        let raw = __crc32c_le(CRC_FINAL_XOR, VECTOR.as_ptr(), VECTOR.len());
        assert_eq!(raw ^ CRC_FINAL_XOR, CRC32C_STANDARD);
    }

    #[test]
    fn crc32_be_known_vector() {
        let _modules = crate::test_serial::claim();
        let raw = crc32_be(CRC_FINAL_XOR, VECTOR.as_ptr(), VECTOR.len());
        assert_eq!(raw ^ CRC_FINAL_XOR, CRC32_BE_STANDARD);
    }

    #[test]
    fn crc_t10dif_known_vector() {
        let _modules = crate::test_serial::claim();
        assert_eq!(crc_t10dif_arch(0, VECTOR.as_ptr(), VECTOR.len()), CRC_T10DIF_STANDARD);
        assert_eq!(crc_t10dif_generic(0, VECTOR.as_ptr(), VECTOR.len()), CRC_T10DIF_STANDARD);
    }

    #[test]
    fn null_nonempty_returns_seed() {
        let _modules = crate::test_serial::claim();
        const SEED: u32 = 0x1020_3040;
        assert_eq!(crc32_le(SEED, core::ptr::null(), VECTOR.len()), SEED);
    }
}
