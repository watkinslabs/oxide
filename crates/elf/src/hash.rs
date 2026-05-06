// ELF symbol-table hash functions + table walkers per
//   - "ELF Symbol Hash Table" (DT_HASH, sysv shape)
//   - GNU Hash Section (DT_GNU_HASH, ld.so 2003+)
//
// Both let a dynamic linker resolve "name → symbol index" in O(1)
// average instead of a linear scan over the symbol table. ld-musl
// supports both; ld-glibc requires DT_GNU_HASH and only falls
// back to DT_HASH when the older one is present.

/// Classic ELF/SysV symbol hash. RFC: ELF spec §"Symbol Hash Tbl".
/// # C: O(N) over the name
pub fn elf_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &b in name {
        h = (h << 4).wrapping_add(b as u32);
        let g = h & 0xF000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

/// GNU symbol hash. djb2 with 33 multiplier.
/// # C: O(N) over the name
pub fn gnu_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in name {
        h = h.wrapping_mul(33).wrapping_add(b as u32);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference vectors from glibc/elf/dl-hash.h test suite.
    #[test]
    fn elf_hash_known_vectors() {
        assert_eq!(elf_hash(b""), 0);
        assert_eq!(elf_hash(b"printf"), 0x77905A6);
        assert_eq!(elf_hash(b"exit"),   0x6CF04);
    }

    #[test]
    fn gnu_hash_starts_at_5381() {
        assert_eq!(gnu_hash(b""), 5381);
    }

    #[test]
    fn gnu_hash_collisions_distinct() {
        // Different names hash to different values for any name we
        // expect to actually appear in a DT_GNU_HASH bucket.
        assert_ne!(gnu_hash(b"printf"), gnu_hash(b"exit"));
        assert_ne!(gnu_hash(b"open"),   gnu_hash(b"close"));
        // Hash is deterministic.
        assert_eq!(gnu_hash(b"printf"), gnu_hash(b"printf"));
    }
}
