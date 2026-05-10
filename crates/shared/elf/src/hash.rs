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

/// Look up `name` in a sysv DT_HASH table at `hash_bytes`.
/// `read_sym_name(idx) -> Option<&[u8]>` resolves a symbol index
/// to its NUL-terminated string in the linked DT_STRTAB.
/// Returns the symbol-table index of the first match.
/// # C: O(chain length) — worst case O(N)
pub fn lookup_sysv<F>(hash_bytes: &[u8], name: &[u8], mut read_sym_name: F) -> Option<u32>
where F: FnMut(u32) -> Option<alloc::vec::Vec<u8>>
{
    if hash_bytes.len() < 8 { return None; }
    let nbucket = u32::from_le_bytes(hash_bytes[0..4].try_into().unwrap());
    let nchain  = u32::from_le_bytes(hash_bytes[4..8].try_into().unwrap());
    let bucket_off = 8;
    let chain_off  = bucket_off + (nbucket as usize) * 4;
    let need = chain_off + (nchain as usize) * 4;
    if hash_bytes.len() < need { return None; }
    let h = elf_hash(name) % nbucket;
    let bucket_base = bucket_off + (h as usize) * 4;
    let mut idx = u32::from_le_bytes(hash_bytes[bucket_base..bucket_base+4].try_into().unwrap());
    while idx != 0 && idx < nchain {
        if let Some(sname) = read_sym_name(idx) {
            if sname == name { return Some(idx); }
        }
        let chain_pos = chain_off + (idx as usize) * 4;
        idx = u32::from_le_bytes(hash_bytes[chain_pos..chain_pos+4].try_into().unwrap());
    }
    None
}

/// Look up `name` in a DT_GNU_HASH table at `hash_bytes`.
/// `read_sym_name(idx) -> Option<&[u8]>` resolves a symbol index
/// to its name in the linked DT_STRTAB.
/// # C: O(chain length) with a Bloom-filter early-out
pub fn lookup_gnu<F>(hash_bytes: &[u8], name: &[u8], mut read_sym_name: F) -> Option<u32>
where F: FnMut(u32) -> Option<alloc::vec::Vec<u8>>
{
    if hash_bytes.len() < 16 { return None; }
    let nbuckets    = u32::from_le_bytes(hash_bytes[0..4].try_into().unwrap()) as usize;
    let symoffset   = u32::from_le_bytes(hash_bytes[4..8].try_into().unwrap());
    let bloom_size  = u32::from_le_bytes(hash_bytes[8..12].try_into().unwrap()) as usize;
    let bloom_shift = u32::from_le_bytes(hash_bytes[12..16].try_into().unwrap());
    let bloom_off   = 16;
    let buckets_off = bloom_off + bloom_size * 8;
    let chain_off   = buckets_off + nbuckets * 4;
    if hash_bytes.len() < chain_off { return None; }

    let h = gnu_hash(name);
    // Bloom filter check (Word = u64 on 64-bit ELF).
    if bloom_size > 0 {
        let word_idx = ((h / 64) as usize) % bloom_size;
        let mask = (1u64 << ((h as u64) & 63))
                 | (1u64 << ((h.wrapping_shr(bloom_shift)) as u64 & 63));
        let bloom_pos = bloom_off + word_idx * 8;
        let word = u64::from_le_bytes(hash_bytes[bloom_pos..bloom_pos+8].try_into().unwrap());
        if (word & mask) != mask { return None; }
    }

    let bucket_pos = buckets_off + (h as usize % nbuckets) * 4;
    let bucket_val = u32::from_le_bytes(hash_bytes[bucket_pos..bucket_pos+4].try_into().unwrap());
    if bucket_val == 0 { return None; }
    let mut idx = bucket_val;
    loop {
        let chain_idx_byte = chain_off + ((idx - symoffset) as usize) * 4;
        if chain_idx_byte + 4 > hash_bytes.len() { return None; }
        let chain_h = u32::from_le_bytes(hash_bytes[chain_idx_byte..chain_idx_byte+4].try_into().unwrap());
        if (chain_h | 1) == (h | 1) {
            // Hash matches (low bit cleared). Verify name.
            if let Some(sname) = read_sym_name(idx) {
                if sname == name { return Some(idx); }
            }
        }
        if (chain_h & 1) != 0 { break; }   // last entry in chain
        idx += 1;
    }
    None
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
    fn sysv_lookup_finds_symbol() {
        // Build a 4-bucket sysv hash table with two symbols:
        //   sym1 (idx=1) name "foo"
        //   sym2 (idx=2) name "bar"
        let nbucket = 4u32;
        let nchain  = 4u32;
        let h_foo = elf_hash(b"foo") % nbucket;
        let h_bar = elf_hash(b"bar") % nbucket;
        // Layout buckets[]: bucket[h_foo]=1, bucket[h_bar]=2 (with collision handled later)
        let mut hash = std::vec::Vec::new();
        hash.extend_from_slice(&nbucket.to_le_bytes());
        hash.extend_from_slice(&nchain.to_le_bytes());
        let mut buckets = std::vec![0u32; nbucket as usize];
        // Avoid bucket-collision in this minimal test.
        if h_foo == h_bar { return; }
        buckets[h_foo as usize] = 1;
        buckets[h_bar as usize] = 2;
        for b in &buckets { hash.extend_from_slice(&b.to_le_bytes()); }
        let chain = std::vec![0u32; nchain as usize];
        for c in &chain { hash.extend_from_slice(&c.to_le_bytes()); }

        let resolver = |i: u32| -> Option<std::vec::Vec<u8>> {
            match i {
                1 => Some(b"foo".to_vec()),
                2 => Some(b"bar".to_vec()),
                _ => None,
            }
        };
        assert_eq!(lookup_sysv(&hash, b"foo", &resolver), Some(1));
        assert_eq!(lookup_sysv(&hash, b"bar", &resolver), Some(2));
        assert_eq!(lookup_sysv(&hash, b"missing", &resolver), None);
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
