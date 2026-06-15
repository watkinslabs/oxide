// Symbol resolution within a DSO (docs/59§5). Reuses `elf::hash`'s
// DT_GNU_HASH / DT_HASH table walkers; this layer wires them to the DSO's
// DT_SYMTAB + DT_STRTAB so a name resolves to a symbol index and then to its
// st_value/binding/type/shndx. glibc requires GNU_HASH and falls back to the
// classic table only when GNU_HASH is absent.
use alloc::vec::Vec;
use elf::{lookup_gnu, lookup_sysv};

/// Elf64_Sym is 24 bytes: st_name(u32)@0, st_info(u8)@4, st_other(u8)@5,
/// st_shndx(u16)@6, st_value(u64)@8, st_size(u64)@16.
pub const SYMENT: usize = 24;

pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;
pub const SHN_UNDEF: u16 = 0;

/// A DSO's symbol + string tables, as in-memory byte windows.
pub struct SymView<'a> {
    pub symtab: &'a [u8],
    pub strtab: &'a [u8],
}

impl<'a> SymView<'a> {
    fn field(&self, idx: u32, off: usize, len: usize) -> Option<&'a [u8]> {
        let base = (idx as usize) * SYMENT + off;
        self.symtab.get(base..base + len)
    }
    /// # C: strtab string for symbol idx (st_name → DT_STRTAB)
    pub fn name(&self, idx: u32) -> Option<&'a [u8]> {
        let st_name = u32::from_le_bytes(self.field(idx, 0, 4)?.try_into().ok()?) as usize;
        let s = self.strtab.get(st_name..)?;
        let end = s.iter().position(|&b| b == 0)?;
        Some(&s[..end])
    }
    /// # C: st_value of symbol idx
    pub fn value(&self, idx: u32) -> Option<u64> {
        Some(u64::from_le_bytes(self.field(idx, 8, 8)?.try_into().ok()?))
    }
    /// # C: st_info of symbol idx (binding<<4 | type)
    pub fn info(&self, idx: u32) -> Option<u8> {
        self.field(idx, 4, 1).map(|b| b[0])
    }
    /// # C: st_shndx of symbol idx (SHN_UNDEF == undefined)
    pub fn shndx(&self, idx: u32) -> Option<u16> {
        Some(u16::from_le_bytes(self.field(idx, 6, 2)?.try_into().ok()?))
    }
    /// # C: symbol binding (st_info >> 4)
    pub fn binding(&self, idx: u32) -> Option<u8> { self.info(idx).map(|i| i >> 4) }
    /// # C: true if symbol idx is a defined (non-UNDEF) export
    pub fn is_defined(&self, idx: u32) -> bool {
        self.shndx(idx).is_some_and(|s| s != SHN_UNDEF)
    }
}

/// Resolve `name` to its symbol-table index using GNU_HASH (preferred) or
/// the classic DT_HASH table. Returns None if absent in both / not found.
///
/// # C: gnu-hash then sysv-hash lookup of `name`
pub fn resolve(gnu_hash: Option<&[u8]>, sysv_hash: Option<&[u8]>, sym: &SymView, name: &[u8]) -> Option<u32> {
    let read = |i: u32| -> Option<Vec<u8>> { sym.name(i).map(|s| s.to_vec()) };
    if let Some(h) = gnu_hash {
        if let Some(idx) = lookup_gnu(h, name, read) { return Some(idx); }
        // GNU_HASH present but miss → symbol genuinely absent here.
        return None;
    }
    if let Some(h) = sysv_hash {
        return lookup_sysv(h, name, read);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use elf::gnu_hash;

    // Build a symtab (Elf64_Sym array) + strtab for the given (name, value)
    // pairs. Index 0 is the reserved null symbol.
    fn build_syms(syms: &[(&[u8], u64, u16)]) -> (Vec<u8>, Vec<u8>) {
        let mut strtab = std::vec![0u8]; // leading NUL
        let mut symtab = std::vec![0u8; SYMENT]; // null sym
        for (name, value, shndx) in syms {
            let st_name = strtab.len() as u32;
            strtab.extend_from_slice(name);
            strtab.push(0);
            let mut e = std::vec![0u8; SYMENT];
            e[0..4].copy_from_slice(&st_name.to_le_bytes());
            e[4] = STB_GLOBAL << 4; // global func
            e[6..8].copy_from_slice(&shndx.to_le_bytes());
            e[8..16].copy_from_slice(&value.to_le_bytes());
            symtab.extend_from_slice(&e);
        }
        (symtab, strtab)
    }

    #[test]
    fn symview_accessors() {
        let (symtab, strtab) = build_syms(&[(b"printf", 0x1234, 7), (b"undef", 0, SHN_UNDEF)]);
        let v = SymView { symtab: &symtab, strtab: &strtab };
        assert_eq!(v.name(1), Some(&b"printf"[..]));
        assert_eq!(v.value(1), Some(0x1234));
        assert_eq!(v.binding(1), Some(STB_GLOBAL));
        assert!(v.is_defined(1));
        assert!(!v.is_defined(2)); // SHN_UNDEF
    }

    #[test]
    fn resolve_via_sysv() {
        let (symtab, strtab) = build_syms(&[(b"foo", 0xaa, 7), (b"bar", 0xbb, 7)]);
        let v = SymView { symtab: &symtab, strtab: &strtab };
        // 4-bucket sysv table; place foo@idx1, bar@idx2 (skip on collision)
        let nbucket = 8u32;
        let h_foo = elf::elf_hash(b"foo") % nbucket;
        let h_bar = elf::elf_hash(b"bar") % nbucket;
        if h_foo == h_bar { return; }
        let nchain = 3u32;
        let mut hash = std::vec::Vec::new();
        hash.extend_from_slice(&nbucket.to_le_bytes());
        hash.extend_from_slice(&nchain.to_le_bytes());
        let mut buckets = std::vec![0u32; nbucket as usize];
        buckets[h_foo as usize] = 1;
        buckets[h_bar as usize] = 2;
        for b in &buckets { hash.extend_from_slice(&b.to_le_bytes()); }
        for c in &[0u32, 0, 0] { hash.extend_from_slice(&c.to_le_bytes()); }
        assert_eq!(resolve(None, Some(&hash), &v, b"foo"), Some(1));
        assert_eq!(resolve(None, Some(&hash), &v, b"bar"), Some(2));
        assert_eq!(resolve(None, Some(&hash), &v, b"none"), None);
    }

    #[test]
    fn resolve_via_gnu() {
        // single symbol "sym0" at index 1 (symoffset=1). Build a 1-bucket
        // gnu-hash table with a 1-word bloom filter.
        let (symtab, strtab) = build_syms(&[(b"sym0", 0x99, 7)]);
        let v = SymView { symtab: &symtab, strtab: &strtab };
        let h = gnu_hash(b"sym0");
        let bloom_shift = 6u32;
        let nbuckets = 1u32;
        let symoffset = 1u32;
        let bloom_size = 1u32;
        let mut hash = std::vec::Vec::new();
        hash.extend_from_slice(&nbuckets.to_le_bytes());
        hash.extend_from_slice(&symoffset.to_le_bytes());
        hash.extend_from_slice(&bloom_size.to_le_bytes());
        hash.extend_from_slice(&bloom_shift.to_le_bytes());
        let word = (1u64 << ((h as u64) & 63)) | (1u64 << ((h.wrapping_shr(bloom_shift)) as u64 & 63));
        hash.extend_from_slice(&word.to_le_bytes()); // bloom[0]
        hash.extend_from_slice(&1u32.to_le_bytes()); // buckets[0] = 1 (first sym idx)
        hash.extend_from_slice(&(h | 1).to_le_bytes()); // chain[0]: hash, low bit=1 (end)
        assert_eq!(resolve(Some(&hash), None, &v, b"sym0"), Some(1));
        assert_eq!(resolve(Some(&hash), None, &v, b"absent"), None); // bloom reject or miss
    }
}
