// PT_DYNAMIC walker — reads the array of (d_tag, d_val/d_ptr)
// pairs that the dynamic linker consumes to find string table,
// symbol table, relocation table, hash table, etc.
//
// Per ELF64-x86-64 ABI § "Dynamic Section". 16 bytes per entry:
// i64 d_tag + u64 d_val. Terminator entry has tag == DT_NULL.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::parser::ElfError;

pub const DT_NULL:        i64 = 0;
pub const DT_NEEDED:      i64 = 1;
pub const DT_PLTRELSZ:    i64 = 2;
pub const DT_PLTGOT:      i64 = 3;
pub const DT_HASH:        i64 = 4;
pub const DT_STRTAB:      i64 = 5;
pub const DT_SYMTAB:      i64 = 6;
pub const DT_RELA:        i64 = 7;
pub const DT_RELASZ:      i64 = 8;
pub const DT_RELAENT:     i64 = 9;
pub const DT_STRSZ:       i64 = 10;
pub const DT_SYMENT:      i64 = 11;
pub const DT_INIT:        i64 = 12;
pub const DT_FINI:        i64 = 13;
pub const DT_SONAME:      i64 = 14;
pub const DT_RPATH:       i64 = 15;
pub const DT_PLTREL:      i64 = 20;
pub const DT_JMPREL:      i64 = 23;
pub const DT_INIT_ARRAY:  i64 = 25;
pub const DT_FINI_ARRAY:  i64 = 26;
pub const DT_INIT_ARRAYSZ:i64 = 27;
pub const DT_FINI_ARRAYSZ:i64 = 28;
pub const DT_RUNPATH:     i64 = 29;
pub const DT_FLAGS:       i64 = 30;
pub const DT_GNU_HASH:    i64 = 0x6FFFFEF5;
pub const DT_VERSYM:      i64 = 0x6FFFFFF0;
pub const DT_RELRSZ:      i64 = 35;
pub const DT_RELR:        i64 = 36;
pub const DT_RELRENT:     i64 = 37;

/// Hard bounds applied before any dynamic metadata is retained.
pub const MAX_DYNAMIC_ENTRIES: usize = 4096;
pub const MAX_NEEDED_LIBRARIES: usize = 256;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DynEntry {
    pub tag: i64,
    pub val: u64,
}

/// Parsed PT_DYNAMIC contents — every tag a v1 dynamic linker
/// reads. Caller resolves the *_ADDR fields against `load_bias`
/// to get the in-memory address.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DynInfo {
    pub strtab_addr:   Option<u64>,
    pub strtab_size:   Option<u64>,
    pub symtab_addr:   Option<u64>,
    pub syment:        Option<u64>,
    pub hash_addr:     Option<u64>,
    pub gnu_hash_addr: Option<u64>,
    pub rela_addr:     Option<u64>,
    pub rela_size:     Option<u64>,
    pub rela_ent:      Option<u64>,
    pub jmprel_addr:   Option<u64>,
    pub pltrel_size:   Option<u64>,
    pub pltrel_kind:   Option<u64>,    // 7=DT_RELA, 17=DT_REL
    pub init_addr:     Option<u64>,
    pub fini_addr:     Option<u64>,
    pub init_array:    Option<u64>,
    pub init_array_sz: Option<u64>,
    pub fini_array:    Option<u64>,
    pub fini_array_sz: Option<u64>,
    pub soname_off:    Option<u64>,
    pub flags:         Option<u64>,
    pub needed:        Vec<u64>,        // DT_NEEDED string offsets
    pub runpath_off:   Option<u64>,
    pub rpath_off:     Option<u64>,
    pub relr_addr:     Option<u64>,
    pub relr_size:     Option<u64>,
    pub relr_ent:      Option<u64>,
}

/// Walk the dynamic section starting at byte offset `dyn_off` in
/// `file` (the PT_DYNAMIC's `p_offset`) for `dyn_size` bytes.
/// Returns `DynInfo` populated with every recognized tag.
/// # C: O(N entries)
pub fn parse_dynamic(file: &[u8], dyn_off: usize, dyn_size: usize) -> Result<DynInfo, ElfError> {
    if dyn_off.checked_add(dyn_size).map_or(true, |end| end > file.len()) || dyn_size % 16 != 0 {
        return Err(ElfError::Einval);
    }
    let mut info = DynInfo::default();
    let mut o = dyn_off;
    let end = dyn_off + dyn_size;
    let mut entries = 0;
    let mut terminated = false;
    while o + 16 <= end {
        entries += 1;
        if entries > MAX_DYNAMIC_ENTRIES { return Err(ElfError::Einval); }
        let tag = i64::from_le_bytes(file[o..o+8].try_into().unwrap());
        let val = u64::from_le_bytes(file[o+8..o+16].try_into().unwrap());
        match tag {
            DT_NULL          => { terminated = true; break; },
            DT_NEEDED        => {
                if info.needed.len() == MAX_NEEDED_LIBRARIES { return Err(ElfError::Einval); }
                info.needed.push(val);
            },
            DT_STRTAB        => info.strtab_addr = Some(val),
            DT_STRSZ         => info.strtab_size = Some(val),
            DT_SYMTAB        => info.symtab_addr = Some(val),
            DT_SYMENT        => info.syment      = Some(val),
            DT_HASH          => info.hash_addr   = Some(val),
            DT_GNU_HASH      => info.gnu_hash_addr = Some(val),
            DT_RELA          => info.rela_addr   = Some(val),
            DT_RELASZ        => info.rela_size   = Some(val),
            DT_RELAENT       => info.rela_ent    = Some(val),
            DT_JMPREL        => info.jmprel_addr = Some(val),
            DT_PLTRELSZ      => info.pltrel_size = Some(val),
            DT_PLTREL        => info.pltrel_kind = Some(val),
            DT_INIT          => info.init_addr   = Some(val),
            DT_FINI          => info.fini_addr   = Some(val),
            DT_INIT_ARRAY    => info.init_array  = Some(val),
            DT_INIT_ARRAYSZ  => info.init_array_sz = Some(val),
            DT_FINI_ARRAY    => info.fini_array  = Some(val),
            DT_FINI_ARRAYSZ  => info.fini_array_sz = Some(val),
            DT_SONAME        => info.soname_off  = Some(val),
            DT_FLAGS         => info.flags       = Some(val),
            DT_RUNPATH       => info.runpath_off = Some(val),
            DT_RPATH         => info.rpath_off   = Some(val),
            DT_RELR          => info.relr_addr   = Some(val),
            DT_RELRSZ        => info.relr_size   = Some(val),
            DT_RELRENT       => info.relr_ent    = Some(val),
            _ => {}
        }
        o += 16;
    }
    if !terminated { return Err(ElfError::Einval); }
    Ok(info)
}

/// Read a NUL-terminated string out of the strtab at `off`.
/// Caller has already located the strtab bytes.
/// # C: O(strlen)
pub fn read_strtab(strtab: &[u8], off: u64) -> Result<String, ElfError> {
    let off = off as usize;
    if off >= strtab.len() { return Err(ElfError::Einval); }
    let s = &strtab[off..];
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    core::str::from_utf8(&s[..end])
        .map(|s| s.into())
        .map_err(|_| ElfError::Einval)
}

/// Read one required NUL-terminated dynamic-string entry without changing
/// its byte representation. Library names are ABI bytes, not Rust text.
/// # C: O(strlen)
pub fn read_strtab_bytes(strtab: &[u8], off: u64) -> Result<Vec<u8>, ElfError> {
    let off: usize = off.try_into().map_err(|_| ElfError::Einval)?;
    let s = strtab.get(off..).ok_or(ElfError::Einval)?;
    let end = s.iter().position(|&b| b == 0).ok_or(ElfError::Einval)?;
    if end == 0 { return Err(ElfError::Einval); }
    Ok(s[..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_dyn(out: &mut Vec<u8>, tag: i64, val: u64) {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&val.to_le_bytes());
    }

    #[test]
    fn parse_canonical_dynamic_section() {
        let mut buf = std::vec::Vec::new();
        write_dyn(&mut buf, DT_NEEDED, 1);
        write_dyn(&mut buf, DT_NEEDED, 9);
        write_dyn(&mut buf, DT_STRTAB, 0x1000);
        write_dyn(&mut buf, DT_STRSZ,  0x100);
        write_dyn(&mut buf, DT_SYMTAB, 0x2000);
        write_dyn(&mut buf, DT_SYMENT, 24);
        write_dyn(&mut buf, DT_RELA,   0x3000);
        write_dyn(&mut buf, DT_RELASZ, 48);
        write_dyn(&mut buf, DT_RELAENT, 24);
        write_dyn(&mut buf, DT_FLAGS,  0);
        write_dyn(&mut buf, DT_NULL,   0);
        let info = parse_dynamic(&buf, 0, buf.len()).unwrap();
        assert_eq!(info.needed.len(), 2);
        assert_eq!(info.strtab_addr, Some(0x1000));
        assert_eq!(info.symtab_addr, Some(0x2000));
        assert_eq!(info.rela_size, Some(48));
    }

    #[test]
    fn empty_dynamic() {
        let buf = std::vec![0u8; 16];  // single DT_NULL terminator
        let info = parse_dynamic(&buf, 0, 16).unwrap();
        assert!(info.needed.is_empty());
        assert!(info.strtab_addr.is_none());
    }

    #[test]
    fn read_strtab_at_offset() {
        let strtab = b"\0libc.so.6\0libpthread.so.0\0";
        assert_eq!(read_strtab(strtab, 1).unwrap(), "libc.so.6");
        assert_eq!(read_strtab(strtab, 11).unwrap(), "libpthread.so.0");
    }

    #[test]
    fn read_strtab_oob_errors() {
        let strtab = b"\0lib\0";
        assert!(read_strtab(strtab, 100).is_err());
    }

    #[test]
    fn dynamic_table_requires_terminator_and_exact_entries() {
        let mut buf = std::vec::Vec::new();
        write_dyn(&mut buf, DT_NEEDED, 1);
        assert!(parse_dynamic(&buf, 0, buf.len()).is_err());
        buf.extend_from_slice(&[0; 8]);
        assert!(parse_dynamic(&buf, 0, buf.len()).is_err());
        let mut valid = std::vec::Vec::new();
        write_dyn(&mut valid, DT_NEEDED, 1);
        write_dyn(&mut valid, DT_NULL, 0);
        assert!(parse_dynamic(&valid, 0, valid.len()).is_ok());
    }

    #[test]
    fn required_dynamic_string_rejects_missing_nul_and_empty_name() {
        assert!(read_strtab_bytes(b"\0libc.so.6", 1).is_err());
        assert!(read_strtab_bytes(b"\0libc.so.6\0", 0).is_err());
        assert_eq!(read_strtab_bytes(b"\0libc.so.6\0", 1).unwrap(), b"libc.so.6");
    }
}
