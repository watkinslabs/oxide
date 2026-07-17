// _DYNAMIC array parsing (docs/59§5). The dynamic section is an array of
// Elf64_Dyn { d_tag, d_val } terminated by DT_NULL. d_ptr-class values hold
// link-time virtual addresses; the loader adds the load bias to reach the
// runtime address. Pure logic — no memory of the loaded image is touched.

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Dyn {
    pub d_tag: i64,
    pub d_val: u64,
}

pub const DT_NULL: i64 = 0;
pub const DT_NEEDED: i64 = 1;
pub const DT_PLTRELSZ: i64 = 2;
pub const DT_PLTGOT: i64 = 3;
pub const DT_HASH: i64 = 4;
pub const DT_STRTAB: i64 = 5;
pub const DT_SYMTAB: i64 = 6;
pub const DT_RELA: i64 = 7;
pub const DT_RELASZ: i64 = 8;
pub const DT_RELAENT: i64 = 9;
pub const DT_STRSZ: i64 = 10;
pub const DT_SYMENT: i64 = 11;
pub const DT_INIT: i64 = 12;
pub const DT_FINI: i64 = 13;
pub const DT_SONAME: i64 = 14;
pub const DT_RPATH: i64 = 15;
pub const DT_SYMBOLIC: i64 = 16;
pub const DT_PLTREL: i64 = 20;
pub const DT_JMPREL: i64 = 23;
pub const DT_BIND_NOW: i64 = 24;
pub const DT_INIT_ARRAY: i64 = 25;
pub const DT_FINI_ARRAY: i64 = 26;
pub const DT_INIT_ARRAYSZ: i64 = 27;
pub const DT_FINI_ARRAYSZ: i64 = 28;
pub const DT_RUNPATH: i64 = 29;
pub const DT_FLAGS: i64 = 30;
pub const DT_GNU_HASH: i64 = 0x6fff_fef5;
pub const DT_VERSYM: i64 = 0x6fff_fff0;
pub const DT_VERDEF: i64 = 0x6fff_fffc;
pub const DT_VERDEFNUM: i64 = 0x6fff_fffd;
pub const DT_RELACOUNT: i64 = 0x6fff_fff9;
pub const DT_VERNEED: i64 = 0x6fff_fffe;
pub const DT_VERNEEDNUM: i64 = 0x6fff_ffff;

pub const DF_BIND_NOW: u64 = 0x8;

/// Bootstrap-relevant tags extracted from a `_DYNAMIC` array. d_ptr-class
/// fields are stored raw (link-time vaddr); add the load bias to use them.
#[derive(Default, Clone)]
pub struct DynInfo {
    pub rela: Option<u64>,
    pub relasz: u64,
    pub relaent: u64,
    pub relacount: u64,
    pub jmprel: Option<u64>,
    pub pltrelsz: u64,
    pub symtab: Option<u64>,
    pub syment: u64,
    pub strtab: Option<u64>,
    pub strsz: u64,
    pub gnu_hash: Option<u64>,
    pub hash: Option<u64>,
    pub pltgot: Option<u64>,
    pub versym: Option<u64>,
    pub verneed: Option<u64>,
    pub verneednum: u64,
    pub verdef: Option<u64>,
    /// DT_NEEDED soname strtab offsets, in order.
    pub needed: alloc::vec::Vec<u64>,
    pub rpath: Option<u64>,
    pub runpath: Option<u64>,
    pub init: Option<u64>,
    pub init_array: Option<u64>,
    pub init_arraysz: u64,
    pub fini_array: Option<u64>,
    pub fini_arraysz: u64,
    pub soname: Option<u64>,
    pub flags: u64,
    pub bind_now: bool,
}

/// # C: parse a `_DYNAMIC` slice into the bootstrap tag set
pub fn parse(dynv: &[Dyn]) -> DynInfo {
    let mut i = DynInfo { relaent: 24, syment: 24, ..DynInfo::default() };
    for d in dynv {
        match d.d_tag {
            DT_NULL => break,
            DT_RELA => i.rela = Some(d.d_val),
            DT_RELASZ => i.relasz = d.d_val,
            DT_RELAENT => i.relaent = d.d_val,
            DT_RELACOUNT => i.relacount = d.d_val,
            DT_JMPREL => i.jmprel = Some(d.d_val),
            DT_PLTRELSZ => i.pltrelsz = d.d_val,
            DT_SYMTAB => i.symtab = Some(d.d_val),
            DT_SYMENT => i.syment = d.d_val,
            DT_STRTAB => i.strtab = Some(d.d_val),
            DT_STRSZ => i.strsz = d.d_val,
            DT_GNU_HASH => i.gnu_hash = Some(d.d_val),
            DT_HASH => i.hash = Some(d.d_val),
            DT_PLTGOT => i.pltgot = Some(d.d_val),
            DT_VERSYM => i.versym = Some(d.d_val),
            DT_VERNEED => i.verneed = Some(d.d_val),
            DT_VERNEEDNUM => i.verneednum = d.d_val,
            DT_VERDEF => i.verdef = Some(d.d_val),
            DT_NEEDED => i.needed.push(d.d_val),
            DT_RPATH => i.rpath = Some(d.d_val),
            DT_RUNPATH => i.runpath = Some(d.d_val),
            DT_INIT => i.init = Some(d.d_val),
            DT_INIT_ARRAY => i.init_array = Some(d.d_val),
            DT_INIT_ARRAYSZ => i.init_arraysz = d.d_val,
            DT_FINI_ARRAY => i.fini_array = Some(d.d_val),
            DT_FINI_ARRAYSZ => i.fini_arraysz = d.d_val,
            DT_SONAME => i.soname = Some(d.d_val),
            DT_FLAGS => {
                i.flags = d.d_val;
                if d.d_val & DF_BIND_NOW != 0 { i.bind_now = true; }
            }
            DT_BIND_NOW => i.bind_now = true,
            _ => {}
        }
    }
    i
}

/// Parse a `_DYNAMIC` array reached by raw pointer (walks to DT_NULL).
/// # C: parse(dynv[0..=DT_NULL])
pub unsafe fn parse_ptr(dynv: *const Dyn) -> DynInfo {
    // SAFETY: dynv is a DT_NULL-terminated _DYNAMIC array in a mapped object;
    // we read entries sequentially to the terminator, all in-bounds.
    unsafe {
        let mut n = 0usize;
        while (*dynv.add(n)).d_tag != DT_NULL { n += 1; }
        parse(core::slice::from_raw_parts(dynv, n + 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_core_tags() {
        let dynv = [
            Dyn { d_tag: DT_RELA, d_val: 0x1000 },
            Dyn { d_tag: DT_RELASZ, d_val: 240 },
            Dyn { d_tag: DT_RELAENT, d_val: 24 },
            Dyn { d_tag: DT_RELACOUNT, d_val: 10 },
            Dyn { d_tag: DT_SYMTAB, d_val: 0x200 },
            Dyn { d_tag: DT_STRTAB, d_val: 0x400 },
            Dyn { d_tag: DT_RPATH, d_val: 0x28 },
            Dyn { d_tag: DT_RUNPATH, d_val: 0x40 },
            Dyn { d_tag: DT_BIND_NOW, d_val: 0 },
            Dyn { d_tag: DT_NULL, d_val: 0 },
            Dyn { d_tag: DT_RELA, d_val: 0xdead }, // past DT_NULL: ignored
        ];
        let i = parse(&dynv);
        assert_eq!(i.rela, Some(0x1000));
        assert_eq!(i.relasz, 240);
        assert_eq!(i.relacount, 10);
        assert_eq!(i.symtab, Some(0x200));
        assert_eq!(i.strtab, Some(0x400));
        assert_eq!(i.rpath, Some(0x28));
        assert_eq!(i.runpath, Some(0x40));
        assert!(i.bind_now);
        assert_eq!(i.relaent, 24);
    }
    #[test]
    fn flags_bind_now() {
        let dynv = [Dyn { d_tag: DT_FLAGS, d_val: DF_BIND_NOW }, Dyn { d_tag: DT_NULL, d_val: 0 }];
        assert!(parse(&dynv).bind_now);
    }
}
