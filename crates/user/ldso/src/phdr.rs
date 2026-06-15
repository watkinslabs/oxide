// In-memory program-header walking (docs/31§4). The kernel maps the app and
// passes its phdrs via auxv AT_PHDR; the rtld walks them to find PT_DYNAMIC
// (for relocation) and PT_PHDR (to recover the app's load bias). Elf64_Phdr
// is 56 bytes. Pure parsing over a borrowed phdr slice; hosted-tested.

pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_PHDR: u32 = 6;
pub const PHDR_SIZE: usize = 56;

#[inline]
fn rd_u32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap()))
}
#[inline]
fn rd_u64(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap()))
}

/// p_vaddr of the first phdr of `ptype` in a packed phdr array, or None.
/// # C: first phdr[ptype].p_vaddr
pub fn find_vaddr(phdrs: &[u8], phnum: usize, ptype: u32) -> Option<u64> {
    for i in 0..phnum {
        let o = i * PHDR_SIZE;
        if rd_u32(phdrs, o)? == ptype {
            return rd_u64(phdrs, o + 16); // p_vaddr @16
        }
    }
    None
}

/// Page-aligned [min,max) of all PT_LOAD p_vaddr..+p_memsz (link-relative).
/// # C: span over PT_LOAD vaddr ranges
pub fn load_vaddr_span(phdrs: &[u8], phnum: usize) -> Option<(u64, u64)> {
    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut seen = false;
    for i in 0..phnum {
        let o = i * PHDR_SIZE;
        if rd_u32(phdrs, o)? == PT_LOAD {
            let v = rd_u64(phdrs, o + 16)?;
            let m = rd_u64(phdrs, o + 40)?; // p_memsz @40
            if v < min { min = v; }
            if v + m > max { max = v + m; }
            seen = true;
        }
    }
    if seen { Some((min, max)) } else { None }
}

/// App load bias from AT_PHDR: the kernel-reported phdr address minus the
/// link-time vaddr of the PT_PHDR segment. (For a PIE both differ by the
/// load bias; for a non-PIE PT_PHDR.p_vaddr == AT_PHDR so bias is 0.)
///
/// # C: at_phdr - phdr[PT_PHDR].p_vaddr
pub fn load_bias(phdrs: &[u8], phnum: usize, at_phdr: u64) -> Option<u64> {
    let pv = find_vaddr(phdrs, phnum, PT_PHDR)?;
    Some(at_phdr.wrapping_sub(pv))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn phdr(ptype: u32, vaddr: u64, memsz: u64) -> Vec<u8> {
        let mut e = std::vec![0u8; PHDR_SIZE];
        e[0..4].copy_from_slice(&ptype.to_le_bytes());
        e[16..24].copy_from_slice(&vaddr.to_le_bytes());
        e[40..48].copy_from_slice(&memsz.to_le_bytes());
        e
    }

    #[test]
    fn finds_types_and_bias() {
        let mut t = Vec::new();
        t.extend(phdr(PT_PHDR, 0x40, 0x1c0));
        t.extend(phdr(PT_LOAD, 0, 0x1000));
        t.extend(phdr(PT_DYNAMIC, 0x2dc0, 0x200));
        t.extend(phdr(PT_LOAD, 0x2000, 0x500));
        let phnum = 4;
        assert_eq!(find_vaddr(&t, phnum, PT_DYNAMIC), Some(0x2dc0));
        assert_eq!(find_vaddr(&t, phnum, PT_INTERP), None);
        assert_eq!(load_vaddr_span(&t, phnum), Some((0, 0x2500)));
        // kernel mapped phdrs at runtime 0x5555_0040 → bias 0x5555_0000
        assert_eq!(load_bias(&t, phnum, 0x5555_0040), Some(0x5555_0000));
    }

    #[test]
    fn non_pie_zero_bias() {
        let mut t = Vec::new();
        t.extend(phdr(PT_PHDR, 0x40_0040, 0));
        t.extend(phdr(PT_LOAD, 0x40_0000, 0x1000));
        assert_eq!(load_bias(&t, 2, 0x40_0040), Some(0));
    }
}
