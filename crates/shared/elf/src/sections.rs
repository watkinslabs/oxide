//! ELF64 section-table views used by loaded-image metadata owners.

use crate::parser::{ElfError, ElfType, KResult, LoadSegment, EI_MAG, ELFCLASS64, ELFDATA2LSB, EV_CURRENT};

pub const SHT_PROGBITS: u32 = 1;
pub const SHT_NOBITS: u32 = 8;
pub const SHF_ALLOC: u64 = 0x2;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SectionView<'a> {
    pub name: &'a str,
    pub sh_type: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub bytes: &'a [u8],
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PublishedEhFrame<'a> {
    pub image_start: u64,
    pub image_end: u64,
    pub address: u64,
    pub bytes: &'a [u8],
}

/// Find one named ELF section and return its file-backed bytes.
///
/// Section names are metadata only; callers must use `addr` plus the image
/// load bias when publishing an address into a running process.  `SHT_NOBITS`
/// sections are represented with an empty byte view because no file bytes
/// exist for them.
pub fn find<'a>(file: &'a [u8], name: &str) -> KResult<Option<SectionView<'a>>> {
    if file.len() < 64 || file.get(..4) != Some(&EI_MAG) || file[4] != ELFCLASS64
        || file[5] != ELFDATA2LSB || file[6] != EV_CURRENT {
        return Err(ElfError::Enoexec);
    }
    let ty = u16_at(file, 16)?;
    if !matches!(ElfType::from_u16(ty), Some(ElfType::Exec | ElfType::Dyn)) {
        return Err(ElfError::Enoexec);
    }
    let shoff = u64_at(file, 0x28)? as usize;
    let shentsize = u16_at(file, 0x3a)? as usize;
    let shnum = u16_at(file, 0x3c)? as usize;
    let shstrndx = u16_at(file, 0x3e)? as usize;
    if shentsize != 64 || shnum == 0 || shstrndx >= shnum {
        return Err(ElfError::Einval);
    }
    let table_end = shoff.checked_add(shentsize.checked_mul(shnum).ok_or(ElfError::Einval)?)
        .ok_or(ElfError::Einval)?;
    if table_end > file.len() { return Err(ElfError::Einval); }
    let names = section_bytes(file, shoff, shentsize, shstrndx)?;
    for index in 0..shnum {
        let off = shoff + index * shentsize;
        let name_off = u32_at(file, off)? as usize;
        let section_name = cstr(names, name_off)?;
        if section_name != name { continue; }
        let sh_type = u32_at(file, off + 4)?;
        let flags = u64_at(file, off + 8)?;
        let addr = u64_at(file, off + 16)?;
        let data_off = u64_at(file, off + 24)?;
        let size = u64_at(file, off + 32)?;
        let bytes = if sh_type == SHT_NOBITS {
            &[]
        } else {
            let end = data_off.checked_add(size).ok_or(ElfError::Einval)?;
            file.get(data_off as usize..end as usize).ok_or(ElfError::Einval)?
        };
        return Ok(Some(SectionView { name: section_name, sh_type, flags, addr,
            offset: data_off, size, bytes }));
    }
    Ok(None)
}

pub fn eh_frame<'a>(file: &'a [u8]) -> KResult<Option<SectionView<'a>>> {
    let section = find(file, ".eh_frame")?;
    if let Some(view) = section {
        if view.sh_type != SHT_PROGBITS || view.flags & SHF_ALLOC == 0 {
            return Err(ElfError::Einval);
        }
    }
    Ok(section)
}

/// Publish `.eh_frame` only when its file and virtual ranges belong to one
/// file-backed PT_LOAD.  `load_base` is the bias already selected by the ELF
/// placement owner; this function does not choose or map an address.
pub fn publish_eh_frame<'a>(file: &'a [u8], loads: &[LoadSegment], load_base: u64)
    -> KResult<Option<PublishedEhFrame<'a>>>
{
    let Some(section) = eh_frame(file)? else { return Ok(None); };
    let section_end = section.addr.checked_add(section.size).ok_or(ElfError::Einval)?;
    let mut image_start = u64::MAX;
    let mut image_end = 0;
    for load in loads {
        let load_vend = load.vaddr.checked_add(load.mem_sz).ok_or(ElfError::Einval)?;
        let load_fend = load.file_off.checked_add(load.file_sz).ok_or(ElfError::Einval)?;
        image_start = image_start.min(load.vaddr);
        image_end = image_end.max(load_vend);
        let in_virtual = section.addr >= load.vaddr && section_end <= load_vend;
        let in_file = section.offset >= load.file_off && section.offset.checked_add(section.size)
            .ok_or(ElfError::Einval)? <= load_fend;
        if in_virtual && in_file {
            let address = load_base.checked_add(section.addr).ok_or(ElfError::Einval)?;
            return Ok(Some(PublishedEhFrame { image_start: load_base.checked_add(image_start)
                .ok_or(ElfError::Einval)?, image_end: load_base.checked_add(image_end)
                .ok_or(ElfError::Einval)?, address, bytes: section.bytes }));
        }
    }
    Err(ElfError::Einval)
}

fn section_bytes<'a>(file: &'a [u8], shoff: usize, entsize: usize, index: usize)
    -> KResult<&'a [u8]>
{
    let off = shoff + index * entsize;
    let data_off = u64_at(file, off + 24)? as usize;
    let size = u64_at(file, off + 32)? as usize;
    file.get(data_off..data_off.checked_add(size).ok_or(ElfError::Einval)?)
        .ok_or(ElfError::Einval)
}

fn cstr(buf: &[u8], off: usize) -> KResult<&str> {
    let tail = buf.get(off..).ok_or(ElfError::Einval)?;
    let end = tail.iter().position(|&b| b == 0).ok_or(ElfError::Einval)?;
    core::str::from_utf8(&tail[..end]).map_err(|_| ElfError::Einval)
}

fn u16_at(buf: &[u8], off: usize) -> KResult<u16> {
    let b = buf.get(off..off + 2).ok_or(ElfError::Einval)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}
fn u32_at(buf: &[u8], off: usize) -> KResult<u32> {
    let b = buf.get(off..off + 4).ok_or(ElfError::Einval)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn u64_at(buf: &[u8], off: usize) -> KResult<u64> {
    let b = buf.get(off..off + 8).ok_or(ElfError::Einval)?;
    Ok(u64::from_le_bytes(b.try_into().map_err(|_| ElfError::Einval)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn fixture() -> Vec<u8> {
        let mut f = vec![0u8; 0x300];
        f[0..4].copy_from_slice(&EI_MAG); f[4] = ELFCLASS64; f[5] = ELFDATA2LSB; f[6] = EV_CURRENT;
        f[16..18].copy_from_slice(&(ElfType::Dyn as u16).to_le_bytes());
        f[0x28..0x30].copy_from_slice(&0x180u64.to_le_bytes());
        f[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
        f[0x3c..0x3e].copy_from_slice(&4u16.to_le_bytes()); f[0x3e..0x40].copy_from_slice(&2u16.to_le_bytes());
        f[0x80..0x95].copy_from_slice(b"\0.shstrtab\0.eh_frame\0");
        let sh = 0x180;
        f[sh + 64 * 2 + 0..sh + 64 * 2 + 4].copy_from_slice(&1u32.to_le_bytes());
        f[sh + 64 * 2 + 4..sh + 64 * 2 + 8].copy_from_slice(&3u32.to_le_bytes());
        f[sh + 64 * 2 + 24..sh + 64 * 2 + 32].copy_from_slice(&0x80u64.to_le_bytes());
        f[sh + 64 * 2 + 32..sh + 64 * 2 + 40].copy_from_slice(&21u64.to_le_bytes());
        f[sh + 64 * 3 + 0..sh + 64 * 3 + 4].copy_from_slice(&11u32.to_le_bytes());
        f[sh + 64 * 3 + 4..sh + 64 * 3 + 8].copy_from_slice(&SHT_PROGBITS.to_le_bytes());
        f[sh + 64 * 3 + 8..sh + 64 * 3 + 16].copy_from_slice(&SHF_ALLOC.to_le_bytes());
        f[sh + 64 * 3 + 16..sh + 64 * 3 + 24].copy_from_slice(&0x4000u64.to_le_bytes());
        f[sh + 64 * 3 + 24..sh + 64 * 3 + 32].copy_from_slice(&0x120u64.to_le_bytes());
        f[sh + 64 * 3 + 32..sh + 64 * 3 + 40].copy_from_slice(&4u64.to_le_bytes());
        f[0x120..0x124].copy_from_slice(&[1, 2, 3, 4]); f
    }

    #[test]
    fn finds_allocated_eh_frame_bytes() {
        let file = fixture();
        let view = eh_frame(&file).unwrap().unwrap();
        assert_eq!(view.addr, 0x4000); assert_eq!(view.bytes, &[1, 2, 3, 4]);
    }

    #[test]
    fn rejects_section_bytes_outside_file() {
        let mut f = fixture(); f[0x180 + 64 * 3 + 24..0x180 + 64 * 3 + 32]
            .copy_from_slice(&0x400u64.to_le_bytes());
        assert_eq!(eh_frame(&f), Err(ElfError::Einval));
    }

    #[test]
    fn publishes_only_a_file_backed_loaded_range() {
        let file = fixture();
        let loads = [LoadSegment { flags: crate::parser::PFlags::R, file_off: 0x100,
            file_sz: 0x30, vaddr: 0x3ff0, mem_sz: 0x30, align: 0x10 }];
        let published = publish_eh_frame(&file, &loads, 0x1000).unwrap().unwrap();
        assert_eq!(published.address, 0x5000);
        assert_eq!(published.image_start, 0x4ff0);
        assert_eq!(published.image_end, 0x5020);
    }

    #[test]
    fn rejects_eh_frame_outside_loaded_file_range() {
        let file = fixture();
        let loads = [LoadSegment { flags: crate::parser::PFlags::R, file_off: 0x100,
            file_sz: 4, vaddr: 0x3ff0, mem_sz: 0x30, align: 0x10 }];
        assert_eq!(publish_eh_frame(&file, &loads, 0x1000), Err(ElfError::Einval));
    }
}
