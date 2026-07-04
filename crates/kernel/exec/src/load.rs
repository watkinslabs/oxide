use alloc::sync::Arc;

use elf::{self, ElfType, PFlags};
use hal::UserVirtAddr;
use vmm::{AddressSpace, VmaBacking, VmaFlags, VmaProt};

use crate::{ARCH_MACHINE, LoadError, LoadStaging, LoadedImage, PAGE, PIE_LOAD_BIAS};

pub(crate) fn place_image(
    blob: &[u8],
    as_: &AddressSpace,
    bias_override: Option<u64>,
    apply_self_relocs: bool,
) -> Result<LoadedImage, LoadError> {
    let parsed = elf::parse(blob, ARCH_MACHINE)?;

    let bias: u64 = match (bias_override, parsed.elf_type) {
        (Some(b), ElfType::Dyn) => b,
        (Some(_), _) => return Err(LoadError::Enoexec),
        (None, ElfType::Dyn) => PIE_LOAD_BIAS,
        (None, ElfType::Exec) => 0,
        _ => return Err(LoadError::Enoexec),
    };

    let mut max_end: u64 = 0;
    let mut staging: alloc::vec::Vec<LoadStaging> = alloc::vec::Vec::with_capacity(parsed.loads.len());
    for seg in &parsed.loads {
        let vaddr = seg.vaddr.checked_add(bias).ok_or(LoadError::Einval)?;
        let vstart = align_down(vaddr, PAGE);
        let vend = align_up(vaddr.checked_add(seg.mem_sz).ok_or(LoadError::Einval)?, PAGE);
        if vend <= vstart {
            return Err(LoadError::Einval);
        }

        let file_off = seg.file_off as usize;
        let file_sz = seg.file_sz as usize;
        let raw_data = blob
            .get(file_off..file_off.checked_add(file_sz).ok_or(LoadError::Einval)?)
            .ok_or(LoadError::Einval)?;
        let head_pad = (vaddr - vstart) as usize;
        let buf_len = (vend - vstart) as usize;
        let copy_n = buf_len.min(head_pad + raw_data.len());
        let mut padded = alloc::vec![0u8; buf_len];
        padded[head_pad..copy_n].copy_from_slice(&raw_data[..copy_n - head_pad]);

        let mut prot = VmaProt::empty();
        if seg.flags.contains(PFlags::R) {
            prot |= VmaProt::READ;
        }
        if seg.flags.contains(PFlags::W) {
            prot |= VmaProt::WRITE;
        }
        if seg.flags.contains(PFlags::X) {
            prot |= VmaProt::EXEC;
        }

        if vend > max_end {
            max_end = vend;
        }
        staging.push(LoadStaging { vstart, vend, prot, padded, head_pad });
    }

    if apply_self_relocs && matches!(parsed.elf_type, ElfType::Dyn) && bias != 0 {
        apply_relative_relocs_into(blob, &parsed, bias, &mut staging)?;
    }

    for s in staging {
        let data: Arc<[u8]> = as_.stash_bytes(s.padded.into_boxed_slice());
        let hint = UserVirtAddr::new(s.vstart).ok_or(LoadError::Einval)?;
        let _ = as_
            .mmap(
                Some(hint),
                (s.vend - s.vstart) as usize,
                s.prot,
                VmaFlags::PRIVATE,
                VmaBacking::KernelBytes { data, off: 0 },
                true,
            )
            .map_err(|_| LoadError::Enomem)?;
        let _ = s.head_pad;
    }

    let entry = UserVirtAddr::new(parsed.entry.checked_add(bias).ok_or(LoadError::Einval)?)
        .ok_or(LoadError::Einval)?;
    let brk = UserVirtAddr::new(max_end).ok_or(LoadError::Einval)?;

    let phoff = parsed.phoff;
    let mut phdr_va: u64 = 0;
    for seg in &parsed.loads {
        if phoff >= seg.file_off && phoff < seg.file_off + seg.file_sz {
            phdr_va = seg.vaddr + (phoff - seg.file_off) + bias;
            break;
        }
    }

    if bias_override.is_none() {
        const HEAP_RESERVE: u64 = 64 * 1024 * 1024;
        let heap_start = max_end;
        let heap_end = heap_start.checked_add(HEAP_RESERVE).ok_or(LoadError::Einval)?;
        let heap_hint = UserVirtAddr::new(heap_start).ok_or(LoadError::Einval)?;
        if heap_end <= heap_start {
            return Err(LoadError::Einval);
        }
        let _ = as_
            .mmap(
                Some(heap_hint),
                (heap_end - heap_start) as usize,
                VmaProt::READ | VmaProt::WRITE,
                VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
                VmaBacking::Anonymous,
                true,
            )
            .map_err(|_| LoadError::Enomem)?;
        as_.set_brk_window(heap_start, heap_end);
    }

    Ok(LoadedImage {
        entry,
        brk,
        phdr_va,
        phentsize: parsed.phentsize,
        phnum: parsed.phnum,
        interp_base: 0,
        interp_entry: 0,
    })
}

#[inline]
fn align_down(v: u64, a: u64) -> u64 { v & !(a - 1) }

#[inline]
fn align_up(v: u64, a: u64) -> u64 { (v + (a - 1)) & !(a - 1) }

fn apply_relative_relocs_into(
    blob: &[u8],
    parsed: &elf::ParsedElf,
    bias: u64,
    staging: &mut [LoadStaging],
) -> Result<(), LoadError> {
    let mut dyn_off: usize = 0;
    let mut dyn_sz: usize = 0;
    for i in 0..(parsed.phnum as usize) {
        let base = parsed.phoff as usize + i * (parsed.phentsize as usize);
        let p_type = u32::from_le_bytes(blob[base..base + 4].try_into().unwrap_or([0; 4]));
        if p_type == 2 {
            dyn_off =
                u64::from_le_bytes(blob[base + 8..base + 16].try_into().unwrap_or([0; 8])) as usize;
            dyn_sz =
                u64::from_le_bytes(blob[base + 32..base + 40].try_into().unwrap_or([0; 8])) as usize;
            break;
        }
    }
    if dyn_sz == 0 {
        return Ok(());
    }
    if dyn_off + dyn_sz > blob.len() {
        return Err(LoadError::Einval);
    }
    let mut rela_off: u64 = 0;
    let mut rela_sz: u64 = 0;
    let mut rela_ent: u64 = 24;
    let mut p = dyn_off;
    while p + 16 <= dyn_off + dyn_sz {
        let tag = i64::from_le_bytes(blob[p..p + 8].try_into().unwrap_or([0; 8]));
        let val = u64::from_le_bytes(blob[p + 8..p + 16].try_into().unwrap_or([0; 8]));
        match tag {
            0 => break,
            7 => rela_off = val,
            8 => rela_sz = val,
            9 => rela_ent = val,
            _ => {}
        }
        p += 16;
    }
    if rela_sz == 0 {
        return Ok(());
    }
    let mut file_rela: u64 = 0;
    for seg in &parsed.loads {
        if rela_off >= seg.vaddr && rela_off < seg.vaddr + seg.file_sz {
            file_rela = seg.file_off + (rela_off - seg.vaddr);
            break;
        }
    }
    if file_rela == 0 {
        return Ok(());
    }
    let n = (rela_sz / rela_ent) as usize;
    for i in 0..n {
        let r = (file_rela as usize) + i * (rela_ent as usize);
        if r + 24 > blob.len() {
            return Err(LoadError::Einval);
        }
        let r_off = u64::from_le_bytes(blob[r..r + 8].try_into().unwrap_or([0; 8]));
        let r_info = u64::from_le_bytes(blob[r + 8..r + 16].try_into().unwrap_or([0; 8]));
        let r_add = i64::from_le_bytes(blob[r + 16..r + 24].try_into().unwrap_or([0; 8]));
        let r_type = (r_info & 0xffff_ffff) as u32;
        if r_type != 8 && r_type != 0x403 {
            continue;
        }
        let dst_va = bias.checked_add(r_off).ok_or(LoadError::Einval)?;
        let val = (bias as i64).wrapping_add(r_add) as u64;
        if dst_va == 0 {
            return Err(LoadError::Einval);
        }
        let mut placed = false;
        for s in staging.iter_mut() {
            if dst_va >= s.vstart && dst_va + 8 <= s.vend {
                let off = (dst_va - s.vstart) as usize;
                if off + 8 > s.padded.len() {
                    return Err(LoadError::Einval);
                }
                s.padded[off..off + 8].copy_from_slice(&val.to_le_bytes());
                placed = true;
                break;
            }
        }
        let _ = placed;
    }
    Ok(())
}
