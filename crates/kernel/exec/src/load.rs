use alloc::sync::Arc;

use elf::{self, ElfType, PFlags};
use hal::UserVirtAddr;
use vmm::{AddressSpace, FileBacking, VmaBacking, VmaFlags, VmaProt};

use crate::place::{self, Placement};
use crate::{ARCH_MACHINE, LoadError, LoadStaging, LoadedImage, PAGE};

struct ZeroTailBacking { inner: Arc<dyn FileBacking>, zero_from: u64 }
impl FileBacking for ZeroTailBacking {
    fn read_at(&self, off: u64, dst: &mut [u8]) -> Result<usize, vmm::FileBackingError> {
        if off >= self.zero_from { dst.fill(0); return Ok(dst.len()); }
        let n = (self.zero_from - off).min(dst.len() as u64) as usize;
        let got = self.inner.read_at(off, &mut dst[..n])?;
        if got < n { return Ok(got); }
        dst[n..].fill(0);
        Ok(dst.len())
    }
    fn size_hint(&self) -> u64 { self.inner.size_hint() }
    fn ino(&self) -> u64 { self.inner.ino() }
    fn i_nlink(&self) -> u32 { self.inner.i_nlink() }
    fn i_mode(&self) -> u16 { self.inner.i_mode() }
    fn map_path(&self) -> Option<&[u8]> { self.inner.map_path() }
    fn object_id(&self) -> u64 { self.inner.object_id() }
}

pub(crate) fn place_image(
    blob: &[u8],
    as_: &AddressSpace,
    placement: Placement,
    apply_self_relocs: bool,
    file: Option<&Arc<dyn FileBacking>>,
) -> Result<LoadedImage, LoadError> {
    let parsed = elf::parse(blob, ARCH_MACHINE)?;
    if !matches!(parsed.elf_type, ElfType::Dyn | ElfType::Exec) {
        return Err(LoadError::Enoexec);
    }
    let bias = place::resolve(placement, parsed.elf_type, &parsed.loads, as_)?;
    // Relocating the image before it runs means editing its bytes, which a
    // mapping of the unmodified file cannot express. That case keeps the
    // kernel-byte backing; see `crate::relocs_precede_file_backing`.
    let file = if crate::relocs_precede_file_backing(apply_self_relocs, parsed.elf_type, bias)
        { None } else { file };

    let mut max_end: u64 = 0;
    // Linux `mm->start_code`..`end_data`: first executable PT_LOAD is
    // code, first writable PT_LOAD is data. Recorded page-aligned.
    let (mut start_code, mut end_code): (u64, u64) = (0, 0);
    let (mut start_data, mut end_data): (u64, u64) = (0, 0);
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
        let sp = crate::layout::split(
            vstart, vend, vaddr, seg.file_off, seg.file_sz, seg.mem_sz, PAGE, file.is_some());
        // Only the part of the segment that is not a mapping of the file needs
        // a kernel-owned copy: an image mapped from its file to the last page
        // costs no bytes here at all.
        let tail_from = (sp.file_end - vstart) as usize;
        let mut padded = alloc::vec![0u8; buf_len - tail_from];
        let copy_lo = tail_from.max(head_pad);
        let copy_hi = buf_len.min(head_pad + raw_data.len());
        if copy_hi > copy_lo {
            padded[copy_lo - tail_from..copy_hi - tail_from]
                .copy_from_slice(&raw_data[copy_lo - head_pad..copy_hi - head_pad]);
        }

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
        if prot.contains(VmaProt::EXEC) && start_code == 0 {
            start_code = vstart; end_code = vend;
        }
        if prot.contains(VmaProt::WRITE) && start_data == 0 {
            start_data = vstart; end_data = vend;
        }
        staging.push(LoadStaging {
            vstart, vend, prot, padded, head_pad,
            file_end: sp.file_end, file_pgoff: sp.file_pgoff, file_zero_from: sp.file_zero_from,
        });
    }

    if apply_self_relocs && matches!(parsed.elf_type, ElfType::Dyn) && bias != 0 {
        apply_relative_relocs_into(blob, &parsed, bias, &mut staging)?;
    }

    for s in staging {
        // Linux `vm_file` on a PT_LOAD: the mapping names the file it came
        // from, so the segment classifies as file-backed everywhere a mapping
        // is classified by what stands behind it.
        if let (Some(b), true) = (file, s.file_end > s.vstart) {
            let backing: Arc<dyn FileBacking> = match s.file_zero_from {
                Some(zero_from) => Arc::new(ZeroTailBacking { inner: Arc::clone(b), zero_from }),
                None => Arc::clone(b),
            };
            let hint = UserVirtAddr::new(s.vstart).ok_or(LoadError::Einval)?;
            let _ = as_
                .mmap(
                    Some(hint),
                    (s.file_end - s.vstart) as usize,
                    s.prot,
                    VmaFlags::PRIVATE,
                    VmaBacking::File { backing, off: s.file_pgoff },
                    true,
                )
                .map_err(|_| LoadError::Enomem)?;
        }
        if s.vend > s.file_end {
            let data: Arc<[u8]> = as_.stash_bytes(s.padded.into_boxed_slice());
            let hint = UserVirtAddr::new(s.file_end).ok_or(LoadError::Einval)?;
            let _ = as_
                .mmap(
                    Some(hint),
                    (s.vend - s.file_end) as usize,
                    s.prot,
                    VmaFlags::PRIVATE,
                    VmaBacking::KernelBytes { data, off: 0 },
                    true,
                )
                .map_err(|_| LoadError::Enomem)?;
        }
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

    Ok(LoadedImage {
        entry,
        brk,
        load_base: bias,
        phdr_va,
        phentsize: parsed.phentsize,
        phnum: parsed.phnum,
        interp_base: 0,
        interp_entry: 0,
        start_code,
        end_code,
        start_data,
        end_data,
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
            // `padded` starts at `file_end`, not at the segment start: the
            // bytes below it are a mapping of the file and are not the
            // loader's to edit.
            if dst_va >= s.file_end && dst_va + 8 <= s.vend {
                let off = (dst_va - s.file_end) as usize;
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
