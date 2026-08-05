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
    file: Option<&Arc<dyn FileBacking>>,
) -> Result<LoadedImage, LoadError> {
    let parsed = elf::parse(blob, ARCH_MACHINE)?;
    if !matches!(parsed.elf_type, ElfType::Dyn | ElfType::Exec) {
        return Err(LoadError::Enoexec);
    }
    let bias = place::resolve(placement, parsed.elf_type, &parsed.loads, as_)?;
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
