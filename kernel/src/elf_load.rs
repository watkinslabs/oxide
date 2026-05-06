// ELF loader glue per docs/31§4.
//
// Drives `crates/elf::parse` against a `&'static [u8]` blob and
// registers each PT_LOAD as a MAP_FIXED VMA in the supplied
// `AddressSpace` with `VmaBacking::KernelBytes` (P2-17). Returns
// the entry-point VA the caller drops to user mode at.
//
// v1 scope (no VFS, no ld.so):
//  - blob is `&'static [u8]` baked into the kernel image; future
//    callers (execve via VFS) will pass a freshly-read inode page
//    instead.
//  - `ET_DYN` (PIE) is loaded at its declared `p_vaddr` — no
//    `load_bias` randomisation yet (`31§6` ASLR is v1.x).
//  - PT_INTERP / PT_TLS / PT_DYNAMIC are parsed but not acted on.
//  - Stack + auxv build is the smoke driver's responsibility for
//    now; the loader only places the executable image.

#![cfg(target_os = "oxide-kernel")]

use elf::{parse, ElfError, ElfType, EM_AARCH64, EM_X86_64, PFlags};
use hal::UserVirtAddr;
use vmm::{AddressSpace, VmaBacking, VmaFlags, VmaProt};

const PAGE: u64 = 4096;

/// The current-arch `e_machine` per `31§2` invariant 1.
#[cfg(target_arch = "x86_64")]
pub const ARCH_MACHINE: u16 = EM_X86_64;
#[cfg(target_arch = "aarch64")]
pub const ARCH_MACHINE: u16 = EM_AARCH64;

/// Loader error — surfaces ENOEXEC for invariant violations and
/// ENOMEM for mmap failures, matching docs/31§9.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LoadError {
    Enoexec,
    Einval,
    Enomem,
}

impl From<ElfError> for LoadError {
    fn from(e: ElfError) -> Self {
        match e {
            ElfError::Enoexec    => LoadError::Enoexec,
            ElfError::Einval     => LoadError::Einval,
            ElfError::Eopnotsupp => LoadError::Einval,
        }
    }
}

/// Result of a successful load — caller drops to user mode at
/// `entry` per docs/31§3 `LoadedExe`.
#[derive(Copy, Clone, Debug)]
pub struct LoadedImage {
    pub entry:      UserVirtAddr,
    pub brk:        UserVirtAddr,
    /// User VA where the program-header table lives. Computed by
    /// finding the PT_LOAD whose file range covers `e_phoff` and
    /// translating: `phdr_va = seg.vaddr + (phoff - seg.file_off)`.
    /// Auxv AT_PHDR per `31§4`. `0` if no PT_LOAD covers phoff.
    pub phdr_va:    u64,
    pub phentsize:  u16,
    pub phnum:      u16,
}

/// Default load bias for ET_DYN (PIE) images. Real Linux
/// randomises this per-exec; v1 uses a fixed value disjoint from
/// the hand-rolled-blob VAs (0x400000) and from the user stack
/// (0x501000). 0x10000000 keeps the user-half plenty of room.
/// docs/31§6 ASLR is v1.x — fixed bias for now.
const PIE_LOAD_BIAS: u64 = 0x1000_0000;

/// Load `blob` into `as_` per docs/31§4. Each PT_LOAD becomes a
/// MAP_FIXED VMA with `VmaBacking::KernelBytes` (P2-17) so demand-
/// paging copies the bytes from the kernel image on first touch.
///
/// PIE binaries (`ET_DYN`) get the fixed `PIE_LOAD_BIAS`; non-PIE
/// (`ET_EXEC`) load at their declared `p_vaddr`. All `entry`,
/// `phdr_va`, `brk`, and stack VAs are biased accordingly.
///
/// `blob` must outlive the address space (in practice always
/// 'static — it's `include_bytes!`'d from the kernel image).
///
/// # C: O(phdrs) parse + O(phdrs) mmap
pub fn load_static_blob(
    blob: &'static [u8],
    as_: &AddressSpace,
) -> Result<LoadedImage, LoadError> {
    let parsed = parse(blob, ARCH_MACHINE)?;

    let bias: u64 = match parsed.elf_type {
        ElfType::Dyn  => PIE_LOAD_BIAS,
        ElfType::Exec => 0,
        _             => return Err(LoadError::Enoexec),
    };

    let mut max_end: u64 = 0;
    for seg in &parsed.loads {
        let vaddr = seg.vaddr.checked_add(bias).ok_or(LoadError::Einval)?;
        // Round VMA range to page granule per `11§4` (mmap
        // alignment requirement).
        let vstart = align_down(vaddr, PAGE);
        let vend   = align_up(vaddr.checked_add(seg.mem_sz)
            .ok_or(LoadError::Einval)?, PAGE);
        if vend <= vstart { return Err(LoadError::Einval); }

        // Slice the file-backed extent for this segment.
        let file_off = seg.file_off as usize;
        let file_sz  = seg.file_sz  as usize;
        let raw_data = blob.get(file_off..file_off.checked_add(file_sz)
            .ok_or(LoadError::Einval)?).ok_or(LoadError::Einval)?;
        // P5-10: KernelBytes-backed VMAs assume the slice begins at
        // `vma.start` (the page-aligned vstart). When the segment's
        // p_vaddr isn't page-aligned (e.g., musl's RW segment at
        // 0x2f30 with vstart 0x2000), we need a head_pad of zeros
        // so a fault at vstart finds zeros and a fault at vaddr
        // finds the file bytes. Pre-P5-10 the loader passed the
        // raw slice and the fault path read past data.len() at
        // vaddr.., zero-filling our actual file content.
        let head_pad = (vaddr - vstart) as usize;
        let data: &'static [u8] = if head_pad == 0 {
            raw_data
        } else {
            let mut padded = alloc::vec![0u8; head_pad + raw_data.len()];
            padded[head_pad..].copy_from_slice(raw_data);
            alloc::boxed::Box::leak(padded.into_boxed_slice())
        };

        // Translate ELF p_flags to VmaProt (W^X already enforced
        // by the parser).
        let mut prot = VmaProt::empty();
        if seg.flags.contains(PFlags::R) { prot |= VmaProt::READ;  }
        if seg.flags.contains(PFlags::W) { prot |= VmaProt::WRITE; }
        if seg.flags.contains(PFlags::X) { prot |= VmaProt::EXEC;  }

        let hint = UserVirtAddr::new(vstart).ok_or(LoadError::Einval)?;
        let _ = as_.mmap(
            Some(hint),
            (vend - vstart) as usize,
            prot,
            VmaFlags::PRIVATE,
            VmaBacking::KernelBytes { data },
            true,            // MAP_FIXED — place exactly at p_vaddr+bias
        ).map_err(|_| LoadError::Enomem)?;

        if vend > max_end { max_end = vend; }
    }

    // Apply DT_RELA self-relocations for PIE static-pie images.
    // Linux's binfmt_elf does this for kernel-loaded static-pie;
    // musl's _start_c also applies them but only after walking
    // PT_DYNAMIC, so we apply pre-emptively (idempotent re-write
    // by musl is harmless).
    if matches!(parsed.elf_type, ElfType::Dyn) && bias != 0 {
        apply_relative_relocs(blob, &parsed, bias)?;
    }

    let entry = UserVirtAddr::new(parsed.entry.checked_add(bias)
        .ok_or(LoadError::Einval)?).ok_or(LoadError::Einval)?;
    let brk   = UserVirtAddr::new(max_end).ok_or(LoadError::Einval)?;

    // Compute phdr_va: the user VA the program header table lives
    // at after load. Find the PT_LOAD whose file range covers
    // `phoff` and translate file→virt.
    let phoff = parsed.phoff;
    let mut phdr_va: u64 = 0;
    for seg in &parsed.loads {
        if phoff >= seg.file_off && phoff < seg.file_off + seg.file_sz {
            phdr_va = seg.vaddr + (phoff - seg.file_off) + bias;
            break;
        }
    }

    // Register a heap region per docs/15§5 `brk(2)`: an Anonymous
    // VMA covering [max_end, max_end + HEAP_RESERVE) so `sys_brk`
    // can extend lazily via demand-paging. v1: 64 MiB heap.
    const HEAP_RESERVE: u64 = 64 * 1024 * 1024;
    let heap_start = max_end;
    let heap_end   = heap_start.checked_add(HEAP_RESERVE)
        .ok_or(LoadError::Einval)?;
    let heap_hint  = UserVirtAddr::new(heap_start).ok_or(LoadError::Einval)?;
    if heap_end <= heap_start {
        return Err(LoadError::Einval);
    }
    let _ = as_.mmap(
        Some(heap_hint),
        (heap_end - heap_start) as usize,
        VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
        VmaBacking::Anonymous,
        true,
    ).map_err(|_| LoadError::Enomem)?;
    as_.set_brk_window(heap_start, heap_end);

    Ok(LoadedImage {
        entry, brk,
        phdr_va, phentsize: parsed.phentsize, phnum: parsed.phnum,
    })
}

#[inline]
fn align_down(v: u64, a: u64) -> u64 { v & !(a - 1) }
#[inline]
fn align_up(v: u64, a: u64)   -> u64 { (v + (a - 1)) & !(a - 1) }

/// Walk the PT_DYNAMIC array to find DT_RELA + DT_RELASZ + DT_RELAENT,
/// then apply each `R_X86_64_RELATIVE` (type 8) entry: write
/// `(bias + r_addend)` to user VA `(bias + r_offset)`. For static-
/// PIE this turns init_array / fini_array / GOT entries from
/// file-time-zero-bias offsets into runtime-correct absolute VAs.
/// Kernel CPL=0 writes through the active CR3 (caller already
/// activated the new AS).
/// # SAFETY: caller activated the destination AS so user VAs route
/// through its PT; PT_LOAD covering the reloc offsets is R|W; CPL=0
/// writes through user mapping.
/// # C: O(N_relas)
fn apply_relative_relocs(
    blob: &'static [u8],
    parsed: &elf::ParsedElf,
    bias: u64,
) -> Result<(), LoadError> {
    // Find PT_DYNAMIC in the raw phdrs.
    let mut dyn_off: usize = 0;
    let mut dyn_sz:  usize = 0;
    for i in 0..(parsed.phnum as usize) {
        let base = parsed.phoff as usize + i * (parsed.phentsize as usize);
        let p_type = u32::from_le_bytes(blob[base..base+4].try_into().unwrap_or([0;4]));
        if p_type == 2 {  // PT_DYNAMIC
            dyn_off = u64::from_le_bytes(blob[base+8..base+16].try_into().unwrap_or([0;8])) as usize;
            dyn_sz  = u64::from_le_bytes(blob[base+32..base+40].try_into().unwrap_or([0;8])) as usize;
            break;
        }
    }
    if dyn_sz == 0 { return Ok(()); }
    if dyn_off + dyn_sz > blob.len() { return Err(LoadError::Einval); }

    // Walk Elf64_Dyn entries (16 B each: i64 d_tag + u64 d_val).
    // Pull DT_RELA (7), DT_RELASZ (8), DT_RELAENT (9).
    let mut rela_off: u64 = 0;
    let mut rela_sz:  u64 = 0;
    let mut rela_ent: u64 = 24;  // standard
    let mut p = dyn_off;
    while p + 16 <= dyn_off + dyn_sz {
        let tag = i64::from_le_bytes(blob[p..p+8].try_into().unwrap_or([0;8]));
        let val = u64::from_le_bytes(blob[p+8..p+16].try_into().unwrap_or([0;8]));
        match tag {
            0  => break,           // DT_NULL
            7  => rela_off = val,
            8  => rela_sz  = val,
            9  => rela_ent = val,
            _ => {}
        }
        p += 16;
    }
    if rela_sz == 0 { return Ok(()); }

    // RELA offset is a VA in the unbiased image. We need the FILE
    // offset to read the entries — find the PT_LOAD covering that
    // VA and compute file_off = seg.file_off + (rela_off - seg.vaddr).
    let mut file_rela: u64 = 0;
    for seg in &parsed.loads {
        if rela_off >= seg.vaddr && rela_off < seg.vaddr + seg.file_sz {
            file_rela = seg.file_off + (rela_off - seg.vaddr);
            break;
        }
    }
    if file_rela == 0 { return Ok(()); }
    let n = (rela_sz / rela_ent) as usize;
    for i in 0..n {
        let r = (file_rela as usize) + i * (rela_ent as usize);
        if r + 24 > blob.len() { return Err(LoadError::Einval); }
        let r_off  = u64::from_le_bytes(blob[r   ..r+ 8].try_into().unwrap_or([0;8]));
        let r_info = u64::from_le_bytes(blob[r+ 8..r+16].try_into().unwrap_or([0;8]));
        let r_add  = i64::from_le_bytes(blob[r+16..r+24].try_into().unwrap_or([0;8]));
        let r_type = (r_info & 0xffff_ffff) as u32;
        // R_X86_64_RELATIVE = 8; R_AARCH64_RELATIVE = 0x403.
        if r_type != 8 && r_type != 0x403 { continue; }
        let dst = bias.checked_add(r_off).ok_or(LoadError::Einval)?;
        let val = (bias as i64).wrapping_add(r_add) as u64;
        if dst == 0 { return Err(LoadError::Einval); }
        // SAFETY: dst is a user VA inside a PT_LOAD R|W mapping (ELF places init_array/fini_array/GOT in writable data); active CR3 routes there; CPL=0 writes through user mapping; user_fault_handler resolves any not-present user page.
        unsafe { core::ptr::write_volatile(dst as *mut u64, val); }
    }
    Ok(())
}
