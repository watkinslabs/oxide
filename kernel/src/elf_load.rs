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

use elf::{parse, ElfError, ElfType, EM_X86_64, PFlags};
#[cfg(target_arch = "aarch64")]
use elf::EM_AARCH64;
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
/// `interp_entry` if non-zero (PT_INTERP path), otherwise at
/// `entry`. The auxv build (`exec_stack`) carries `interp_base`
/// in AT_BASE so the dynamic linker can locate itself.
#[derive(Copy, Clone, Debug)]
pub struct LoadedImage {
    /// The exec's own e_entry, biased by PIE_LOAD_BIAS for ET_DYN.
    /// Becomes auxv AT_ENTRY; the dynamic linker hands control here
    /// after loading DT_NEEDED. Static-PIE binaries jump here directly.
    pub entry:      UserVirtAddr,
    pub brk:        UserVirtAddr,
    /// User VA where the program-header table lives. Computed by
    /// finding the PT_LOAD whose file range covers `e_phoff` and
    /// translating: `phdr_va = seg.vaddr + (phoff - seg.file_off)`.
    /// Auxv AT_PHDR per `31§4`. `0` if no PT_LOAD covers phoff.
    pub phdr_va:    u64,
    pub phentsize:  u16,
    pub phnum:      u16,
    /// Load base of the dynamic-linker (PT_INTERP) image, or `0`
    /// if no interpreter was requested. Auxv AT_BASE per `31§4`.
    pub interp_base: u64,
    /// Entry-point of the dynamic linker, or `0` if no interpreter.
    /// `spawn_user_blob_smoke` / `sys_execve` drop to ring 3 here
    /// when non-zero so the linker runs first; the linker reads
    /// AT_ENTRY to find the exec's actual entry.
    pub interp_entry: u64,
}

impl LoadedImage {
    /// User RIP to drop into ring 3: the dynamic linker if PT_INTERP
    /// was set, else the exec's own entry (static-PIE / static path).
    /// # C: O(1)
    pub fn user_ip(&self) -> u64 {
        if self.interp_entry != 0 { self.interp_entry } else { self.entry.as_u64() }
    }
}

/// Read the dynamic-linker (PT_INTERP) file from the rootfs and
/// return an owned `Vec<u8>`. Caller drops it after `place_image`
/// has copied the segment bytes into AS-owned staging buffers
/// (per B22) — no per-exec leak.
/// # SAFETY: caller is the ELF loader; ext4 mount has been brought
/// up by `kernel_main` before any execve runs.
/// # C: O(file size) — one ext4 read.
#[cfg(target_os = "oxide-kernel")]
fn read_interp_blob(path: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    crate::dev_ext4::read_file(path)
}

#[cfg(not(target_os = "oxide-kernel"))]
fn read_interp_blob(_path: &[u8]) -> Option<alloc::vec::Vec<u8>> { None }

/// Default load bias for ET_DYN (PIE) images. Real Linux
/// randomises this per-exec; v1 uses a fixed value disjoint from
/// the hand-rolled-blob VAs (0x400000) and from the user stack
/// (0x501000). 0x10000000 keeps the user-half plenty of room.
/// docs/31§6 ASLR is v1.x — fixed bias for now.
const PIE_LOAD_BIAS: u64 = 0x1000_0000;

/// Load bias for the dynamic-linker (PT_INTERP) image. Disjoint
/// from `PIE_LOAD_BIAS` + the 64 MiB heap above the exec so the
/// linker's PT_LOADs never collide with the exec's heap window.
/// Real Linux randomises this; v1 fixed.
const INTERP_LOAD_BIAS: u64 = 0x4000_0000;

/// Load `blob` into `as_` per docs/31§4. Each PT_LOAD becomes a
/// MAP_FIXED VMA with `VmaBacking::KernelBytes` (P2-17) so demand-
/// paging copies the bytes from the kernel image on first touch.
///
/// PIE binaries (`ET_DYN`) get the fixed `PIE_LOAD_BIAS`; non-PIE
/// (`ET_EXEC`) load at their declared `p_vaddr`. All `entry`,
/// `phdr_va`, `brk`, and stack VAs are biased accordingly.
///
/// `blob` only needs to live for the duration of this call: the
/// segment bytes are copied into AS-owned staging Vecs (B22), so
/// the input slice can be a transient `&Vec<u8>` from an ext4 read
/// or a `&'static` const-blob — both work.
///
struct LoadStaging {
    vstart:   u64,
    vend:     u64,
    prot:     VmaProt,
    padded:   alloc::vec::Vec<u8>,
    head_pad: usize,
}

/// # C: O(phdrs) parse + O(phdrs) mmap
pub fn load_static_blob(
    blob: &[u8],
    as_: &AddressSpace,
) -> Result<LoadedImage, LoadError> {
    // Load the exec at its declared bias.
    let exec = place_image(blob, as_, None)?;

    // If the ELF has a PT_INTERP, look up the interpreter file from
    // the rootfs and load it at INTERP_LOAD_BIAS. The interpreter
    // is itself an ET_DYN with self-relocs, so `place_image` does
    // the same staging+rebase for it.
    let parsed = parse(blob, ARCH_MACHINE)?;
    let mut interp_base: u64 = 0;
    let mut interp_entry: u64 = 0;
    // PT_INTERP dual-image load: read the interpreter file directly
    // from ext4 (arch-neutral) and stage as a second `place_image`.
    // Both arches use the same flow now — the interpreter binary
    // itself is per-arch (`/lib/ld-musl-x86_64.so.1` vs
    // `/lib/ld-musl-aarch64.so.1`), but the kernel-side mechanics
    // are identical.
    if let Some(interp_path) = parsed.interp {
        let interp_blob = read_interp_blob(interp_path)
            .ok_or(LoadError::Enoexec)?;
        // place_image copies the segment bytes it needs into the
        // AS-owned `staged_bytes` Vec via `stash_bytes`. The original
        // interp_blob Vec drops at end of this scope — no leak.
        let interp = place_image(&interp_blob, as_, Some(INTERP_LOAD_BIAS))?;
        interp_base  = INTERP_LOAD_BIAS;
        interp_entry = interp.entry.as_u64();
    }

    Ok(LoadedImage {
        entry:        exec.entry,
        brk:          exec.brk,
        phdr_va:      exec.phdr_va,
        phentsize:    exec.phentsize,
        phnum:        exec.phnum,
        interp_base,
        interp_entry,
    })
}

/// Inner placement: parse `blob`, lay out PT_LOADs, apply ET_DYN
/// self-relocs into staging buffers, then `mmap` each as
/// `KernelBytes`. `bias_override` lets callers (PT_INTERP) place
/// at a non-default base.
///
/// Returns a `LoadedImage` with `interp_*` zeroed — those fields
/// are populated only by `load_static_blob` after the second pass.
fn place_image(
    blob: &[u8],
    as_: &AddressSpace,
    bias_override: Option<u64>,
) -> Result<LoadedImage, LoadError> {
    let parsed = parse(blob, ARCH_MACHINE)?;

    let bias: u64 = match (bias_override, parsed.elf_type) {
        (Some(b), ElfType::Dyn) => b,
        (Some(_), _)            => return Err(LoadError::Enoexec),
        (None, ElfType::Dyn)    => PIE_LOAD_BIAS,
        (None, ElfType::Exec)   => 0,
        _                       => return Err(LoadError::Enoexec),
    };

    // First pass: build a Vec<(vstart, vend, prot, padded_buf)> so
    // we can apply DT_RELA relocations to the in-kernel buffers
    // BEFORE leaking + mmap'ing them. The previous code wrote
    // through user VAs in the active CR3, which only worked when
    // the active AS happened to alias the new AS's mappings.
    let mut max_end: u64 = 0;
    let mut staging: alloc::vec::Vec<LoadStaging> = alloc::vec::Vec::with_capacity(parsed.loads.len());
    for seg in &parsed.loads {
        let vaddr = seg.vaddr.checked_add(bias).ok_or(LoadError::Einval)?;
        let vstart = align_down(vaddr, PAGE);
        let vend   = align_up(vaddr.checked_add(seg.mem_sz)
            .ok_or(LoadError::Einval)?, PAGE);
        if vend <= vstart { return Err(LoadError::Einval); }

        let file_off = seg.file_off as usize;
        let file_sz  = seg.file_sz  as usize;
        let raw_data = blob.get(file_off..file_off.checked_add(file_sz)
            .ok_or(LoadError::Einval)?).ok_or(LoadError::Einval)?;
        let head_pad = (vaddr - vstart) as usize;
        // Pad to full VMA length so relocations into BSS land in
        // an addressable byte range; the trailing zeros become the
        // user task's BSS at first fault.
        let buf_len = (vend - vstart) as usize;
        let copy_n  = buf_len.min(head_pad + raw_data.len());
        let mut padded = alloc::vec![0u8; buf_len];
        padded[head_pad..copy_n].copy_from_slice(&raw_data[..copy_n - head_pad]);

        let mut prot = VmaProt::empty();
        if seg.flags.contains(PFlags::R) { prot |= VmaProt::READ;  }
        if seg.flags.contains(PFlags::W) { prot |= VmaProt::WRITE; }
        if seg.flags.contains(PFlags::X) { prot |= VmaProt::EXEC;  }

        if vend > max_end { max_end = vend; }
        staging.push(LoadStaging { vstart, vend, prot, padded, head_pad });
    }

    // Apply DT_RELA self-relocations into the staging buffers.
    // Each rela's r_off + bias is a user VA; find which staging
    // entry owns it, translate to the buffer offset, and write
    // there. Demand-faulting later just maps the patched bytes.
    if matches!(parsed.elf_type, ElfType::Dyn) && bias != 0 {
        apply_relative_relocs_into(blob, &parsed, bias, &mut staging)?;
    }

    // Second pass: wrap each staging buf as Arc<[u8]> via stash_bytes
    // so it refcounts across fork (child VMA cloned bumps the Arc;
    // the buffer drops when the last AS holding a KernelBytes VMA to
    // it does), and mmap as KernelBytes pointing into the Arc.
    for s in staging {
        let data: alloc::sync::Arc<[u8]> =
            as_.stash_bytes(s.padded.into_boxed_slice());
        let hint = UserVirtAddr::new(s.vstart).ok_or(LoadError::Einval)?;
        let _ = as_.mmap(
            Some(hint),
            (s.vend - s.vstart) as usize,
            s.prot,
            VmaFlags::PRIVATE,
            VmaBacking::KernelBytes { data, off: 0 },
            true,
        ).map_err(|_| LoadError::Enomem)?;
        let _ = s.head_pad;
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
    // Only the exec image (bias_override == None) gets a heap;
    // the dynamic linker shares the exec's brk window.
    if bias_override.is_none() {
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
    }

    Ok(LoadedImage {
        entry, brk,
        phdr_va, phentsize: parsed.phentsize, phnum: parsed.phnum,
        interp_base: 0, interp_entry: 0,
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
fn apply_relative_relocs_into(
    blob: &[u8],
    parsed: &elf::ParsedElf,
    bias: u64,
    staging: &mut [LoadStaging],
) -> Result<(), LoadError> {
    // Find PT_DYNAMIC + DT_RELA via the same walk as the
    // legacy apply_relative_relocs.
    let mut dyn_off: usize = 0;
    let mut dyn_sz:  usize = 0;
    for i in 0..(parsed.phnum as usize) {
        let base = parsed.phoff as usize + i * (parsed.phentsize as usize);
        let p_type = u32::from_le_bytes(blob[base..base+4].try_into().unwrap_or([0;4]));
        if p_type == 2 {
            dyn_off = u64::from_le_bytes(blob[base+8..base+16].try_into().unwrap_or([0;8])) as usize;
            dyn_sz  = u64::from_le_bytes(blob[base+32..base+40].try_into().unwrap_or([0;8])) as usize;
            break;
        }
    }
    if dyn_sz == 0 { return Ok(()); }
    if dyn_off + dyn_sz > blob.len() { return Err(LoadError::Einval); }
    let mut rela_off: u64 = 0;
    let mut rela_sz:  u64 = 0;
    let mut rela_ent: u64 = 24;
    let mut p = dyn_off;
    while p + 16 <= dyn_off + dyn_sz {
        let tag = i64::from_le_bytes(blob[p..p+8].try_into().unwrap_or([0;8]));
        let val = u64::from_le_bytes(blob[p+8..p+16].try_into().unwrap_or([0;8]));
        match tag {
            0  => break,
            7  => rela_off = val,
            8  => rela_sz  = val,
            9  => rela_ent = val,
            _ => {}
        }
        p += 16;
    }
    if rela_sz == 0 { return Ok(()); }
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
        if r_type != 8 && r_type != 0x403 { continue; }
        let dst_va = bias.checked_add(r_off).ok_or(LoadError::Einval)?;
        let val    = (bias as i64).wrapping_add(r_add) as u64;
        if dst_va == 0 { return Err(LoadError::Einval); }
        // Locate staging entry covering dst_va, write into its buf.
        let mut placed = false;
        for s in staging.iter_mut() {
            if dst_va >= s.vstart && dst_va + 8 <= s.vend {
                let off = (dst_va - s.vstart) as usize;
                if off + 8 > s.padded.len() { return Err(LoadError::Einval); }
                s.padded[off..off+8].copy_from_slice(&val.to_le_bytes());
                placed = true;
                break;
            }
        }
        // Silently skip relocations that fall outside any PT_LOAD
        // (corrupt input — apply_relative_relocs originally faulted).
        let _ = placed;
    }
    Ok(())
}

#[allow(dead_code)]
fn apply_relative_relocs(
    blob: &[u8],
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
