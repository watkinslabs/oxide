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

use elf::{parse, ElfError, EM_AARCH64, EM_X86_64, PFlags};
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
    pub entry: UserVirtAddr,
    pub brk:   UserVirtAddr,
}

/// Load `blob` into `as_` per docs/31§4. Each PT_LOAD becomes a
/// MAP_FIXED VMA with `VmaBacking::KernelBytes` (P2-17) so demand-
/// paging copies the bytes from the kernel image on first touch.
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

    let mut max_end: u64 = 0;
    for seg in &parsed.loads {
        // Round VMA range to page granule per `11§4` (mmap
        // alignment requirement).
        let vstart = align_down(seg.vaddr, PAGE);
        let vend   = align_up(seg.vaddr.checked_add(seg.mem_sz)
            .ok_or(LoadError::Einval)?, PAGE);
        if vend <= vstart { return Err(LoadError::Einval); }

        // Slice the file-backed extent for this segment. The
        // load_bias = 0 (PIE without ASLR loads at p_vaddr).
        let file_off = seg.file_off as usize;
        let file_sz  = seg.file_sz  as usize;
        let data = blob.get(file_off..file_off.checked_add(file_sz)
            .ok_or(LoadError::Einval)?).ok_or(LoadError::Einval)?;

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
            true,            // MAP_FIXED — place exactly at p_vaddr
        ).map_err(|_| LoadError::Enomem)?;

        if vend > max_end { max_end = vend; }
    }

    let entry = UserVirtAddr::new(parsed.entry).ok_or(LoadError::Einval)?;
    let brk   = UserVirtAddr::new(max_end).ok_or(LoadError::Einval)?;

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

    Ok(LoadedImage { entry, brk })
}

#[inline]
fn align_down(v: u64, a: u64) -> u64 { v & !(a - 1) }
#[inline]
fn align_up(v: u64, a: u64)   -> u64 { (v + (a - 1)) & !(a - 1) }
