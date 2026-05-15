// vDSO bring-up per `15` + Linux Documentation/abi/vdso.rst.
// The vDSO is a tiny ELF mapped into every user AS at execve.
// glibc / musl / Go runtimes probe AT_SYSINFO_EHDR to find it and
// call the exported `__vdso_*` symbols instead of invoking the
// equivalent syscalls directly.
//
// Substrate: each exported symbol is a syscall trampoline — no
// fast path yet. Provides the AT_SYSINFO_EHDR auxv entry every
// modern runtime checks at startup, and the symbol-lookup surface
// glibc's vDSO resolver walks. Fast-path (vvar page + clock-
// monotonic encoder read without leaving user mode) rides a
// follow-up.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use hal::UserVirtAddr;
use vmm::{VmaBacking, VmaFlags, VmaProt};

#[cfg(target_arch = "x86_64")]
pub const VDSO_BLOB: &[u8] = include_bytes!("../blobs/vdso-x86_64.so");
#[cfg(target_arch = "aarch64")]
pub const VDSO_BLOB: &[u8] = include_bytes!("../blobs/vdso-aarch64.so");

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const ELF_PHOFF: usize = 32;     // e_phoff
const ELF_PHENTSIZE: usize = 54; // e_phentsize
const ELF_PHNUM: usize = 56;     // e_phnum

/// Parse the vDSO ELF and return (max_vaddr_end, Vec<segment>) where
/// each segment is (vaddr, filesz, memsz, p_offset, p_flags).
/// Returns None on malformed ELF (kernel boot continues without vDSO).
fn parse_segments() -> Option<(u64, alloc::vec::Vec<(u64, u64, u64, u64, u32)>)> {
    let b = VDSO_BLOB;
    if b.len() < ELF_PHNUM + 2 { return None; }
    if &b[0..4] != b"\x7fELF" { return None; }
    let phoff = u64::from_le_bytes(b[ELF_PHOFF..ELF_PHOFF+8].try_into().ok()?);
    let phentsize = u16::from_le_bytes(b[ELF_PHENTSIZE..ELF_PHENTSIZE+2].try_into().ok()?) as usize;
    let phnum = u16::from_le_bytes(b[ELF_PHNUM..ELF_PHNUM+2].try_into().ok()?) as usize;
    if phentsize < 56 { return None; }
    let mut segs = alloc::vec::Vec::with_capacity(phnum);
    let mut end: u64 = 0;
    for i in 0..phnum {
        let off = phoff as usize + i * phentsize;
        if off + 56 > b.len() { return None; }
        let p_type   = u32::from_le_bytes(b[off..off+4].try_into().ok()?);
        if p_type != PT_LOAD { continue; }
        let p_flags  = u32::from_le_bytes(b[off+4..off+8].try_into().ok()?);
        let p_offset = u64::from_le_bytes(b[off+8..off+16].try_into().ok()?);
        let p_vaddr  = u64::from_le_bytes(b[off+16..off+24].try_into().ok()?);
        let p_filesz = u64::from_le_bytes(b[off+32..off+40].try_into().ok()?);
        let p_memsz  = u64::from_le_bytes(b[off+40..off+48].try_into().ok()?);
        let seg_end  = (p_vaddr + p_memsz + 0xfff) & !0xfff;
        if seg_end > end { end = seg_end; }
        segs.push((p_vaddr, p_filesz, p_memsz, p_offset, p_flags));
    }
    Some((end, segs))
}

/// Translate ELF PF_* flags to VmaProt.
fn prot_of(p_flags: u32) -> VmaProt {
    let mut p = VmaProt::empty();
    if (p_flags & PF_R) != 0 { p |= VmaProt::READ; }
    if (p_flags & PF_W) != 0 { p |= VmaProt::WRITE; }
    if (p_flags & PF_X) != 0 { p |= VmaProt::EXEC; }
    p
}

/// Map the vDSO into the calling task's AS, honoring per-PT_LOAD
/// vaddr / memsz / flags. Also maps a kernel-published vvar page
/// at `base - 0x1000` so the linker-script `_vdso_data` symbol
/// resolves to that VA — the vDSO fast paths read live time
/// from this page without invoking a syscall.
///
/// Layout:
///   base - 0x1000  RO  vvar page (seq + monotonic_ns + realtime)
///   base ..      RX/RO vDSO PT_LOAD segments
///
/// Returns the load VA (== ELF header VA) for AT_SYSINFO_EHDR.
/// # C: O(N_pt_loads × N_vmas)
pub fn map_into_current() -> Option<u64> {
    let cur = sched::live::current()?;
    // SAFETY: running task on this CPU; preempt-off; sole writer of mm slot.
    let mm = unsafe { cur.mm_ref() }?.clone();
    let (total, segs) = parse_segments()?;
    if segs.is_empty() || total == 0 { return None; }
    // Reserve vvar + total bytes: vvar = 1 page right before vDSO base.
    let reserve = (0x1000 + total) as usize;
    let placeholder = mm.mmap(None, reserve,
        VmaProt::READ, VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
        VmaBacking::Anonymous, false).ok()?;
    let vvar_va = placeholder.as_u64();
    let base    = vvar_va + 0x1000;
    let _ = mm.munmap(placeholder, reserve);
    // 1. Map the vvar page (RO from user mode) backed by the
    // single shared kernel frame so kernel publisher writes
    // propagate to every user reader without copy.
    let vvar_pa = crate::vvar::pa();
    if vvar_pa == 0 { return None; }
    let vvar_hint = UserVirtAddr::new(vvar_va)?;
    mm.mmap(Some(vvar_hint), 0x1000, VmaProt::READ, VmaFlags::PRIVATE,
        VmaBacking::KernelFrame { pa: vvar_pa }, true).ok()?;
    // 2. Map each PT_LOAD of the vDSO ELF at base + v_addr.
    for (vaddr, filesz, memsz, p_offset, p_flags) in segs {
        let seg_start = base.wrapping_add(vaddr);
        let seg_len_pages = ((memsz + 0xfff) & !0xfff) as usize;
        if seg_len_pages == 0 { continue; }
        let data_start = p_offset as usize;
        let data_end   = (p_offset + filesz) as usize;
        if data_end > VDSO_BLOB.len() { return None; }
        let slice = Arc::<[u8]>::from(VDSO_BLOB[data_start..data_end].to_vec().into_boxed_slice());
        let prot = prot_of(p_flags);
        let hint = UserVirtAddr::new(seg_start)?;
        mm.mmap(Some(hint), seg_len_pages, prot, VmaFlags::PRIVATE,
            VmaBacking::KernelBytes { data: slice, off: 0 }, true).ok()?;
    }
    Some(base)
}
