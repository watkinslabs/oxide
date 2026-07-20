// F158: /proc/self/smaps + /proc/<pid>/smaps. Linux-conformant
// per-VMA detailed memory stats. Each VMA produces a header line
// (same as /proc/self/maps) followed by a metadata block with
// Size, Rss, Pss, Shared/Private Clean/Dirty, Referenced,
// Anonymous, LazyFree, AnonHugePages, ShmemHugePages,
// ShmemPmdMapped, FilePmdMapped, Shared_Hugetlb, Private_Hugetlb,
// Swap, SwapPss, KernelPageSize, MMUPageSize, Locked, ProtectionKey,
// THPeligible, VmFlags.
//
// Fields with an authoritative owner:
//   - Size = VMA byte length / 1024.
//   - Rss / Pss and Swap / SwapPss scan canonical present/swap PTEs.
//   - Anonymous counts resident anonymous pages.
//   - Dirty/referenced accounting remains zero until the page metadata owner
//     exposes those bits; procfs does not invent them from VMA protection.
//   - VmFlags = Linux short-tag list derived from VmaProt + VmaFlags.
//
// Each VMA emits ~16 lines × ~20 chars = 320 bytes; 50 VMAs × 320
// = ~16 KiB. We size the Vec generously and use streaming reads.


use alloc::vec::Vec;
use vfs::{Ino, InodeRef};

const KIB_BYTES: u64 = 1024;

/// `/proc/self/smaps` inode. # C: O(1)
pub fn make_proc_self_smaps() -> InodeRef {
    crate::dyn_file::make_gen_file(crate::ids::SMAPS as Ino, build_for_current)
}

/// `/proc/<pid>/smaps` inode (per-pid). # C: O(1)
pub fn make_proc_pid_smaps(tid: u32) -> InodeRef {
    crate::dyn_file::make_pid_gen_file(crate::live::pid_ino(0x1B, tid), tid, build_for_pid)
}

/// Build the body for the current task.
/// # C: O(N_vmas)
pub fn build_for_current() -> Vec<u8> {
    let cur = match sched::live::current() { Some(c) => c, None => return Vec::new() };
    // SAFETY: mm slot single-mutator per `13§5`.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return Vec::new() };
    build_from_mm(&mm)
}

/// Build the body for a specific pid (looked up via registry).
/// # C: O(N_vmas)
pub fn build_for_pid(tid: u32) -> Vec<u8> {
    let task = match sched::live::registry::lookup(tid) { Some(t) => t, None => return Vec::new() };
    // SAFETY: mm slot single-mutator per `13§5`; we read a snapshot.
    let mm = match unsafe { (*task.mm.get()).as_ref() } { Some(m) => m.clone(), None => return Vec::new() };
    build_from_mm(&mm)
}

fn build_from_mm(mm: &vmm::AddressSpace) -> Vec<u8> {
    let mut out = Vec::with_capacity(4096);
    for vma in mm.snapshot_vmas() {
        let kb = (vma.end.as_u64() - vma.start.as_u64()) / KIB_BYTES;
        let page_stats = pmm::user_as::range_memory_stats(mm, vma.start, vma.end);
        let rss_kb = page_stats.resident_pages * (hal::PAGE_SIZE_BYTES / KIB_BYTES);
        let swap_kb = page_stats.swapped_pages * (hal::PAGE_SIZE_BYTES / KIB_BYTES);
        let is_anon = matches!(vma.backing, vmm::VmaBacking::Anonymous);
        // Header line — same as maps.
        push_hex(&mut out, vma.start.as_u64());
        out.push(b'-');
        push_hex(&mut out, vma.end.as_u64());
        out.push(b' ');
        out.push(if vma.prot.contains(vmm::VmaProt::READ)  { b'r' } else { b'-' });
        out.push(if vma.prot.contains(vmm::VmaProt::WRITE) { b'w' } else { b'-' });
        out.push(if vma.prot.contains(vmm::VmaProt::EXEC)  { b'x' } else { b'-' });
        out.push(if vma.flags.contains(vmm::VmaFlags::SHARED) { b's' } else { b'p' });
        push(&mut out, b" 00000000 00:00 0 ");
        if vma.flags.contains(vmm::VmaFlags::GROWSDOWN) { push(&mut out, b"[stack]"); }
        out.push(b'\n');
        // Detail block.
        kv_kb(&mut out, b"Size:           ", kb);
        kv_kb(&mut out, b"KernelPageSize: ", 4);
        kv_kb(&mut out, b"MMUPageSize:    ", 4);
        kv_kb(&mut out, b"Rss:            ", rss_kb);
        kv_kb(&mut out, b"Pss:            ", rss_kb);
        kv_kb(&mut out, b"Pss_Dirty:      ", 0);
        kv_kb(&mut out, b"Shared_Clean:   ", 0);
        kv_kb(&mut out, b"Shared_Dirty:   ", 0);
        kv_kb(&mut out, b"Private_Clean:  ", 0);
        kv_kb(&mut out, b"Private_Dirty:  ", 0);
        kv_kb(&mut out, b"Referenced:     ", 0);
        kv_kb(&mut out, b"Anonymous:      ", if is_anon { rss_kb } else { 0 });
        kv_kb(&mut out, b"LazyFree:       ", 0);
        kv_kb(&mut out, b"AnonHugePages:  ", 0);
        kv_kb(&mut out, b"ShmemPmdMapped: ", 0);
        kv_kb(&mut out, b"FilePmdMapped:  ", 0);
        kv_kb(&mut out, b"Shared_Hugetlb: ", 0);
        kv_kb(&mut out, b"Private_Hugetlb:", 0);
        kv_kb(&mut out, b"Swap:           ", swap_kb);
        kv_kb(&mut out, b"SwapPss:        ", swap_kb);
        kv_kb(&mut out, b"Locked:         ", if vma.flags.contains(vmm::VmaFlags::LOCKED) { rss_kb } else { 0 });
        push(&mut out, b"THPeligible:    0\n");
        push(&mut out, b"ProtectionKey:  0\n");
        // VmFlags short-tag list per Linux Documentation/filesystems/proc.rst.
        push(&mut out, b"VmFlags:");
        if vma.prot.contains(vmm::VmaProt::READ)        { push(&mut out, b" rd"); }
        if vma.prot.contains(vmm::VmaProt::WRITE)       { push(&mut out, b" wr"); }
        if vma.prot.contains(vmm::VmaProt::EXEC)        { push(&mut out, b" ex"); }
        if vma.flags.contains(vmm::VmaFlags::SHARED)    { push(&mut out, b" sh"); }
        if vma.flags.contains(vmm::VmaFlags::GROWSDOWN) { push(&mut out, b" gd"); }
        if !vma.flags.contains(vmm::VmaFlags::SHARED) { push(&mut out, b" mr mw me"); } // can-mremap-in-place
        if is_anon                                      { push(&mut out, b" ac"); }
        out.push(b'\n');
    }
    out
}

fn push(v: &mut Vec<u8>, b: &[u8]) { v.extend_from_slice(b); }

fn push_u64(v: &mut Vec<u8>, mut n: u64) {
    if n == 0 { v.push(b'0'); return; }
    let mut buf = [0u8; 20]; let mut i = 0;
    while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    while i > 0 { i -= 1; v.push(buf[i]); }
}

fn push_hex(v: &mut Vec<u8>, mut n: u64) {
    if n == 0 { v.push(b'0'); return; }
    let mut buf = [0u8; 16]; let mut i = 0;
    while n > 0 {
        let nib = (n & 0xf) as u8;
        buf[i] = if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) };
        n >>= 4; i += 1;
    }
    while i > 0 { i -= 1; v.push(buf[i]); }
}

fn kv_kb(out: &mut Vec<u8>, k: &[u8], v: u64) {
    push(out, k); push_u64(out, v); push(out, b" kB\n");
}
