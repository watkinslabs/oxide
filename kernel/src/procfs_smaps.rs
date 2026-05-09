// F158: /proc/self/smaps + /proc/<pid>/smaps. Linux-conformant
// per-VMA detailed memory stats. Each VMA produces a header line
// (same as /proc/self/maps) followed by a metadata block with
// Size, Rss, Pss, Shared/Private Clean/Dirty, Referenced,
// Anonymous, LazyFree, AnonHugePages, ShmemHugePages,
// ShmemPmdMapped, FilePmdMapped, Shared_Hugetlb, Private_Hugetlb,
// Swap, SwapPss, KernelPageSize, MMUPageSize, Locked, ProtectionKey,
// THPeligible, VmFlags.
//
// v1 fields:
//   - Size = VMA byte length / 1024.
//   - Rss / Pss = same as Size (assume fully resident; UP no swap).
//   - Private_Clean / Private_Dirty = Size for writable; Clean=Size
//     for RO. Shared variants 0 (no MAP_SHARED tracking yet).
//   - Anonymous = Size for Anonymous-backed VMAs.
//   - VmFlags = Linux short-tag list derived from VmaProt + VmaFlags.
//
// Each VMA emits ~16 lines × ~20 chars = 320 bytes; 50 VMAs × 320
// = ~16 KiB. We size the Vec generously and use streaming reads.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use vfs::{FileType, Inode, InodeRef, Ino, KResult, VfsError};

/// `/proc/self/smaps` inode.
pub struct ProcSelfSmapsInode;

impl Inode for ProcSelfSmapsInode {
    fn ino(&self) -> Ino { 0x3000_1B00 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = build_for_current();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}

/// `/proc/<pid>/smaps` inode (per-pid).
pub struct ProcPidSmapsInode { pub tid: u32 }

impl Inode for ProcPidSmapsInode {
    fn ino(&self) -> Ino { (0x3000_1B01u64).wrapping_add(self.tid as u64) }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = build_for_pid(self.tid);
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}

/// Build the body for the current task.
/// # C: O(N_vmas)
pub fn build_for_current() -> Vec<u8> {
    let cur = match crate::sched::current() { Some(c) => c, None => return Vec::new() };
    // SAFETY: mm slot single-mutator per `13§5`.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return Vec::new() };
    build_from_mm(&mm)
}

/// Build the body for a specific pid (looked up via registry).
/// # C: O(N_vmas)
pub fn build_for_pid(tid: u32) -> Vec<u8> {
    let task = match crate::sched::registry::lookup(tid) { Some(t) => t, None => return Vec::new() };
    // SAFETY: mm slot single-mutator per `13§5`; we read a snapshot.
    let mm = match unsafe { (*task.mm.get()).as_ref() } { Some(m) => m.clone(), None => return Vec::new() };
    build_from_mm(&mm)
}

fn build_from_mm(mm: &vmm::AddressSpace) -> Vec<u8> {
    let mut out = Vec::with_capacity(4096);
    for vma in mm.snapshot_vmas() {
        let kb = (vma.end.as_u64() - vma.start.as_u64()) / 1024;
        let is_anon = matches!(vma.backing, vmm::VmaBacking::Anonymous);
        let is_writable = vma.prot.contains(vmm::VmaProt::WRITE);
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
        kv_kb(&mut out, b"Rss:            ", kb);
        kv_kb(&mut out, b"Pss:            ", kb);
        kv_kb(&mut out, b"Pss_Dirty:      ", if is_writable { kb } else { 0 });
        kv_kb(&mut out, b"Shared_Clean:   ", 0);
        kv_kb(&mut out, b"Shared_Dirty:   ", 0);
        kv_kb(&mut out, b"Private_Clean:  ", if is_writable { 0 } else { kb });
        kv_kb(&mut out, b"Private_Dirty:  ", if is_writable { kb } else { 0 });
        kv_kb(&mut out, b"Referenced:     ", kb);
        kv_kb(&mut out, b"Anonymous:      ", if is_anon { kb } else { 0 });
        kv_kb(&mut out, b"LazyFree:       ", 0);
        kv_kb(&mut out, b"AnonHugePages:  ", 0);
        kv_kb(&mut out, b"ShmemPmdMapped: ", 0);
        kv_kb(&mut out, b"FilePmdMapped:  ", 0);
        kv_kb(&mut out, b"Shared_Hugetlb: ", 0);
        kv_kb(&mut out, b"Private_Hugetlb:", 0);
        kv_kb(&mut out, b"Swap:           ", 0);
        kv_kb(&mut out, b"SwapPss:        ", 0);
        kv_kb(&mut out, b"Locked:         ", 0);
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
