// 026 msync — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(any(target_os = "oxide-kernel", test))]

use syscall::errno::Errno;
use syscall::SyscallArgs;

/// `MS_ASYNC` — Linux no-op since 2.5.67/2.6.17 dirty tracking.
pub(crate) const MS_ASYNC: u64 = 0x1;
/// `MS_INVALIDATE` — reject locked VMAs with EBUSY.
pub(crate) const MS_INVALIDATE: u64 = 0x2;
/// `MS_SYNC` — flush shared file-backed VMAs and wait.
pub(crate) const MS_SYNC: u64 = 0x4;
const PAGE: u64 = 0x1000;
const PAGE_MASK: u64 = PAGE - 1;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn page_align_len(len: u64) -> Option<u64> {
    len.checked_add(PAGE_MASK).map(|v| v & !PAGE_MASK)
}

/// Linux `msync(2)` over a stable VMA snapshot. Returns the syscall result.
/// # C: O(N_vmas + N_dirty_range)
pub(crate) fn msync_vmas(start: u64, len: u64, flags: u64, vmas: &[vmm::Vma]) -> i64 {
    if (flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC)) != 0 { return err(Errno::Einval); }
    if (start & PAGE_MASK) != 0 { return err(Errno::Einval); }
    if (flags & MS_ASYNC) != 0 && (flags & MS_SYNC) != 0 { return err(Errno::Einval); }
    let Some(len) = page_align_len(len) else { return err(Errno::Enomem); };
    let Some(end) = start.checked_add(len) else { return err(Errno::Enomem); };
    if end == start { return 0; }

    let mut pos = start;
    let mut unmapped = false;
    for vma in vmas {
        let vs = vma.start.as_u64();
        let ve = vma.end.as_u64();
        if ve <= pos { continue; }
        if vs >= end { break; }
        if pos < vs {
            if flags == MS_ASYNC { return err(Errno::Enomem); }
            unmapped = true;
            pos = vs;
            if pos >= end { break; }
        }
        if pos >= ve { continue; }
        if (flags & MS_INVALIDATE) != 0 && vma.flags.contains(vmm::VmaFlags::LOCKED) {
            return err(Errno::Ebusy);
        }
        let seg_end = core::cmp::min(end, ve);
        if (flags & MS_SYNC) != 0 && vma.flags.contains(vmm::VmaFlags::SHARED) {
            if let vmm::VmaBacking::File { backing, off } = &vma.backing {
                let fstart = off.saturating_add(pos - vs);
                let fend_excl = off.saturating_add(seg_end - vs);
                // `vfs_fsync_range(vma->vm_file, fstart, fend, 1)`
                // (`mm/msync.c:96`) — DURABLE, not merely written back. The old
                // `writeback_range` call handed the bytes to the filesystem and
                // stopped there: no journal commit, no device barrier, so
                // `MS_SYNC` bought nothing over `MS_ASYNC`.
                if backing.fsync_range(fstart, fend_excl).is_err() {
                    return err(Errno::Eio);
                }
            }
        }
        pos = ve;
        if pos >= end { return if unmapped { err(Errno::Enomem) } else { 0 }; }
    }
    err(Errno::Enomem)
}

#[cfg(target_os = "oxide-kernel")]
fn current_vmas() -> Result<alloc::vec::Vec<vmm::Vma>, Errno> {
    let cur = sched::live::current().ok_or(Errno::Einval)?;
    // SAFETY: mm slot single-mutator per `13§5`; running task on this CPU.
    let mm = unsafe { cur.mm_ref() }.ok_or(Errno::Einval)?;
    Ok(mm.snapshot_vmas())
}

#[cfg(not(target_os = "oxide-kernel"))]
fn current_vmas() -> Result<std::vec::Vec<vmm::Vma>, Errno> {
    Err(Errno::Einval)
}

/// `sys_msync(addr, len, flags)` — slot 26.
/// ABI shim per `docs/53§4`. Work fn: `msync_vmas`.
/// # C: O(N_vmas + N_dirty_range)
pub fn sys_msync(args: &SyscallArgs) -> i64 {
    let vmas = match current_vmas() {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    msync_vmas(args.a0, args.a1, args.a2, &vmas)
}
