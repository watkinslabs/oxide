// 028 madvise — one syscall, one file (docs/53 §0).
#![cfg(any(target_os = "oxide-kernel", test))]

use syscall::errno::Errno;
#[cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;

const PAGE: u64 = 0x1000;
const PAGE_MASK: u64 = PAGE - 1;

const MADV_NORMAL: u64 = 0;
const MADV_RANDOM: u64 = 1;
const MADV_SEQUENTIAL: u64 = 2;
const MADV_WILLNEED: u64 = 3;
const MADV_DONTNEED: u64 = 4;
const MADV_FREE: u64 = 8;
const MADV_REMOVE: u64 = 9;
const MADV_DONTFORK: u64 = 10;
const MADV_DOFORK: u64 = 11;
const MADV_MERGEABLE: u64 = 12;
const MADV_UNMERGEABLE: u64 = 13;
const MADV_HUGEPAGE: u64 = 14;
const MADV_NOHUGEPAGE: u64 = 15;
const MADV_DONTDUMP: u64 = 16;
const MADV_DODUMP: u64 = 17;
const MADV_WIPEONFORK: u64 = 18;
const MADV_KEEPONFORK: u64 = 19;
const MADV_COLD: u64 = 20;
const MADV_PAGEOUT: u64 = 21;
const MADV_POPULATE_READ: u64 = 22;
const MADV_POPULATE_WRITE: u64 = 23;
const MADV_DONTNEED_LOCKED: u64 = 24;
const MADV_COLLAPSE: u64 = 25;
const MADV_HWPOISON: u64 = 100;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn page_align_len(len: u64) -> Option<u64> {
    len.checked_add(PAGE_MASK).map(|v| v & !PAGE_MASK)
}

fn advice_valid(advice: u64) -> bool {
    matches!(advice,
        MADV_NORMAL | MADV_RANDOM | MADV_SEQUENTIAL | MADV_WILLNEED |
        MADV_DONTNEED | MADV_FREE | MADV_REMOVE | MADV_DONTFORK |
        MADV_DOFORK | MADV_MERGEABLE | MADV_UNMERGEABLE | MADV_HUGEPAGE |
        MADV_NOHUGEPAGE | MADV_DONTDUMP | MADV_DODUMP | MADV_WIPEONFORK |
        MADV_KEEPONFORK | MADV_COLD | MADV_PAGEOUT | MADV_POPULATE_READ |
        MADV_POPULATE_WRITE | MADV_DONTNEED_LOCKED | MADV_COLLAPSE |
        MADV_HWPOISON)
}

pub(crate) trait MadviseOps {
    fn evict_pages(&mut self, _start: u64, _len: u64) -> i64 { 0 }
    fn pageout_anon_pages(&mut self, _start: u64, _len: u64) -> i64 { 0 }
    fn update_flags(&mut self, _start: u64, _len: u64,
                    _set: vmm::VmaFlags, _clear: vmm::VmaFlags) {}
    fn populate(&mut self, _start: u64, _len: u64, _write: bool) -> i64 { 0 }
}

fn find_vma<'a>(vmas: &'a [vmm::Vma], pos: u64) -> Option<&'a vmm::Vma> {
    vmas.iter().find(|v| v.end.as_u64() > pos)
}

fn file_err(e: vmm::FileBackingError) -> i64 {
    match e {
        vmm::FileBackingError::Acces => err(Errno::Eacces),
        vmm::FileBackingError::Badf => err(Errno::Ebadf),
        vmm::FileBackingError::Inval => err(Errno::Einval),
        vmm::FileBackingError::Io => err(Errno::Eio),
        vmm::FileBackingError::NoMem => err(Errno::Enomem),
        vmm::FileBackingError::OpNotSupp => err(Errno::Eopnotsupp),
    }
}

fn sealed_discard_rejected(vma: &vmm::Vma, advice: u64) -> bool {
    let discard = matches!(advice, MADV_FREE | MADV_DONTNEED | MADV_DONTNEED_LOCKED |
        MADV_REMOVE | MADV_DONTFORK | MADV_WIPEONFORK);
    discard
        && vma.flags.contains(vmm::VmaFlags::SEALED)
        && matches!(vma.backing, vmm::VmaBacking::Anonymous)
        && !vma.prot.contains(vmm::VmaProt::WRITE)
}

fn apply_vma<O: MadviseOps>(ops: &mut O, advice: u64, vma: &vmm::Vma, start: u64, end: u64) -> i64 {
    if sealed_discard_rejected(vma, advice) { return err(Errno::Eperm); }
    let len = end - start;
    match advice {
        MADV_NORMAL => {
            ops.update_flags(start, len, vmm::VmaFlags::empty(),
                vmm::VmaFlags::RAND_READ | vmm::VmaFlags::SEQ_READ);
            0
        }
        MADV_RANDOM => {
            ops.update_flags(start, len, vmm::VmaFlags::RAND_READ, vmm::VmaFlags::SEQ_READ);
            0
        }
        MADV_SEQUENTIAL => {
            ops.update_flags(start, len, vmm::VmaFlags::SEQ_READ, vmm::VmaFlags::RAND_READ);
            0
        }
        MADV_WILLNEED => 0,
        MADV_COLD => {
            if vma.flags.contains(vmm::VmaFlags::LOCKED) || matches!(vma.backing, vmm::VmaBacking::PhysRange { .. }) {
                return err(Errno::Einval);
            }
            0
        }
        MADV_PAGEOUT => {
            if vma.flags.contains(vmm::VmaFlags::LOCKED) || matches!(vma.backing, vmm::VmaBacking::PhysRange { .. }) {
                return err(Errno::Einval);
            }
            match &vma.backing {
                vmm::VmaBacking::Anonymous => ops.pageout_anon_pages(start, len),
                vmm::VmaBacking::File { off, backing } if vma.flags.contains(vmm::VmaFlags::SHARED) => {
                    let foff = off.saturating_add(start.saturating_sub(vma.start.as_u64()));
                    backing.madvise_pageout(foff, len).map_or_else(
                        || ops.evict_pages(start, len),
                        |result| result.map_or_else(file_err, |_| 0),
                    )
                }
                _ => ops.evict_pages(start, len),
            }
        }
        MADV_DONTNEED | MADV_DONTNEED_LOCKED => {
            if advice != MADV_DONTNEED_LOCKED && vma.flags.contains(vmm::VmaFlags::LOCKED) {
                return err(Errno::Einval);
            }
            if matches!(vma.backing, vmm::VmaBacking::PhysRange { .. }) {
                return err(Errno::Einval);
            }
            ops.evict_pages(start, len)
        }
        MADV_FREE => {
            if vma.flags.contains(vmm::VmaFlags::LOCKED)
                || !matches!(vma.backing, vmm::VmaBacking::Anonymous)
                || vma.flags.contains(vmm::VmaFlags::SHARED) {
                return err(Errno::Einval);
            }
            ops.evict_pages(start, len)
        }
        MADV_REMOVE => {
            if vma.flags.contains(vmm::VmaFlags::LOCKED) { return err(Errno::Einval); }
            if !vma.flags.contains(vmm::VmaFlags::SHARED)
                || !vma.may_prot.contains(vmm::VmaProt::WRITE) {
                return err(Errno::Eacces);
            }
            match &vma.backing {
                vmm::VmaBacking::File { backing, off } => {
                    let foff = off + (start - vma.start.as_u64());
                    backing.madvise_remove(foff, len).map_or_else(file_err, |_| 0)
                }
                _ => err(Errno::Einval),
            }
        }
        MADV_DONTFORK => {
            ops.update_flags(start, len, vmm::VmaFlags::DONTFORK, vmm::VmaFlags::empty());
            0
        }
        MADV_DOFORK => {
            if matches!(vma.backing, vmm::VmaBacking::Special | vmm::VmaBacking::PhysRange { .. }) {
                return err(Errno::Einval);
            }
            ops.update_flags(start, len, vmm::VmaFlags::empty(), vmm::VmaFlags::DONTFORK);
            0
        }
        MADV_WIPEONFORK => {
            if !matches!(vma.backing, vmm::VmaBacking::Anonymous) || vma.flags.contains(vmm::VmaFlags::SHARED) {
                return err(Errno::Einval);
            }
            ops.update_flags(start, len, vmm::VmaFlags::WIPEONFORK, vmm::VmaFlags::empty());
            0
        }
        MADV_KEEPONFORK => {
            ops.update_flags(start, len, vmm::VmaFlags::empty(), vmm::VmaFlags::WIPEONFORK);
            0
        }
        MADV_DONTDUMP => {
            ops.update_flags(start, len, vmm::VmaFlags::DONTDUMP, vmm::VmaFlags::empty());
            0
        }
        MADV_DODUMP => {
            if matches!(vma.backing, vmm::VmaBacking::Special | vmm::VmaBacking::PhysRange { .. }) {
                return err(Errno::Einval);
            }
            ops.update_flags(start, len, vmm::VmaFlags::empty(), vmm::VmaFlags::DONTDUMP);
            0
        }
        MADV_MERGEABLE => {
            ops.update_flags(start, len, vmm::VmaFlags::MERGEABLE, vmm::VmaFlags::empty());
            0
        }
        MADV_UNMERGEABLE => {
            ops.update_flags(start, len, vmm::VmaFlags::empty(), vmm::VmaFlags::MERGEABLE);
            0
        }
        MADV_HUGEPAGE => {
            ops.update_flags(start, len, vmm::VmaFlags::HUGEPAGE, vmm::VmaFlags::NOHUGEPAGE);
            0
        }
        MADV_NOHUGEPAGE => {
            ops.update_flags(start, len, vmm::VmaFlags::NOHUGEPAGE, vmm::VmaFlags::HUGEPAGE);
            0
        }
        MADV_POPULATE_READ => {
            if !vma.prot.contains(vmm::VmaProt::READ) { return err(Errno::Einval); }
            ops.populate(start, len, false)
        }
        MADV_POPULATE_WRITE => {
            if !vma.prot.contains(vmm::VmaProt::WRITE) { return err(Errno::Einval); }
            ops.populate(start, len, true)
        }
        MADV_COLLAPSE => err(Errno::Einval),
        MADV_HWPOISON => err(Errno::Eperm),
        _ => err(Errno::Einval),
    }
}

/// Linux `do_madvise()` over a stable VMA snapshot. Mutations are delegated to
/// `ops` so hosted tests can assert ordering without a live page table.
/// # C: O(N_vmas + pages for destructive advice)
pub(crate) fn madvise_vmas<O: MadviseOps>(
    start: u64,
    len_in: u64,
    advice: u64,
    vmas: &[vmm::Vma],
    ops: &mut O,
) -> i64 {
    if !advice_valid(advice) { return err(Errno::Einval); }
    if (start & PAGE_MASK) != 0 { return err(Errno::Einval); }
    let Some(len) = page_align_len(len_in) else { return err(Errno::Einval); };
    if len_in != 0 && len == 0 { return err(Errno::Einval); }
    let Some(end) = start.checked_add(len) else { return err(Errno::Einval); };
    if end < start { return err(Errno::Einval); }
    if len_in == 0 { return 0; }
    if advice == MADV_HWPOISON { return err(Errno::Eperm); }

    let mut pos = start;
    let mut unmapped = false;
    while pos < end {
        let Some(vma) = find_vma(vmas, pos) else { return err(Errno::Enomem); };
        if vma.start.as_u64() > pos {
            unmapped = true;
            pos = vma.start.as_u64();
            if pos >= end { break; }
        }
        let seg_start = core::cmp::max(pos, vma.start.as_u64());
        let seg_end = core::cmp::min(end, vma.end.as_u64());
        if seg_start < seg_end {
            let rv = apply_vma(ops, advice, vma, seg_start, seg_end);
            if rv != 0 { return rv; }
        }
        pos = seg_end;
    }
    if unmapped { err(Errno::Enomem) } else { 0 }
}

#[cfg(target_os = "oxide-kernel")]
struct LiveOps {
    mm: alloc::sync::Arc<vmm::AddressSpace>,
}

#[cfg(target_os = "oxide-kernel")]
impl MadviseOps for LiveOps {
    fn evict_pages(&mut self, start: u64, len: u64) -> i64 {
        pmm::user_as::evict_pages_in_range(start, len)
    }

    fn pageout_anon_pages(&mut self, start: u64, len: u64) -> i64 {
        pmm::user_as::pageout_anon_range(&self.mm, start, len)
    }

    fn update_flags(&mut self, start: u64, len: u64,
                    set: vmm::VmaFlags, clear: vmm::VmaFlags) {
        let Some(ua) = hal::UserVirtAddr::new(start) else { return };
        self.mm.update_flags_range(ua, len as usize, set, clear);
    }

    fn populate(&mut self, start: u64, len: u64, write: bool) -> i64 {
        let Some(ua) = hal::UserVirtAddr::new(start) else { return err(Errno::Enomem); };
        let prot = if write { vmm::VmaProt::WRITE } else { vmm::VmaProt::READ };
        pmm::user_as::populate_current_range(ua, len as usize, prot)
            .map_or_else(|_| err(Errno::Enomem), |_| 0)
    }
}

#[cfg(target_os = "oxide-kernel")]
fn current_mm_vmas() -> Result<(alloc::sync::Arc<vmm::AddressSpace>, alloc::vec::Vec<vmm::Vma>), Errno> {
    let cur = sched::live::current().ok_or(Errno::Einval)?;
    // SAFETY: mm slot single-mutator per `13§5`; running task on this CPU.
    let mm = unsafe { cur.mm_ref() }.ok_or(Errno::Einval)?.clone();
    let vmas = mm.snapshot_vmas();
    Ok((mm, vmas))
}

/// `sys_madvise(addr, len, advice)` — slot 28.
/// ABI shim per `docs/53§4`. Work fn: `madvise_vmas`.
/// # C: O(N_vmas + pages for destructive advice)
#[cfg(target_os = "oxide-kernel")]
pub fn sys_madvise(args: &SyscallArgs) -> i64 {
    let (mm, vmas) = match current_mm_vmas() {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let mut ops = LiveOps { mm };
    madvise_vmas(args.a0, args.a1, args.a2, &vmas, &mut ops)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    const TEST_START: u64 = 0x40_000;
    const TEST_LEN: u64 = PAGE;

    struct RecordedOps {
        pageout: Option<(u64, u64)>,
        evicted: bool,
    }

    impl MadviseOps for RecordedOps {
        fn evict_pages(&mut self, _start: u64, _len: u64) -> i64 {
            self.evicted = true;
            0
        }

        fn pageout_anon_pages(&mut self, start: u64, len: u64) -> i64 {
            self.pageout = Some((start, len));
            0
        }
    }

    fn anonymous_vma() -> vmm::Vma {
        let end = TEST_START + TEST_LEN;
        vmm::Vma::new(
            hal::UserVirtAddr::new(TEST_START).expect("test address is user canonical"),
            hal::UserVirtAddr::new(end).expect("test end is user canonical"),
            vmm::VmaProt::READ | vmm::VmaProt::WRITE,
            vmm::VmaFlags::PRIVATE | vmm::VmaFlags::ANONYMOUS,
            vmm::VmaBacking::Anonymous,
        )
    }

    struct SharedPageoutBacking {
        called: AtomicBool,
        off:    AtomicU64,
        len:    AtomicU64,
    }

    impl vmm::FileBacking for SharedPageoutBacking {
        fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, vmm::FileBackingError> { Ok(0) }
        fn size_hint(&self) -> u64 { TEST_LEN }
        fn madvise_pageout(&self, off: u64, len: u64) -> Option<Result<usize, vmm::FileBackingError>> {
            self.called.store(true, Ordering::Release);
            self.off.store(off, Ordering::Release);
            self.len.store(len, Ordering::Release);
            Some(Ok(1))
        }
    }

    #[test]
    fn pageout_dispatches_anonymous_range_to_swap_reclaim() {
        let vmas = [anonymous_vma()];
        let mut ops = RecordedOps { pageout: None, evicted: false };
        assert_eq!(madvise_vmas(TEST_START, TEST_LEN, MADV_PAGEOUT, &vmas, &mut ops), 0);
        assert_eq!(ops.pageout, Some((TEST_START, TEST_LEN)));
        assert!(!ops.evicted, "anonymous PAGEOUT must use swap reclaim, not discard");
    }

    #[test]
    fn pageout_dispatches_shared_file_range_to_backing_transaction() {
        let backing = Arc::new(SharedPageoutBacking {
            called: AtomicBool::new(false), off: AtomicU64::new(0), len: AtomicU64::new(0),
        });
        let vma = vmm::Vma::new(
            hal::UserVirtAddr::new(TEST_START).expect("test address is user canonical"),
            hal::UserVirtAddr::new(TEST_START + TEST_LEN).expect("test end is user canonical"),
            vmm::VmaProt::READ | vmm::VmaProt::WRITE,
            vmm::VmaFlags::SHARED,
            vmm::VmaBacking::File { backing: backing.clone(), off: PAGE },
        );
        let mut ops = RecordedOps { pageout: None, evicted: false };
        assert_eq!(madvise_vmas(TEST_START, TEST_LEN, MADV_PAGEOUT, &[vma], &mut ops), 0);
        assert!(backing.called.load(Ordering::Acquire));
        assert_eq!(backing.off.load(Ordering::Acquire), PAGE);
        assert_eq!(backing.len.load(Ordering::Acquire), TEST_LEN);
        assert!(!ops.evicted, "shared pageout must not discard before backing transaction");
    }

    #[test]
    fn pageout_private_file_falls_back_without_calling_shared_backing() {
        let backing = Arc::new(SharedPageoutBacking {
            called: AtomicBool::new(false), off: AtomicU64::new(0), len: AtomicU64::new(0),
        });
        let vma = vmm::Vma::new(
            hal::UserVirtAddr::new(TEST_START).expect("test address is user canonical"),
            hal::UserVirtAddr::new(TEST_START + TEST_LEN).expect("test end is user canonical"),
            vmm::VmaProt::READ | vmm::VmaProt::WRITE,
            vmm::VmaFlags::PRIVATE,
            vmm::VmaBacking::File { backing: backing.clone(), off: PAGE },
        );
        let mut ops = RecordedOps { pageout: None, evicted: false };
        assert_eq!(madvise_vmas(TEST_START, TEST_LEN, MADV_PAGEOUT, &[vma], &mut ops), 0);
        assert!(!backing.called.load(Ordering::Acquire), "MAP_PRIVATE must not page out the inode backing");
        assert!(ops.evicted, "MAP_PRIVATE PAGEOUT falls back to private-page eviction");
    }
}
