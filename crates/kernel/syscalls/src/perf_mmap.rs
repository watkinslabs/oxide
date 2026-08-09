// `mmap(2)` on a `perf_event_open` fd — Linux `perf_mmap`.
//
// The ring pages are REFCOUNTED kernel RAM (`alloc_object_frame`), so they go
// through the file-backed shared-frame path: the fault installs one PTE
// reference per page and munmap/AS-teardown releases it, so a page cannot be
// freed while userspace still maps it. A phys-range mapping
// (`remap_pfn_range`) counts NO reference and would reproduce the io_uring
// free-while-mapped UAF exactly.

use alloc::sync::Arc;

use fs::perf::ring::sizing::{MlockCtx, MLOCK_KB_DEFAULT, PAGE_BYTES};
use fs::perf::mmap::MmapCtx;
use fs::perf::PerfBuffer;

/// `PROT_WRITE`.
const PROT_WRITE: u64 = 2;

struct PerfRingBacking {
    rb:   Arc<PerfBuffer>,
    file: Arc<vfs::File>,
}

impl vmm::FileBacking for PerfRingBacking {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, vmm::FileBackingError> {
        Err(vmm::FileBackingError::Io)
    }
    fn size_hint(&self) -> u64 { self.rb.size() }
    fn ino(&self) -> u64 { self.file.inode().ino() }
    fn shared_frame(&self, off: u64) -> Result<Option<vmm::SharedFrame>, vmm::FileBackingError> {
        Ok(self.rb.frame(off / PAGE_BYTES)
            .map(|pa| vmm::SharedFrame { pa, map_ref_held: false }))
    }
    fn direct_frame(&self, off: u64) -> Option<u64> { self.rb.frame(off / PAGE_BYTES) }
}

/// Resolve a perf-fd mapping, allocating the ring on first `mmap`.
/// `None` = not a perf fd. # C: O(mapped pages)
pub(crate) fn backing(file: &Arc<vfs::File>, off: u64, len: u64, prot: u64, flags: u64)
    -> Option<Result<Arc<dyn vmm::FileBacking>, i64>>
{
    let inode = file.inode();
    let ev = fs::perf::event_of(&inode)?;
    let shared = pmm::mmap_flags::map_type(flags).map(|_| flags & pmm::mmap_flags::MAP_SHARED != 0);
    let shared = match shared { Ok(s) => s, Err(error) => return Some(Err(error)) };
    let vma_pages = len.div_ceil(PAGE_BYTES);
    let ctx = MmapCtx {
        vma_pages,
        pgoff:    off / PAGE_BYTES,
        shared,
        writable: prot & PROT_WRITE != 0,
        mlock:    mlock_ctx(vma_pages),
    };
    match fs::perf::mmap::attach(&ev, &ctx, wakeup_watermark(&ev)) {
        Ok(rb)     => Some(Ok(Arc::new(PerfRingBacking { rb, file: file.clone() }))),
        Err(errno) => Some(Err(-(errno.as_i32() as i64))),
    }
}

/// `attr.wakeup_events`/`wakeup_watermark` share one `u32` slot; only the
/// watermark reading is a byte count, and only when `attr.watermark` is set.
fn wakeup_watermark(ev: &Arc<fs::perf::PerfEvent>) -> u32 { ev.attr.wakeup_events }

/// `perf_mmap_calc_limits`' live inputs. `user->locked_vm` is per-user in the
/// reference; oxide has no `user_struct` accumulator, so the per-user ledger
/// starts empty for every mapping and only the `RLIMIT_MEMLOCK` half of the
/// ladder can refuse — recorded in `scratch/known_issues.md`.
fn mlock_ctx(vma_pages: u64) -> MlockCtx {
    let cur = sched::live::current();
    MlockCtx {
        vma_pages,
        user_locked:    0,
        mlock_kb:       MLOCK_KB_DEFAULT,
        nr_online_cpus: cpu::count().max(1) as u64,
        pinned_vm:      0,
        rlimit_pages:   cur.as_ref()
            .map_or(0, |c| c.rlimit(sched::rlimit::rlim::MEMLOCK).0 / PAGE_BYTES),
        paranoid:       sched::perf_sw::paranoid() > -1,
        cap_ipc_lock:   cur.as_ref().is_some_and(|c| c.has_cap(sched::cap::IPC_LOCK)),
    }
}
