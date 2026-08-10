// `mmap(2)` on a `perf_event_open` fd — Linux `perf_mmap`.
//
// The ring pages are REFCOUNTED kernel RAM (`alloc_object_frame`), so they go
// through the file-backed shared-frame path: the fault installs one PTE
// reference per page and munmap/AS-teardown releases it, so a page cannot be
// freed while userspace still maps it. A phys-range mapping
// (`remap_pfn_range`) counts NO reference and would reproduce the io_uring
// free-while-mapped UAF exactly.

use alloc::sync::Arc;

use fs::perf::ring::sizing::{MlockCtx, PAGE_BYTES};
use fs::perf::mmap::MmapCtx;
use fs::perf::PerfBuffer;
use fs::perf::PerfEvent;

/// `PROT_WRITE`.
const PROT_WRITE: u64 = 2;

struct PerfRingBacking {
    rb:   Arc<PerfBuffer>,
    file: Arc<vfs::File>,
    /// The event whose ring this is. Held directly: the last unmap detaches
    /// the buffer from it, and looking the event up again through the inode
    /// would be a second path to the same object.
    ev:   Arc<PerfEvent>,
    /// The address space this mapping belongs to, captured at `mmap(2)` time.
    /// The pinned-page charge is booked against THIS mm and given back to it,
    /// whichever context runs the final unmap — a teardown that ran against
    /// whatever mm happened to be current would leak the charge on one mm and
    /// under-run it on another.
    mm:   Option<Arc<vmm::AddressSpace>>,
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

    /// Every VMA birth on this ring — the establishing mapping, a split
    /// fragment — is counted, and an open with a charge pending books both the
    /// per-user pages and the pages pinned against this mm.
    fn vma_open(&self) {
        let pinned = fs::perf::mmap::vma_opened(&self.ev, &self.rb);
        if pinned != 0 { if let Some(mm) = self.mm.as_ref() { mm.charge_pinned(pinned); } }
    }

    /// The last mapping gives both halves back, so a process that cycles perf
    /// mappings does not walk its own allowance — or its mm's memory-lock
    /// headroom — to zero.
    fn vma_close(&self) {
        let pinned = fs::perf::mmap::vma_closed(&self.ev, &self.rb);
        if pinned != 0 { if let Some(mm) = self.mm.as_ref() { mm.release_pinned(pinned); } }
    }

    /// `perf_mmap_may_split`: the reference forbids splitting a perf mapping
    /// outright, because the fragments carry sizes and offsets the ring's
    /// accounting was never taken for. A partial `munmap`/`mprotect`/`mremap`
    /// of the ring is `EINVAL`.
    fn may_split(&self) -> bool { false }
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
        uid:      current_uid(),
        mlock:    mlock_ctx(vma_pages),
    };
    match fs::perf::mmap::attach(&ev, &ctx, wakeup_watermark(&ev)) {
        Ok(rb)     => Some(Ok(Arc::new(PerfRingBacking { rb, file: file.clone(), ev, mm: current_mm() }))),
        Err(errno) => Some(Err(-(errno.as_i32() as i64))),
    }
}

/// `attr.wakeup_events`/`wakeup_watermark` share one `u32` slot; only the
/// watermark reading is a byte count, and only when `attr.watermark` is set.
fn wakeup_watermark(ev: &Arc<fs::perf::PerfEvent>) -> u32 { ev.attr.wakeup_events }

/// `current_user()` — the REAL uid, which is the account Linux keys
/// `user_struct` on. A task that has dropped privileges still charges the user
/// it runs as.
fn current_uid() -> u32 {
    sched::live::current()
        .map_or(0, |c| c.creds.ruid.load(core::sync::atomic::Ordering::Acquire))
}

/// `perf_mmap_calc_limits`' live inputs. `user->locked_vm` is filled in by
/// `fs::perf::mmap::attach` from the live per-user ledger — the one place that
/// total exists.
/// The address space the calling task is mapping into.
fn current_mm() -> Option<Arc<vmm::AddressSpace>> {
    let cur = sched::live::current()?;
    // SAFETY: reads the CURRENT task's own mm slot, which only that task
    // replaces, from inside its own mmap(2); the Arc is cloned out before the
    // borrow ends (single-mutator mm slot, `13§5`).
    unsafe { cur.mm_ref() }.cloned()
}

fn mlock_ctx(vma_pages: u64) -> MlockCtx {
    let cur = sched::live::current();
    MlockCtx {
        vma_pages,
        user_locked:    0,  // attach() supplies the live total
        mlock_kb:       sched::perf_sw::mlock_kb(),
        nr_online_cpus: cpu::count().max(1) as u64,
        // The mm's running pinned total. A zero placeholder here made the
        // memory-lock half of the ladder compare every mapping against nothing,
        // so several large mappings in one mm were all admitted.
        pinned_vm:      current_mm().map_or(0, |m| m.pinned_pages()),
        rlimit_pages:   cur.as_ref()
            .map_or(0, |c| c.rlimit(sched::rlimit::rlim::MEMLOCK).0 / PAGE_BYTES),
        paranoid:       sched::perf_sw::paranoid() > -1,
        cap_ipc_lock:   cur.as_ref().is_some_and(|c| c.has_cap(sched::cap::IPC_LOCK)),
    }
}
