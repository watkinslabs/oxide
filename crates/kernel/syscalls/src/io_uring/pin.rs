// Pinned user memory for registered buffers.
//
// Registering a buffer takes a reference on every frame behind it, exactly
// once, at registration time. Later I/O runs against those frames and never
// re-reads the caller's page tables: a buffer that has been registered stays
// the same physical memory until it is unregistered, whatever the process does
// to its mappings afterwards. Re-validating the user range per use instead
// would let an `munmap` + fresh `mmap` between registration and I/O silently
// retarget a registered buffer at unrelated pages.
//
// The pages are reached through the kernel's direct map for the I/O itself, so
// no user mapping has to exist at the moment the transfer runs.

use alloc::vec::Vec;

use syscall::errno::Errno;

/// Bytes per pinned page.
const PAGE: u64 = hal::PAGE_SIZE_BYTES;

/// A registered buffer: the caller's range, and one physical frame per page of
/// it, each holding an object reference for the buffer's whole lifetime.
pub struct PinnedRange {
    /// Start of the caller's range, byte-exact (not page-aligned).
    pub base: u64,
    pub len: u64,
    /// Frames covering `[base & !(PAGE-1), base + len)`, in order.
    pages: Vec<u64>,
}

/// Fault a user range in and take a reference on each of its frames.
/// # C: O(len / PAGE)
fn pin_pages(base: u64, len: u64) -> Result<Vec<u64>, Errno> {
    use vmm::vma::VmaProt;
    let first = base & !(PAGE - 1);
    let last  = (base + len - 1) & !(PAGE - 1);
    let count = ((last - first) / PAGE + 1) as usize;
    let mut pages: Vec<u64> = Vec::new();
    if pages.try_reserve_exact(count).is_err() { return Err(Errno::Enomem); }

    let Some(cur) = sched::live::current() else { return Err(Errno::Efault) };
    // SAFETY: running task on this CPU; single-mutator mm slot; the address space outlives this call.
    let Some(mm) = (unsafe { cur.mm_ref() }) else { return Err(Errno::Efault) };
    let hhdm = pmm::user_as::hhdm_offset();
    let root = mm.root_pa();

    let mut va = first;
    while va <= last {
        let Some(uva) = hal::UserVirtAddr::new(va) else { return Err(Errno::Efault) };
        // Registration pins for both directions, so the page must be present
        // and writable before the reference is taken.
        if pmm::user_as::populate_current_range(uva, PAGE as usize, VmaProt::READ | VmaProt::WRITE).is_err() {
            unpin_pages(&pages);
            return Err(Errno::Efault);
        }
        let pa = match translate(root, va, hhdm) {
            Some(pa) => pa,
            None => { unpin_pages(&pages); return Err(Errno::Efault); }
        };
        // SAFETY: pa is a live user frame just faulted in; this takes the buffer's own object reference, released in unpin_pages.
        unsafe { pmm::setup::inc_object_ref(pa); }
        pages.push(pa);
        va += PAGE;
    }
    Ok(pages)
}

/// Drop the reference this range holds on each frame. # C: O(N_pages)
fn unpin_pages(pages: &[u64]) {
    for &pa in pages {
        // SAFETY: each pa took exactly one object reference in pin_pages; this releases that one reference.
        unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
    }
}

#[cfg(target_arch = "x86_64")]
fn translate(root: u64, va: u64, hhdm: u64) -> Option<u64> {
    // SAFETY: root is the running task's live top-level table and HHDM covers page-table memory; the walk only reads entries.
    unsafe { hal::pt_walker::translate_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(root, va, hhdm).map(|(pa, _)| pa) }
}

#[cfg(target_arch = "aarch64")]
fn translate(root: u64, va: u64, hhdm: u64) -> Option<u64> {
    // SAFETY: root is the running task's live top-level table and HHDM covers page-table memory; the walk only reads entries.
    unsafe { hal::pt_walker::translate_4k_at_root::<hal_aarch64::vmm::PtWalkerArm>(root, va, hhdm).map(|(pa, _)| pa) }
}

impl PinnedRange {
    /// Pin one registered buffer. A zero-length entry with a null base is the
    /// legal empty slot and pins nothing. # C: O(len / PAGE)
    pub fn pin(base: u64, len: u64) -> Result<Self, Errno> {
        if base == 0 && len == 0 { return Ok(Self { base: 0, len: 0, pages: Vec::new() }); }
        if len == 0 { return Err(Errno::Efault); }
        base.checked_add(len).ok_or(Errno::Efault)?;
        let pages = pin_pages(base, len)?;
        Ok(Self { base, len, pages })
    }

    /// Whether this is the empty slot. # C: O(1)
    pub fn is_empty(&self) -> bool { self.len == 0 }

    /// Run `f` over each direct-map chunk of `[off, off+n)` inside the buffer,
    /// in order. `f` returns how many bytes it consumed; a short chunk ends the
    /// walk, which is what makes a short read stop copying. # C: O(n / PAGE)
    pub fn for_each_chunk(&self, off: u64, n: u64, mut f: impl FnMut(&mut [u8]) -> Option<usize>)
        -> Result<usize, Errno>
    {
        let end = off.checked_add(n).ok_or(Errno::Efault)?;
        if end > self.len { return Err(Errno::Efault); }
        let hhdm = pmm::user_as::hhdm_offset();
        let mut done: usize = 0;
        let mut cur = self.base + off;
        while done < n as usize {
            let page_ix = ((cur & !(PAGE - 1)) - (self.base & !(PAGE - 1))) / PAGE;
            let Some(&pa) = self.pages.get(page_ix as usize) else { return Err(Errno::Efault) };
            let in_page = cur & (PAGE - 1);
            let room = (PAGE - in_page) as usize;
            let want = core::cmp::min(room, n as usize - done);
            let ptr = (pa + hhdm + in_page) as *mut u8;
            // SAFETY: pa is a frame this range pinned, mapped for the whole kernel lifetime through the direct map; in_page+want stays inside that one frame.
            let chunk = unsafe { core::slice::from_raw_parts_mut(ptr, want) };
            let Some(got) = f(chunk) else { break };
            done += got;
            cur += got as u64;
            if got < want { break; }
        }
        Ok(done)
    }
}

impl Drop for PinnedRange {
    /// # C: O(N_pages)
    fn drop(&mut self) { unpin_pages(&self.pages); }
}
