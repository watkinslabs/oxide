// The staged image: control pages, the source pages segments are copied into,
// and the relocation list the trampoline walks.
//
// The relocation list is a self-contained chain of `u64` entries, tagged in
// their low bits (`IND_*`), living in pages the image owns. It has to be
// self-contained because it is read AFTER this kernel has stopped running:
// nothing in it may be a virtual address or point at kernel data structures.
//
//   head ──IND_INDIRECTION──▶ [ dest|IND_DESTINATION, src|IND_SOURCE, …,
//                               next_page|IND_INDIRECTION ]
//                                                       └─▶ [ … , IND_DONE ]
//
// The invariant the whole staging algorithm exists to maintain: a SOURCE page
// is either its own destination page, or not a destination page at all. Break
// it and the trampoline overwrites a source page it has not copied yet, and
// the new kernel starts from a corrupt image with no diagnostic anywhere.

extern crate alloc;
use alloc::vec::Vec;

use crate::frames::{clear_page, copy_page, Frames};
use crate::uapi::*;
use crate::validate::{Error, KResult};

/// Where a relocation entry lives, so it can be rewritten in place.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Loc {
    /// `image->head`, the list's first entry.
    Head,
    /// Slot `idx` of the indirection page at `pa`.
    Page(u64, usize),
}

/// Destination sentinel for a page whose address does not matter.
const NO_DEST: u64 = u64::MAX;

/// A staged kexec image.
pub struct KImage {
    /// Entry point the trampoline jumps to once relocation is complete.
    pub start: u64,
    /// Default (reboot) or crash image.
    pub ty: ImageType,
    /// First relocation entry.
    pub head: u64,
    /// Page holding the arch trampoline.
    pub control_code_page: u64,
    /// Scratch page the trampoline uses to swap a page with its destination.
    pub swap_page: u64,
    /// Physical root of the identity page tables the trampoline runs under,
    /// built by `machine::prepare` at LOAD time out of control pages.
    pub arch_pgt: u64,
    /// Byte offset within the control page of the half of the trampoline that
    /// runs identity-mapped. Zero on an architecture whose trampoline is
    /// entered identity-mapped from its first instruction.
    pub arch_entry_off: u64,
    /// The caller's segment list, as validated.
    pub segments: Vec<KexecSegment>,
    /// `KEXEC_PRESERVE_CONTEXT` was requested.
    pub preserve_context: bool,
    cursor: Loc,
    control_pages: Vec<u64>,
    dest_pages: Vec<u64>,
    unusable_pages: Vec<u64>,
    source_pages: Vec<u64>,
    ind_pages: Vec<u64>,
}

impl KImage {
    /// Empty image, before any page is allocated. `head == 0` and the cursor
    /// sits on it, which is the state `kimage_add_entry` expects.
    /// # C: O(1)
    pub fn new(start: u64, ty: ImageType, segments: Vec<KexecSegment>) -> Self {
        Self {
            start, ty, head: 0, control_code_page: 0, swap_page: 0,
            arch_pgt: 0, arch_entry_off: 0, segments,
            preserve_context: false, cursor: Loc::Head,
            control_pages: Vec::new(), dest_pages: Vec::new(),
            unusable_pages: Vec::new(), source_pages: Vec::new(), ind_pages: Vec::new(),
        }
    }

    /// Pages this image currently holds, over every list. Staging correctness
    /// is a page-accounting property, so the count is part of the surface the
    /// tests assert on rather than a debug afterthought.
    /// # C: O(1)
    pub fn page_count(&self) -> usize {
        self.control_pages.len() + self.dest_pages.len() + self.unusable_pages.len()
            + self.source_pages.len() + self.ind_pages.len()
    }

    /// Release every page back to the supplier. Explicit rather than `Drop`
    /// because the supplier is not reachable from the image.
    /// # C: O(N_pages)
    pub fn free<F: Frames>(&mut self, f: &mut F) {
        // Undo the arch's mapping changes FIRST. A control page whose kernel
        // mapping was narrowed for the trampoline must be back at the linear
        // map's default before the allocator can hand it to anyone else.
        crate::machine::cleanup(self);
        for list in [&mut self.control_pages, &mut self.dest_pages, &mut self.unusable_pages,
                     &mut self.source_pages, &mut self.ind_pages] {
            for pa in list.drain(..) {
                // SAFETY: every page in these lists came from `F::alloc` on this
                // supplier, and the image is being torn down — no relocation
                // entry survives this call.
                unsafe { f.free(pa) };
            }
        }
        self.head = 0;
        self.cursor = Loc::Head;
        self.control_code_page = 0;
        self.swap_page = 0;
        self.arch_pgt = 0;
        self.arch_entry_off = 0;
    }

    /// True when `[start, end]` intersects any segment's destination range.
    /// # C: O(nr_segments)
    pub fn is_destination_range(&self, start: u64, end: u64) -> bool {
        self.segments.iter().any(|s| {
            let mstart = s.mem;
            let mend = s.mem + s.memsz.saturating_sub(1);
            s.memsz != 0 && end >= mstart && start <= mend
        })
    }

    // --- relocation list ---------------------------------------------------

    fn read(&self, f: &impl Frames, at: Loc) -> u64 {
        match at {
            Loc::Head => self.head,
            Loc::Page(pa, idx) => match f.ptr(pa) {
                // SAFETY: `pa` is an image-owned indirection page and `idx` is
                // below ENTRIES_PER_PAGE, so the read is inside one page.
                Some(p) => unsafe { (p as *const u64).add(idx).read() },
                None => 0,
            },
        }
    }

    fn write(&mut self, f: &impl Frames, at: Loc, v: u64) {
        match at {
            Loc::Head => self.head = v,
            Loc::Page(pa, idx) => if let Some(p) = f.ptr(pa) {
                // SAFETY: `pa` is an image-owned indirection page and `idx` is
                // below ENTRIES_PER_PAGE, so the write is inside one page.
                unsafe { (p as *mut u64).add(idx).write(v) };
            },
        }
    }

    /// True when the cursor sits on the LAST usable slot of its page, i.e. the
    /// next entry must be an indirection to a fresh page. `Head` is a single
    /// slot, so it is always full.
    fn cursor_is_last(&self) -> bool {
        match self.cursor {
            Loc::Head => true,
            Loc::Page(_, idx) => idx == ENTRIES_PER_PAGE - 1,
        }
    }

    fn advance(&mut self) {
        if let Loc::Page(pa, idx) = self.cursor { self.cursor = Loc::Page(pa, idx + 1); }
    }

    /// `kimage_add_entry`. Grows the list by an indirection page when the
    /// current page is full; the LAST slot of every page is reserved for that
    /// indirection so the chain is always walkable.
    /// # C: O(N_pages) worst case through `alloc_page`
    fn add_entry<F: Frames>(&mut self, f: &mut F, entry: u64) -> KResult<()> {
        if self.read(f, self.cursor) != 0 { self.advance(); }
        if self.cursor_is_last() {
            let pa = self.alloc_page(f, NO_DEST).ok_or(Error::Nomem)?;
            self.ind_pages.push(pa);
            clear_page(f, pa);
            let cur = self.cursor;
            self.write(f, cur, pa | IND_INDIRECTION);
            self.cursor = Loc::Page(pa, 0);
        }
        let cur = self.cursor;
        self.write(f, cur, entry);
        self.advance();
        let next = self.cursor;
        self.write(f, next, 0);
        Ok(())
    }

    /// `kimage_set_destination`.
    /// # C: O(N_pages)
    pub fn set_destination<F: Frames>(&mut self, f: &mut F, dest: u64) -> KResult<()> {
        self.add_entry(f, (dest & PAGE_MASK) | IND_DESTINATION)
    }

    /// `kimage_add_page`.
    /// # C: O(N_pages)
    pub fn add_page<F: Frames>(&mut self, f: &mut F, page: u64) -> KResult<()> {
        self.add_entry(f, (page & PAGE_MASK) | IND_SOURCE)
    }

    /// `kimage_terminate`: close the list with `IND_DONE`. Every walk stops
    /// there, so an image that is never terminated relocates whatever stale
    /// bytes follow it.
    /// # C: O(1)
    pub fn terminate(&mut self, f: &impl Frames) {
        if self.read(f, self.cursor) != 0 { self.advance(); }
        let cur = self.cursor;
        self.write(f, cur, IND_DONE);
    }

    /// Walk the relocation list, calling `visit(location, entry)` until it
    /// returns false or the list ends.
    /// # C: O(N_entries)
    fn for_each_entry(&self, f: &impl Frames, mut visit: impl FnMut(Loc, u64) -> bool) {
        let mut at = Loc::Head;
        loop {
            let entry = self.read(f, at);
            if entry == 0 || entry & IND_DONE != 0 { return; }
            if !visit(at, entry) { return; }
            at = if entry & IND_INDIRECTION != 0 {
                Loc::Page(entry & PAGE_MASK, 0)
            } else {
                match at { Loc::Head => return, Loc::Page(pa, idx) => Loc::Page(pa, idx + 1) }
            };
        }
    }

    /// Collect the list as `(entry, running destination)` pairs — the exact
    /// view the trampoline has. Test-facing, and the only way to assert the
    /// chain is well formed without a boot.
    /// # C: O(N_entries)
    pub fn relocation_entries(&self, f: &impl Frames) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let mut dest = 0u64;
        self.for_each_entry(f, |_, e| {
            if e & IND_DESTINATION != 0 { dest = e & PAGE_MASK; }
            out.push((e, dest));
            if e & IND_SOURCE != 0 { dest += PAGE_SIZE; }
            true
        });
        out
    }

    /// `kimage_dst_used`: the entry whose destination is `page`, if the image
    /// already stages a source for it.
    /// # C: O(N_entries)
    fn dst_used(&self, f: &impl Frames, page: u64) -> Option<Loc> {
        let mut dest = 0u64;
        let mut found = None;
        self.for_each_entry(f, |at, e| {
            if e & IND_DESTINATION != 0 { dest = e & PAGE_MASK; }
            else if e & IND_SOURCE != 0 {
                if page == dest { found = Some(at); return false; }
                dest += PAGE_SIZE;
            }
            true
        });
        found
    }

    /// `kimage_alloc_page`: a page usable as the source for `destination`.
    ///
    /// The three outcomes, in the order they are tried:
    /// 1. a page already parked on the destination list IS the destination —
    ///    use it directly;
    /// 2. a freshly allocated page that is either the destination itself or
    ///    outside every destination range — use it;
    /// 3. a freshly allocated page that lands on SOMEONE ELSE'S destination —
    ///    if that destination already has a source, copy into the new page and
    ///    hand the old source over, which restores the invariant; otherwise
    ///    park the page and try again.
    /// # C: O(N_entries) per attempt, O(N^2) worst case over a whole image
    fn alloc_page<F: Frames>(&mut self, f: &mut F, destination: u64) -> Option<u64> {
        if let Some(i) = self.dest_pages.iter().position(|&p| p == destination) {
            return Some(self.dest_pages.remove(i));
        }
        loop {
            let page = f.alloc()?;
            if page > f.source_limit() { self.unusable_pages.push(page); continue; }
            if page == destination { return Some(page); }
            if !self.is_destination_range(page, page + PAGE_SIZE - 1) { return Some(page); }
            match self.dst_used(f, page) {
                Some(at) => {
                    let old = self.read(f, at);
                    let old_page = old & PAGE_MASK;
                    copy_page(f, page, old_page);
                    self.write(f, at, page | (old & !PAGE_MASK));
                    if let Some(i) = self.source_pages.iter().position(|&p| p == old_page) {
                        self.source_pages[i] = page;
                    }
                    return Some(old_page);
                }
                None => self.dest_pages.push(page),
            }
        }
    }

    /// `kimage_alloc_control_pages` for the normal (non-crash) image: keep
    /// allocating until a page lands outside every destination range, then
    /// return the rejects.
    ///
    /// A control page that overlapped a destination would be overwritten by
    /// the relocation it is itself performing — the trampoline would copy a
    /// segment over its own instruction stream.
    /// # C: O(N_attempts * nr_segments)
    pub fn alloc_control_page<F: Frames>(&mut self, f: &mut F) -> KResult<u64> {
        let mut extra: Vec<u64> = Vec::new();
        let mut got = None;
        while got.is_none() {
            let page = match f.alloc() { Some(p) => p, None => break };
            if page + PAGE_SIZE - 1 >= f.control_limit()
                || self.is_destination_range(page, page + PAGE_SIZE - 1) {
                extra.push(page);
            } else {
                got = Some(page);
            }
        }
        for p in extra {
            // SAFETY: `p` came from `F::alloc` moments ago and was never linked
            // into a relocation entry or any image list.
            unsafe { f.free(p) };
        }
        let page = got.ok_or(Error::Nomem)?;
        self.control_pages.push(page);
        Ok(page)
    }
}

/// Where a segment's bytes come from: user memory for `kexec_load`, a kernel
/// buffer for `kexec_file_load`.
pub trait SegmentSource {
    /// Read `dst.len()` bytes from the segment whose `buf` field is `buf`,
    /// `off` bytes in.
    ///
    /// `buf` is passed per call rather than captured because every segment of
    /// one image names its OWN source buffer — a source that remembered a
    /// single base would fill every segment after the first from the wrong
    /// address, and the result is an image that boots into the wrong bytes.
    fn read_at(&self, buf: u64, off: u64, dst: &mut [u8]) -> KResult<()>;
}

/// `kimage_load_segment` for a default-type image.
///
/// Every destination page gets a source page: allocated, cleared, then filled
/// with up to `PAGE_SIZE` bytes from the segment buffer. The tail beyond
/// `bufsz` stays zero — that is how `.bss` arrives zeroed in the new kernel,
/// and skipping the clear would hand it this kernel's freed heap.
/// # C: O(memsz)
pub fn load_segment<F: Frames, S: SegmentSource>(
    image: &mut KImage, f: &mut F, idx: usize, src: &S,
) -> KResult<()> {
    let seg = image.segments[idx];
    let (mut maddr, mut mbytes, mut ubytes, mut uoff) = (seg.mem, seg.memsz, seg.bufsz, 0u64);
    image.set_destination(f, maddr)?;
    while mbytes != 0 {
        let page = image.alloc_page(f, maddr).ok_or(Error::Nomem)?;
        image.source_pages.push(page);
        image.add_page(f, page)?;
        clear_page(f, page);
        let mchunk = core::cmp::min(mbytes, PAGE_SIZE);
        let uchunk = core::cmp::min(ubytes, mchunk);
        if uchunk != 0 {
            let p = f.ptr(page).ok_or(Error::Nomem)?;
            // SAFETY: `page` is an image-owned staging page of PAGE_SIZE bytes and
            // `uchunk <= PAGE_SIZE`; the image holds it exclusively until relocation.
            let dst = unsafe { core::slice::from_raw_parts_mut(p, uchunk as usize) };
            src.read_at(seg.buf, uoff, dst)?;
            ubytes -= uchunk;
            uoff += uchunk;
        }
        maddr += mchunk;
        mbytes -= mchunk;
    }
    Ok(())
}
