// The live, frame-backed ring — Linux `struct perf_buffer` (`rb_alloc`,
// `rb_free`, `perf_mmap_to_page`, `perf_output_{begin,copy,end}`).
//
// The pages are REFCOUNTED kernel RAM (`alloc_object_frame`), so a user
// mapping of them must take a mapping reference per PTE and release it on
// unmap: a page handed to userspace without one is freed while still mapped
// the moment the fd closes. `frame()` therefore feeds the file-backed
// shared-frame path, never a phys-range mapping.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{fence, AtomicU32, Ordering};

use sync::{PerfRing, Spinlock};

use super::super::sample::RecordBuf;
use super::sizing::{data_size, PAGE_BYTES};
use super::state::{copy_plan, RingState};
use super::userpage;

/// `EPOLLIN | EPOLLRDNORM` — what `perf_output_wakeup` publishes.
const POLL_READY: u32 = vfs::POLL_IN | vfs::POLL_RDNORM;

/// Where the ring's pages live. The kernel backs them with PMM object frames;
/// hosted tests back them with heap pages so the ENTIRE record path — the
/// reservation, the page-crossing copy, the wrap and the control-page
/// publication — runs against real memory without a booted PMM.
enum Pages {
    Frames(Vec<u64>),
    #[cfg(test)]
    Heap(Vec<alloc::boxed::Box<[u8]>>),
}

impl Pages {
    fn len(&self) -> usize {
        match self {
            Pages::Frames(v) => v.len(),
            #[cfg(test)]
            Pages::Heap(v)   => v.len(),
        }
    }
    fn ptr(&self, i: usize) -> Option<*mut u8> {
        match self {
            Pages::Frames(v) => pmm::setup::frame_ptr(*v.get(i)?),
            #[cfg(test)]
            Pages::Heap(v)   => Some(v.get(i)?.as_ptr() as *mut u8),
        }
    }
}

/// Outcome of a successful [`PerfBuffer::output`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wrote {
    /// The record crossed `rb->wakeup`, so `perf_output_wakeup` ran.
    pub wakeup: bool,
}

pub struct PerfBuffer {
    /// Page 0 of the mapping: `struct perf_event_mmap_page`.
    user:  Pages,
    /// `rb->data_pages[]` — `2^n` pages, or empty for a control-page-only ring.
    data:  Pages,
    state: Spinlock<RingState, PerfRing>,
    /// `rb->poll`, latched by a watermark crossing and cleared by `poll(2)`.
    poll:  AtomicU32,
}

impl PerfBuffer {
    /// `rb_alloc(nr_pages, watermark, cpu, flags)`. `nr_data_pages` must
    /// already have passed [`super::sizing::data_pages`]. `overwrite` is the
    /// reference's `!(flags & RING_BUFFER_WRITABLE)` — a read-only mapping
    /// never consults the consumer's tail. # C: O(nr_data_pages)
    pub fn alloc(nr_data_pages: u64, watermark_req: u64, overwrite: bool) -> Option<Arc<PerfBuffer>> {
        let user_pa = pmm::setup::alloc_object_frame()?;
        let mut data = Vec::new();
        if data.try_reserve_exact(nr_data_pages as usize).is_err() {
            release(user_pa);
            return None;
        }
        for _ in 0..nr_data_pages {
            match pmm::setup::alloc_object_frame() {
                Some(pa) => data.push(pa),
                None => {
                    for pa in data { release(pa); }
                    release(user_pa);
                    return None;
                }
            }
        }
        Some(Self::build(Pages::Frames(alloc::vec![user_pa]), Pages::Frames(data),
                         watermark_req, overwrite))
    }

    fn build(user: Pages, data: Pages, watermark_req: u64, overwrite: bool) -> Arc<PerfBuffer> {
        let ds = data_size(data.len() as u64);
        let rb = PerfBuffer {
            user, data,
            state: Spinlock::new(RingState::new(ds, watermark_req, overwrite)),
            poll:  AtomicU32::new(0),
        };
        rb.zero_data();
        rb.with_user_page(|p| userpage::init(p, ds));
        Arc::new(rb)
    }

    /// Heap-backed ring for hosted tests — same code path, no PMM. # C: O(pages)
    #[cfg(test)]
    pub fn hosted(nr_data_pages: u64, watermark_req: u64, overwrite: bool) -> Arc<PerfBuffer> {
        let page = || alloc::vec![0u8; PAGE_BYTES as usize].into_boxed_slice();
        let data = (0..nr_data_pages).map(|_| page()).collect();
        Self::build(Pages::Heap(alloc::vec![page()]), Pages::Heap(data), watermark_req, overwrite)
    }

    /// `perf_mmap_to_page(rb, pgoff)` — page 0 is the control page, the rest
    /// are data pages. `None` past the end is the reference's `-EINVAL`.
    /// # C: O(1)
    pub fn frame(&self, pgoff: u64) -> Option<u64> {
        let (pages, i) = if pgoff == 0 { (&self.user, 0) } else { (&self.data, (pgoff - 1) as usize) };
        match pages {
            Pages::Frames(v) => v.get(i).copied(),
            #[cfg(test)]
            Pages::Heap(_)   => None,
        }
    }

    /// Total mapped bytes: control page + data pages. # C: O(1)
    pub fn size(&self) -> u64 { (self.data.len() as u64 + 1) * PAGE_BYTES }

    /// `perf_data_size(rb)`. # C: O(1)
    pub fn data_size(&self) -> u64 { data_size(self.data.len() as u64) }

    /// `data_page_nr(rb)` — what `perf_mmap_rb` compares a re-mmap against.
    /// # C: O(1)
    pub fn nr_data_pages(&self) -> u64 { self.data.len() as u64 }

    /// `rb_toggle_paused`. # C: O(1)
    pub fn set_paused(&self, paused: bool) {
        let mut g = self.state.lock();
        // A ring with no data pages is permanently paused; un-pausing it would
        // let `reserve` run against a zero-length buffer.
        if self.data.len() == 0 { return; }
        g.paused = paused;
    }

    /// `perf_event_update_userpage` — publish the counter snapshot userspace
    /// reads out of the control page without a syscall. # C: O(1)
    pub fn update_userpage(&self, count: u64, time_enabled: u64, time_running: u64) {
        self.with_user_page(|p| {
            // The seqlock's odd phase must be visible before the payload it
            // guards, and the payload before the even phase that publishes it.
            let seq = userpage::seq(p);
            let _ = seq;
            fence(Ordering::Release);
            userpage::update(p, count, time_enabled, time_running);
            fence(Ordering::Release);
        });
    }

    /// Read `len` bytes of the data area back, for tests that must inspect the
    /// exact record a producer wrote. # C: O(len)
    #[cfg(test)]
    pub fn peek_data(&self, at: u64, len: usize) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::new();
        for i in 0..len as u64 {
            let pos = (at + i) & (self.data_size() - 1);
            let Some(p) = self.data.ptr((pos / PAGE_BYTES) as usize) else { break };
            // SAFETY: test-only read of one buffer-owned data page, at an
            // offset masked into that page.
            out.push(unsafe { *p.add((pos % PAGE_BYTES) as usize) });
        }
        out
    }

    /// `perf_poll`'s `atomic_xchg(&rb->poll, 0)`. # C: O(1)
    pub fn take_poll(&self) -> u32 { self.poll.swap(0, Ordering::AcqRel) }

    /// Unconsumed bytes in the ring — `data_head - data_tail`. # C: O(1)
    pub fn unread(&self) -> u64 {
        let head = self.state.lock().head;
        head.wrapping_sub(self.data_tail())
    }

    /// `perf_output_begin` + `perf_output_copy` + `perf_output_end` for one
    /// complete record, prepending the `PERF_RECORD_LOST` the reference emits
    /// once records have been dropped. Both records land in ONE reservation so
    /// a consumer never sees a sample whose loss report was itself lost.
    ///
    /// `None` == the reference's `-ENOSPC`: the record is dropped and counted,
    /// so the next successful one carries it. `Some(w)` reports whether this
    /// record crossed the wakeup watermark — `perf_output_wakeup`'s trigger,
    /// which the caller turns into the poll wake and `SIGIO` the reference's
    /// `irq_work` delivers.
    /// # C: O(record bytes)
    pub fn output<F, const N: usize>(&self, sample: &[u8], build_lost: F) -> Option<Wrote>
    where F: FnOnce(u64) -> Option<RecordBuf<N>>
    {
        let tail = self.data_tail();
        let mut g = self.state.lock();
        let pending = g.lost;
        let lost_rec = if pending != 0 { build_lost(pending) } else { None };
        let lost_len = lost_rec.as_ref().map_or(0, |r| r.len());
        let total = (sample.len() + lost_len) as u64;
        let res = match g.reserve(tail, total) { Ok(r) => r, Err(()) => return None };
        if lost_rec.is_some() { g.take_lost(); }
        let head = g.head;
        if let Some(r) = lost_rec.as_ref() { self.write_at(res.offset, r.as_slice()); }
        self.write_at(res.offset + lost_len as u64, sample);
        // (B) The record bytes must be visible before the head that advertises
        // them; userspace pairs this with a read barrier after loading
        // `data_head`.
        fence(Ordering::Release);
        self.with_user_page(|p| userpage::set_data_head(p, head));
        if res.wakeup { self.poll.store(POLL_READY, Ordering::Release); }
        Some(Wrote { wakeup: res.wakeup })
    }

    /// Drop and count one record without formatting it — the arm
    /// `__perf_output_begin` takes for a paused ring or an over-long record.
    /// # C: O(1)
    pub fn note_lost(&self) { let mut g = self.state.lock(); g.lost = g.lost.saturating_add(1); }

    /// `READ_ONCE(rb->user_page->data_tail)`. # C: O(1)
    fn data_tail(&self) -> u64 { self.with_user_page(|p| userpage::data_tail(p)).unwrap_or(0) }

    fn with_user_page<R>(&self, f: impl FnOnce(&mut [u8]) -> R) -> Option<R> {
        let p = self.user.ptr(0)?;
        // SAFETY: the control page is one buffer-owned page, allocated in
        // `build` and released only in `Drop`, so the whole page is live and
        // exclusively described by this buffer for the call's duration.
        let s = unsafe { core::slice::from_raw_parts_mut(p, PAGE_BYTES as usize) };
        Some(f(s))
    }

    fn zero_data(&self) {
        for i in 0..self.data.len() {
            if let Some(p) = self.data.ptr(i) {
                // SAFETY: a freshly allocated buffer-owned page of exactly
                // `PAGE_BYTES`, not yet published to any mapping.
                unsafe { core::ptr::write_bytes(p, 0, PAGE_BYTES as usize) };
            }
        }
    }

    /// `__output_copy` — one record, split at the ring's wrap boundary.
    fn write_at(&self, offset: u64, src: &[u8]) {
        if src.is_empty() || self.data.len() == 0 { return; }
        let ds = self.data_size();
        let ((s0, n0), (s1, n1)) = copy_plan(offset, src.len() as u64, ds);
        self.copy_linear(s0, &src[..n0 as usize]);
        self.copy_linear(s1, &src[n0 as usize..(n0 + n1) as usize]);
    }

    fn copy_linear(&self, mut at: u64, mut src: &[u8]) {
        while !src.is_empty() {
            let pg = (at / PAGE_BYTES) as usize;
            let off = (at % PAGE_BYTES) as usize;
            let n = core::cmp::min(PAGE_BYTES as usize - off, src.len());
            let Some(p) = self.data.ptr(pg) else { return };
            {
                // SAFETY: a buffer-owned data page kept alive by this buffer;
                // `off + n` is bounded by the page size above.
                unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), p.add(off), n) };
            }
            at += n as u64;
            src = &src[n..];
        }
    }
}

impl Drop for PerfBuffer {
    fn drop(&mut self) {
        for pages in [&self.user, &self.data] {
            match pages {
                Pages::Frames(v) => for &pa in v { release(pa); },
                #[cfg(test)]
                Pages::Heap(_)   => {}
            }
        }
    }
}

fn release(pa: u64) {
    // SAFETY: the buffer holds exactly one allocation reference per frame it
    // listed, taken in `alloc` and dropped exactly once here; a still-live user
    // mapping holds its own PTE reference, so the page outlives it.
    unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_ok(w: Option<Wrote>) -> bool { w.is_some() }

    /// The hosted PMM hands out real frames, so the whole output path —
    /// reservation, page-crossing copy, wrap, control-page publication — runs
    /// here against real memory rather than a model.
    fn read_data(rb: &PerfBuffer, at: u64, len: usize) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::new();
        for i in 0..len as u64 {
            let pos = (at + i) & (rb.data_size() - 1);
            let p = rb.data.ptr((pos / PAGE_BYTES) as usize).unwrap();
            // SAFETY: test-only read of one buffer-owned data page within it.
            out.push(unsafe { *p.add((pos % PAGE_BYTES) as usize) });
        }
        out
    }

    fn set_tail(rb: &PerfBuffer, tail: u64) {
        rb.with_user_page(|p| p[1032..1040].copy_from_slice(&tail.to_le_bytes()));
    }

    fn head(rb: &PerfBuffer) -> u64 { rb.with_user_page(|p| userpage::data_head(p)).unwrap() }

    #[test]
    fn a_record_lands_in_the_data_area_and_publishes_its_head() {
        let rb = PerfBuffer::hosted(2, 0, false);
        assert_eq!(rb.size(), 3 * PAGE_BYTES);
        assert_eq!(rb.data_size(), 2 * PAGE_BYTES);
        // The control page reports the layout before a single record exists.
        assert_eq!(rb.with_user_page(|p| userpage::data_tail(p)), Some(0));
        assert_eq!(head(&rb), 0);

        let rec = [0xABu8; 24];
        assert!(is_ok(rb.output(&rec, |_| None::<crate::perf::sample::RecordBuf>)));
        assert_eq!(head(&rb), 24, "data_head advertises exactly the bytes written");
        assert_eq!(read_data(&rb, 0, 24), rec);
        assert_eq!(rb.unread(), 24);
    }

    #[test]
    fn a_record_that_straddles_the_wrap_is_split_across_both_ends() {
        let rb = PerfBuffer::hosted(1, 0, true);
        let ds = rb.data_size();
        // Park the producer 8 bytes short of the wrap, then write 24.
        rb.state.lock().head = ds - 8;
        let rec: alloc::vec::Vec<u8> = (0u8..24).collect();
        assert!(is_ok(rb.output(&rec, |_| None::<crate::perf::sample::RecordBuf>)));
        assert_eq!(head(&rb), ds + 16);
        assert_eq!(read_data(&rb, ds - 8, 8), rec[..8], "tail of the ring");
        assert_eq!(read_data(&rb, 0, 16), rec[8..], "wrapped remainder at offset 0");
    }

    #[test]
    fn a_record_crossing_a_page_boundary_is_copied_into_both_frames() {
        let rb = PerfBuffer::hosted(2, 0, true);
        rb.state.lock().head = PAGE_BYTES - 8;
        let rec: alloc::vec::Vec<u8> = (0u8..16).collect();
        assert!(is_ok(rb.output(&rec, |_| None::<crate::perf::sample::RecordBuf>)));
        assert_eq!(read_data(&rb, PAGE_BYTES - 8, 16), rec);
    }

    /// A full ring drops records, and the next successful one carries a
    /// `PERF_RECORD_LOST` reporting exactly how many were dropped.
    #[test]
    fn overrun_drops_records_and_the_next_success_reports_the_loss() {
        let rb = PerfBuffer::hosted(1, 0, false);
        let ds = rb.data_size();
        rb.state.lock().head = ds - 4;
        assert!(!is_ok(rb.output(&[0u8; 8], |_| None::<crate::perf::sample::RecordBuf>)));
        assert!(!is_ok(rb.output(&[0u8; 8], |_| None::<crate::perf::sample::RecordBuf>)));
        assert_eq!(rb.state.lock().lost, 2);
        // The consumer catches up; the next record is prefixed by the loss report.
        set_tail(&rb, ds - 4);
        let prologue = |lost: u64| {
            let mut r = crate::perf::sample::RecordBuf::<1024>::new(
                crate::perf::uapi::record::LOST, 0);
            r.u64(0x77);
            r.u64(lost);
            r.finish()
        };
        assert!(is_ok(rb.output(&[0xEEu8; 8], prologue)));
        assert_eq!(rb.state.lock().lost, 0, "the count is consumed by the record");
        let at = ds - 4;
        let got = read_data(&rb, at, 24);
        assert_eq!(u32::from_le_bytes(got[0..4].try_into().unwrap()),
                   crate::perf::uapi::record::LOST);
        assert_eq!(u16::from_le_bytes(got[6..8].try_into().unwrap()), 24 - 8 + 8);
        assert_eq!(u64::from_le_bytes(got[8..16].try_into().unwrap()), 0x77);
        assert_eq!(u64::from_le_bytes(got[16..24].try_into().unwrap()), 2);
        assert_eq!(read_data(&rb, at + 24, 8), [0xEEu8; 8]);
    }

    #[test]
    fn a_paused_ring_writes_nothing_and_pausing_a_pageless_ring_is_ignored() {
        let rb = PerfBuffer::hosted(1, 0, true);
        rb.set_paused(true);
        assert!(!is_ok(rb.output(&[0u8; 8], |_| None::<crate::perf::sample::RecordBuf>)));
        assert_eq!(head(&rb), 0);
        rb.set_paused(false);
        assert!(is_ok(rb.output(&[0u8; 8], |_| None::<crate::perf::sample::RecordBuf>)));

        let empty = PerfBuffer::hosted(0, 0, true);
        assert_eq!(empty.size(), PAGE_BYTES);
        assert_eq!(empty.data.len(), 0, "no data page to map");
        empty.set_paused(false);
        assert!(!is_ok(empty.output(&[0u8; 8], |_| None::<crate::perf::sample::RecordBuf>)));
    }

    /// `perf_mmap_to_page`'s bounds: page 0 is the control page, pages
    /// `1..=nr` are data pages, and anything past that has no page to map.
    #[test]
    fn frame_lookup_is_bounded_by_the_control_page_plus_data_pages() {
        let rb = PerfBuffer::hosted(4, 0, true);
        assert_eq!(rb.data.len(), 4);
        assert_eq!(rb.size(), 5 * PAGE_BYTES);
        for i in 0..=4 { assert!(rb.data.ptr(i as usize).is_some() || i == 4); }
        assert!(rb.user.ptr(0).is_some());
        assert!(rb.data.ptr(4).is_none(), "one page past the last data page");
    }

    #[test]
    fn a_watermark_crossing_latches_the_poll_readiness_once() {
        let rb = PerfBuffer::hosted(1, 64, true);
        // `perf_output_wakeup` did not run, so the caller must not wake anyone.
        assert_eq!(rb.output(&[0u8; 32], |_| None::<crate::perf::sample::RecordBuf>), Some(Wrote { wakeup: false }));
        assert_eq!(rb.take_poll(), 0, "below the watermark");
        // The crossing both latches `rb->poll` AND tells the caller to run the
        // wake the reference's `irq_work` delivers.
        assert_eq!(rb.output(&[0u8; 40], |_| None::<crate::perf::sample::RecordBuf>), Some(Wrote { wakeup: true }));
        assert_eq!(rb.take_poll(), POLL_READY);
        assert_eq!(rb.take_poll(), 0, "the read clears it");
    }
}
