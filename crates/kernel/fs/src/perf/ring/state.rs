// Producer-side head/tail algebra of the perf ring — `CIRC_SPACE`,
// `__perf_output_begin`'s reservation, the wrap split `__output_copy` performs
// and the `rb->lost` accounting `PERF_RECORD_LOST` reports.
//
// Pure state over explicit inputs. The kernel-side tail comes from the mmapped
// control page (userspace writes it), so it is passed in rather than read here.

/// `CIRC_SPACE(head, tail, size)` — bytes a producer may still write. One byte
/// is always left unused so a full ring is distinguishable from an empty one.
/// `size` must be a power of two. # C: O(1)
pub fn circ_space(head: u64, tail: u64, size: u64) -> u64 {
    if size == 0 { return 0; }
    tail.wrapping_sub(head.wrapping_add(1)) & (size - 1)
}

/// `ring_buffer_has_space` in the forward (non-`write_backward`) direction.
/// # C: O(1)
pub fn has_space(head: u64, tail: u64, data_size: u64, size: u64) -> bool {
    circ_space(head, tail, data_size) >= size
}

/// The two contiguous byte ranges a record occupies once the ring wraps:
/// `((start, len), (0, len))`, the second empty when the record does not wrap.
/// `__output_copy` walks pages; the split is the same arithmetic and is what
/// a wrong wrap boundary corrupts. # C: O(1)
pub fn copy_plan(offset: u64, len: u64, data_size: u64) -> ((u64, u64), (u64, u64)) {
    if data_size == 0 { return ((0, 0), (0, 0)); }
    let start = offset & (data_size - 1);
    let first = core::cmp::min(len, data_size - start);
    ((start, first), (0, len - first))
}

/// Producer state of one ring — Linux `perf_buffer`'s `head`, `wakeup`,
/// `watermark`, `lost` and `paused`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingState {
    pub data_size: u64,
    /// Monotonically increasing byte count ever written (never masked).
    pub head:      u64,
    /// Head value at which the next wakeup is due.
    pub wakeup:    u64,
    pub watermark: u64,
    /// Records dropped for want of space since the last `PERF_RECORD_LOST`.
    pub lost:      u64,
    /// `rb->overwrite` — set for a read-only (`!VM_WRITE`) mapping, where the
    /// producer never consults the consumer's tail.
    pub overwrite: bool,
    /// `rb->paused` — `PERF_EVENT_IOC_PAUSE_OUTPUT`, and unconditionally true
    /// for a ring with no data pages.
    pub paused:    bool,
}

/// What a successful reservation yields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reservation {
    /// Unmasked head value the record starts at.
    pub offset: u64,
    /// True when this reservation crossed the watermark, so the consumer must
    /// be woken (`perf_output_wakeup`).
    pub wakeup: bool,
}

impl RingState {
    /// # C: O(1)
    pub fn new(data_size: u64, watermark: u64, overwrite: bool) -> RingState {
        RingState { data_size, head: 0, wakeup: 0, watermark, lost: 0, overwrite,
                    paused: data_size == 0 }
    }

    /// `__perf_output_begin` — reserve `size` bytes against the consumer's
    /// `data_tail`. `Err(())` is its `-ENOSPC`, and (matching the reference)
    /// bumps `lost` so the next successful record can carry a
    /// `PERF_RECORD_LOST`. # C: O(1)
    pub fn reserve(&mut self, tail: u64, size: u64) -> Result<Reservation, ()> {
        if self.paused {
            // A paused ring WITH pages drops and counts; a ring with no pages
            // at all has nothing to lose.
            if self.data_size != 0 { self.lost = self.lost.saturating_add(1); }
            return Err(());
        }
        if size > self.data_size { self.lost = self.lost.saturating_add(1); return Err(()); }
        if !self.overwrite && !has_space(self.head, tail, self.data_size, size) {
            self.lost = self.lost.saturating_add(1);
            return Err(());
        }
        let offset = self.head;
        self.head = self.head.wrapping_add(size);
        let mut wakeup = false;
        if self.watermark != 0 && self.head.wrapping_sub(self.wakeup) > self.watermark {
            self.wakeup = self.wakeup.wrapping_add(self.watermark);
            wakeup = true;
        }
        Ok(Reservation { offset, wakeup })
    }

    /// `local_xchg(&rb->lost, 0)` — read and clear the drop count for the
    /// `PERF_RECORD_LOST` about to be emitted. # C: O(1)
    pub fn take_lost(&mut self) -> u64 { core::mem::replace(&mut self.lost, 0) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIZE: u64 = 4096;

    #[test]
    fn circ_space_leaves_one_byte_and_reports_a_full_ring_as_zero() {
        assert_eq!(circ_space(0, 0, SIZE), SIZE - 1);
        assert_eq!(circ_space(10, 10, SIZE), SIZE - 1);
        // Consumer has read nothing and the producer filled the ring.
        assert_eq!(circ_space(SIZE - 1, 0, SIZE), 0);
        assert_eq!(circ_space(100, 200, SIZE), 99);
        // Wrapped: head past the mask boundary, tail behind it.
        assert_eq!(circ_space(SIZE + 8, SIZE, SIZE), SIZE - 9);
    }

    #[test]
    fn copy_plan_splits_exactly_at_the_wrap_boundary() {
        assert_eq!(copy_plan(0, 64, SIZE), ((0, 64), (0, 0)));
        assert_eq!(copy_plan(SIZE - 64, 64, SIZE), ((SIZE - 64, 64), (0, 0)));
        // One byte past the last aligned record: 63 before the wrap, 1 after.
        assert_eq!(copy_plan(SIZE - 63, 64, SIZE), ((SIZE - 63, 63), (0, 1)));
        // The unmasked head keeps growing; the plan must mask it.
        assert_eq!(copy_plan(SIZE * 3 + 16, 32, SIZE), ((16, 32), (0, 0)));
        assert_eq!(copy_plan(SIZE * 3 - 8, 32, SIZE), ((SIZE - 8, 8), (0, 24)));
    }

    #[test]
    fn reserve_advances_head_and_refuses_when_the_consumer_lags() {
        let mut s = RingState::new(SIZE, SIZE / 2, false);
        let r = s.reserve(0, 64).unwrap();
        assert_eq!(r.offset, 0);
        assert_eq!(s.head, 64);
        let r = s.reserve(0, 64).unwrap();
        assert_eq!(r.offset, 64);
        assert_eq!(s.head, 128);
        // Fill to within one byte of the tail, then fail.
        s.head = SIZE - 1;
        assert_eq!(s.reserve(0, 1), Err(()));
        assert_eq!(s.lost, 1);
        assert_eq!(s.head, SIZE - 1, "a failed reservation must not move head");
        // The consumer catching up frees the space again.
        assert!(s.reserve(2048, 1).is_ok());
        assert_eq!(s.lost, 1);
    }

    #[test]
    fn reserve_wraps_the_offset_without_resetting_head() {
        let mut s = RingState::new(SIZE, 0, true);
        s.head = SIZE - 16;
        let r = s.reserve(0, 32).unwrap();
        assert_eq!(r.offset, SIZE - 16);
        assert_eq!(s.head, SIZE + 16, "head is a monotonic byte count, never masked");
        assert_eq!(copy_plan(r.offset, 32, SIZE), ((SIZE - 16, 16), (0, 16)));
    }

    #[test]
    fn overwrite_ring_never_consults_the_tail() {
        let mut s = RingState::new(SIZE, 0, true);
        s.head = SIZE * 10;
        assert!(s.reserve(0, 1024).is_ok());
        assert_eq!(s.lost, 0);
    }

    #[test]
    fn paused_ring_drops_and_counts() {
        let mut s = RingState::new(SIZE, 0, false);
        s.paused = true;
        assert_eq!(s.reserve(0, 8), Err(()));
        assert_eq!(s.lost, 1);
        // A ring with no data pages is permanently paused but loses nothing:
        // there was never a buffer to drop into.
        let mut empty = RingState::new(0, 0, false);
        assert!(empty.paused);
        assert_eq!(empty.reserve(0, 8), Err(()));
        assert_eq!(empty.lost, 0);
    }

    #[test]
    fn a_record_larger_than_the_ring_is_lost_not_wrapped_onto_itself() {
        let mut s = RingState::new(SIZE, 0, true);
        assert_eq!(s.reserve(0, SIZE + 1), Err(()));
        assert_eq!(s.lost, 1);
    }

    #[test]
    fn watermark_crossing_requests_exactly_one_wakeup_per_watermark() {
        let mut s = RingState::new(SIZE, 1024, false);
        assert!(!s.reserve(0, 512).unwrap().wakeup);
        assert!(!s.reserve(0, 512).unwrap().wakeup, "head == watermark is not yet past it");
        assert!(s.reserve(0, 8).unwrap().wakeup);
        assert_eq!(s.wakeup, 1024);
        assert!(!s.reserve(0, 8).unwrap().wakeup);
    }

    #[test]
    fn take_lost_clears_the_counter() {
        let mut s = RingState::new(SIZE, 0, false);
        s.head = SIZE - 1;
        let _ = s.reserve(0, 8);
        let _ = s.reserve(0, 8);
        assert_eq!(s.lost, 2);
        assert_eq!(s.take_lost(), 2);
        assert_eq!(s.lost, 0);
        assert_eq!(s.take_lost(), 0);
    }
}
