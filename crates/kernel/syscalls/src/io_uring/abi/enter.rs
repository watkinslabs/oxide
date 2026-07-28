// `io_uring_enter(2)` submit-loop decisions: CQ occupancy and SQ index
// validity. Kept out of the (kernel-gated) slot file so the wraparound
// arithmetic is unit-tested (CLAUDE.md phantom-test rule).
//
// Linux reference: `io_uring/io_uring.c` io_get_sqe() (`sq_dropped` on a bad
// index) and io_cqe_cache_refill()/io_cqring_event_overflow() (CQ occupancy).

/// `IORING_ENTER_*` (Linux `include/uapi/linux/io_uring.h`).
pub const IORING_ENTER_GETEVENTS:       u32 = 1 << 0;
pub const IORING_ENTER_SQ_WAKEUP:       u32 = 1 << 1;
pub const IORING_ENTER_SQ_WAIT:         u32 = 1 << 2;
pub const IORING_ENTER_EXT_ARG:         u32 = 1 << 3;
pub const IORING_ENTER_REGISTERED_RING: u32 = 1 << 4;
pub const IORING_ENTER_ABS_TIMER:       u32 = 1 << 5;
pub const IORING_ENTER_EXT_ARG_REG:     u32 = 1 << 6;
pub const IORING_ENTER_NO_IOWAIT:       u32 = 1 << 7;

/// CQEs the ring can still accept. Head and tail are free-running counters
/// masked only at access time, so the difference is wraparound-correct.
/// # C: O(1)
pub fn cq_space(cq_tail: u32, cq_head: u32, cq_entries: u32) -> u32 {
    cq_entries.saturating_sub(cq_tail.wrapping_sub(cq_head))
}

/// Whether a completion can be posted without overwriting one the caller has
/// not reaped. oxide has no CQ overflow list, so a full ring stops submission
/// (and does NOT report `IORING_FEAT_NODROP`). # C: O(1)
pub fn cq_has_room(cq_tail: u32, cq_head: u32, cq_entries: u32) -> bool {
    cq_space(cq_tail, cq_head, cq_entries) > 0
}

/// Whether an SQ index array entry names a real SQE. Linux `io_get_sqe()`
/// counts a bad index in `sq_dropped` and skips the entry. # C: O(1)
pub fn sq_index_valid(idx: u32, sq_entries: u32) -> bool { idx < sq_entries }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_cq_has_no_room() {
        assert!(cq_has_room(0, 0, 8));
        assert!(cq_has_room(7, 0, 8));
        // tail - head == entries: every slot holds an unreaped completion.
        assert!(!cq_has_room(8, 0, 8));
        // The old loop wrote at `cq_tail & mask` unconditionally, silently
        // overwriting the completion at slot 0.
        assert_eq!(cq_space(8, 0, 8), 0);
        assert!(cq_has_room(8, 1, 8));
    }

    #[test]
    fn cq_occupancy_survives_counter_wraparound() {
        assert!(cq_has_room(0, u32::MAX - 2, 8));
        assert_eq!(cq_space(0, u32::MAX, 8), 7);
        assert!(!cq_has_room(7, u32::MAX, 8));
    }

    #[test]
    fn out_of_range_sq_indices_are_rejected() {
        assert!(sq_index_valid(0, 8));
        assert!(sq_index_valid(7, 8));
        assert!(!sq_index_valid(8, 8));
        assert!(!sq_index_valid(u32::MAX, 8));
    }
}
