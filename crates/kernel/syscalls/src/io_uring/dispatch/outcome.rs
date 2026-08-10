// What one operation reports back to the submission engine: the result the
// CQE carries, plus the CQE flag half, which is how a buffer-selecting
// operation tells the caller which buffer it consumed.

/// # C: n/a
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OpOutcome {
    pub res: i64,
    pub cqe_flags: u32,
    /// The completion carries a 32-byte payload — the two words below.
    pub cqe32: bool,
    /// `big_cqe[2]`, meaningful only when `cqe32` is set.
    pub big: [u64; 2],
}

impl OpOutcome {
    /// A plain result with no CQE flags. # C: O(1)
    pub fn res(res: i64) -> Self { Self { res, cqe_flags: 0, cqe32: false, big: [0; 2] } }

    /// A result whose completion carries a 32-byte payload. # C: O(1)
    pub fn wide(res: i64, big: [u64; 2]) -> Self {
        Self { res, cqe_flags: 0, cqe32: true, big }
    }

    /// A result that consumed provided buffer `bid`. # C: O(1)
    pub fn with_buffer(res: i64, bid: u16) -> Self {
        use crate::io_uring_abi::ops::{IORING_CQE_BUFFER_SHIFT, IORING_CQE_F_BUFFER};
        Self {
            res, cqe_flags: IORING_CQE_F_BUFFER | ((bid as u32) << IORING_CQE_BUFFER_SHIFT),
            cqe32: false, big: [0; 2],
        }
    }
}
