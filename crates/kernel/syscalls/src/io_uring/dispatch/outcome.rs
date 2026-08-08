// What one operation reports back to the submission engine: the result the
// CQE carries, plus the CQE flag half, which is how a buffer-selecting
// operation tells the caller which buffer it consumed.

/// # C: n/a
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OpOutcome {
    pub res: i64,
    pub cqe_flags: u32,
}

impl OpOutcome {
    /// A plain result with no CQE flags. # C: O(1)
    pub fn res(res: i64) -> Self { Self { res, cqe_flags: 0 } }

    /// A result that consumed provided buffer `bid`. # C: O(1)
    pub fn with_buffer(res: i64, bid: u16) -> Self {
        use crate::io_uring_abi::ops::{IORING_CQE_BUFFER_SHIFT, IORING_CQE_F_BUFFER};
        Self { res, cqe_flags: IORING_CQE_F_BUFFER | ((bid as u32) << IORING_CQE_BUFFER_SHIFT) }
    }
}
