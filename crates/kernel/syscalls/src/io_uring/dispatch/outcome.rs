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
    /// A SECOND completion this operation owes, posted straight after the
    /// first: a zero-copy send's notification, saying the payload memory the
    /// submission named is the caller's again. `(user_data, res)`.
    pub notif: Option<(u64, i32)>,
}

impl OpOutcome {
    /// A plain result with no CQE flags. # C: O(1)
    pub fn res(res: i64) -> Self { Self { res, cqe_flags: 0, cqe32: false, big: [0; 2], notif: None } }

    /// A result whose completion carries a 32-byte payload. # C: O(1)
    pub fn wide(res: i64, big: [u64; 2]) -> Self {
        Self { res, cqe_flags: 0, cqe32: true, big, notif: None }
    }

    /// A result that consumed provided buffers starting at `bid`. For a run of
    /// them the caller walks forward from that id by its own buffer sizes;
    /// `buf_more` says the last one is only part-used and the same id will
    /// serve the next operation. # C: O(1)
    pub fn with_buffer(res: i64, bid: u16, buf_more: bool) -> Self {
        Self {
            res, cqe_flags: crate::io_uring_abi::bundle::cqe_flags(bid, buf_more),
            cqe32: false, big: [0; 2], notif: None,
        }
    }
}
