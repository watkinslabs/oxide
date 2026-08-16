// The decoded-reply handle.

extern crate alloc;
use alloc::vec::Vec;

use crate::xdr::Dec;

/// A successful reply: the whole record, plus where the results begin.
///
/// The header bytes are KEPT rather than trimmed so a caller can re-examine
/// them, and the offset is carried rather than recomputed — the header's length
/// varies with the reply verifier's size, and recomputing it at each use is how
/// a caller ends up reading the results from the wrong offset.
#[derive(Debug, PartialEq, Eq)]
pub struct Reply {
    /// The xid this reply answered.
    pub xid: u32,
    /// The whole received record.
    pub record: Vec<u8>,
    /// Offset within `record` at which the procedure's results begin.
    pub results_at: usize,
}

impl Reply {
    /// The procedure's result bytes. # C: O(1)
    pub fn results(&self) -> &[u8] { &self.record[self.results_at..] }

    /// A decoder positioned at the results. # C: O(1)
    pub fn dec(&self) -> Dec<'_> { Dec::new(self.results()) }
}
