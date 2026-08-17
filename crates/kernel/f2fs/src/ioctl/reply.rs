//! What a command hands back.
//!
//! Three channels, because commands use them in every combination: the fixed
//! payload written back over the caller's argument, a further buffer the
//! argument named by pointer, and the command's own result value. Folding
//! them into one would lose the difference between a command that reports a
//! count in its result and one that writes the same count into its argument —
//! and callers read exactly one of the two.

use alloc::vec::Vec;

/// A command's answer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Reply {
    /// Bytes written back over the caller's fixed argument. Present only for
    /// the commands whose [`super::spec::Payload`] says the payload travels
    /// outward.
    pub payload: Option<Vec<u8>>,
    /// Bytes written to the buffer the argument named by pointer.
    pub indirect: Option<Vec<u8>>,
    /// The value the call itself returns. Zero for the commands that report
    /// through their argument, which is most of them.
    pub value: i64,
}

impl Reply {
    /// Nothing to hand back but success. # C: O(1)
    pub fn done() -> Self { Self::default() }

    /// A payload written back over the caller's argument. # C: O(1)
    pub fn payload(bytes: Vec<u8>) -> Self {
        Self { payload: Some(bytes), indirect: None, value: 0 }
    }

    /// A thirty-two-bit answer in the caller's argument. # C: O(1)
    pub fn u32(v: u32) -> Self { Self::payload(v.to_le_bytes().to_vec()) }

    /// A sixty-four-bit answer in the caller's argument. # C: O(1)
    pub fn u64(v: u64) -> Self { Self::payload(v.to_le_bytes().to_vec()) }

    /// A count reported through the call's own result rather than through the
    /// argument. # C: O(1)
    pub fn value(v: i64) -> Self { Self { payload: None, indirect: None, value: v } }

    /// Attach the buffer the argument named by pointer. # C: O(1)
    pub fn with_indirect(mut self, bytes: Vec<u8>) -> Self {
        self.indirect = Some(bytes);
        self
    }
}
