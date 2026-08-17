//! What one rule evaluation produced.

extern crate alloc;
use alloc::string::String;

use crate::nft_expr::uapi::{NFT_CONTINUE, NFT_GOTO, NFT_JUMP};

/// A verdict code plus, for the two transferring verdicts, the chain it
/// transfers to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleVerdict {
    pub code: i32,
    pub chain: Option<String>,
}

impl Default for RuleVerdict {
    fn default() -> Self { Self::cont() }
}

impl RuleVerdict {
    /// Fall through to the next rule. # C: O(1)
    pub const fn cont() -> Self { Self { code: NFT_CONTINUE, chain: None } }

    /// # C: O(1)
    pub const fn code(code: i32) -> Self { Self { code, chain: None } }

    /// Whether the code leaves netfilter rather than steering the walk.
    /// # C: O(1)
    pub const fn is_absolute(&self) -> bool { self.code >= 0 }

    /// Whether the code transfers control to another chain. # C: O(1)
    pub const fn transfers(&self) -> bool { matches!(self.code, NFT_JUMP | NFT_GOTO) }
}
