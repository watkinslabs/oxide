//! The volume-wide status word: every condition a mount can be in.
//!
//! One word, seventeen conditions. A monitoring tool decodes it by bit
//! position, so a condition nothing raises is indistinguishable from a
//! condition that is not happening — which is why the set is complete here and
//! why each bit has exactly one place that raises it and one that lowers it.
//!
//! Two of the seventeen are not stored: whether anything is waiting for a
//! checkpoint, and whether a replay is running, are already the volume's own
//! state and reading them twice would let the two disagree. They are folded in
//! at the one point the word is composed.
//!
//! Module manifest:
//! - `bits`:  the bit positions, which are the ABI, and which of them derive.
//! - `state`: the stored bits, what seeds them at mount, and the composed word.
//! - `freeze`: what a freeze and a thaw of one volume decide.

pub mod bits;
pub mod freeze;
pub mod state;

pub use state::{Derived, SbFlags};
