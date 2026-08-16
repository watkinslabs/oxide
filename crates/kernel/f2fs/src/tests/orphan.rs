//! The orphan list.
//!
//! Module manifest:
//! - `codec`: the block's layout and the pack arithmetic, driven pure.
//! - `live`:  a volume parking a real inode and reclaiming it at the close.
//! - `recover`: what a mount does with a pack a crash left carrying a list.

#[path = "orphan/codec.rs"]
mod codec;
#[path = "orphan/live.rs"]
mod live;
#[path = "orphan/recover.rs"]
mod recover;
