//! The orphan list.
//!
//! Module manifest:
//! - `codec`: the block's layout and the pack arithmetic, driven pure.
//! - `live`:  a volume parking a real inode and reclaiming it at its eviction.
//! - `recover`: what a mount does with a pack a crash left carrying a list.
//! - `unlinked_open`: the same lifecycle driven through `unlink_child`/`iput`,
//!   which is what proves anything CALLS the parking and the eviction.

#[path = "orphan/codec.rs"]
mod codec;
#[path = "orphan/live.rs"]
mod live;
#[path = "orphan/recover.rs"]
mod recover;
#[path = "orphan/unlinked_open.rs"]
mod unlinked_open;
