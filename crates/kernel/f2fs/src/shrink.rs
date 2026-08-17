//! Giving memory back when the machine is short of it.
//!
//! Three caches a mount keeps grow without an upper bound of their own,
//! because each is bounded by usefulness rather than by size: the read extent
//! cache, the block-age extent cache, and the free-node-id cache. Reclaim is
//! how they are held down, and until this module existed the passes that free
//! their entries had no caller outside their own tests — the caches grew for
//! the life of the mount and the only thing that ever shrank them was
//! unmounting.
//!
//! One shrinker for the FILESYSTEM, not one per mount, which is the shape the
//! reference uses and the shape reclaim needs: a machine under memory pressure
//! wants a budget spent where the entries are, and per-mount shrinkers make
//! every mount answer a full budget. So mounts join a list and the two
//! callbacks walk it.
//!
//! A mount is held WEAKLY. The list must not be what keeps a filesystem alive,
//! or an unmount would never complete, and a mount that has gone away between
//! two reclaim passes is dropped from the list by the pass that finds it.
//!
//! Module manifest:
//! - `budget`:   how one reclaim budget is divided between the caches, and
//!               what counts as reclaimable. No mount, no lock, no allocator.
//! - `registry`: the list of mounts, joining it, leaving it, and the two
//!               callbacks reclaim calls.

pub mod budget;
pub mod registry;

pub use budget::{reclaimable, split, Budget};
pub use registry::{count, install, join, leave, scan};
