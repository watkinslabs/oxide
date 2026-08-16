//! The overlay's own inodes, and the operations the VFS calls on them.
//!
//! An overlay inode stands for a merged object: it carries the object list the
//! lookup produced, and every operation reaches through that list to the real
//! object in whichever layer holds it. Two things it also carries, which the
//! list alone cannot supply: the overlay inode of its PARENT and its own name,
//! because copying an object up requires copying its ancestors up first, and
//! nothing else here knows where an object sits in the tree.
//!
//! Module manifest:
//! - `node`: the per-object state, and building an overlay inode from it.
//! - `ops`:  the namespace and metadata operations.
//! - `fops`: reads, writes and directory iteration.

pub mod node;
pub mod ops;
pub mod fops;

pub use node::{make_inode, OvlInode};
pub use ops::OvlOps;
